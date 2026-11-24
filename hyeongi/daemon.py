#!/usr/bin/env python3
"""hyeongid — the HYEONGI daemon: every detector in one long-running process.

Linux: started by systemd (hyeongid.service), logs to the journal.
Windows: started at boot by the "hyeongid" SYSTEM scheduled task, logs to
%ProgramData%/HYEONGI/logs/hyeongid.log.

  hyeongid [--config PATH]          (= python3 -m hyeongi.daemon)

Workers (each restarts itself with back-off if it fails):
  ids     follow the IDS alert file (Suricata eve.json / Snort alert_json)
  flows   one live nfstream capture: ML classification (if a model exists)
          and flow logging for training data (capture.enabled)
  expiry  remove expired blocks every daemon.expiry_interval seconds
          (needed for the Windows firewall, which has no timeouts)
  triage  read-only LLM report every daemon.triage_interval seconds

Safety is the same as everywhere else: with `enforce: false` nothing is
blocked; detectors only log what they would block.
"""
from hyeongi.alerts import Ignore, ENCRYPTED_PORTS, PAYLOAD_PREFIXES, REVIEW_RULES
import argparse
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time

from hyeongi import config


def setup_logging(c):
    """Windows: rotating log file (+ console). Linux: stdout only — systemd
    puts it in the journal (journalctl -u hyeongid)."""
    log = logging.getLogger("hyeongi")
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler(sys.stdout)
    if config.WINDOWS:
        log_dir = os.path.join(config.PROGRAMDATA, "logs")
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "hyeongid.log")
        fmt = logging.Formatter("%(asctime)s %(threadName)-6s %(message)s")
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=5_000_000, backupCount=5,
                                                  encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
        sh.setFormatter(fmt)
    else:
        path = "journal (journalctl -u hyeongid)"
        sh.setFormatter(logging.Formatter("%(threadName)-6s %(message)s"))
    log.addHandler(sh)
    return log, path


def supervised(name, fn, stop, log):
    """Run fn() in a thread; restart it with back-off until stop is set."""
    # keep the daemon alive: a failing worker never takes the others down
    def loop():
        delay = 5
        while not stop.is_set():
            try:
                fn()
                if stop.is_set():
                    return
                log.info(f"{name} returned; restarting in {delay}s")
            except Exception as e:
                log.error(f"{name} failed: {e!r}; restarting in {delay}s")
            if stop.wait(delay):
                return
            delay = min(delay * 2, 300)
    t = threading.Thread(target=loop, name=name, daemon=True)
    t.start()
    return t


def main():
    ap = argparse.ArgumentParser(prog="hyeongid", description="HYEONGI daemon (all detectors in one process)")
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    c = config.load(a.config)
    log, log_path = setup_logging(c)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except (ValueError, OSError):
            pass

    from hyeongi.practice import state as practice_state
    if practice_state():                      # started anyway during practice mode: wait
        ps = practice_state()
        log.warning(f"practice mode since {ps['start']}: waiting, nothing runs until "
                    "`hyeongi practice end`")
        while practice_state() and not stop.wait(10):
            pass
        if stop.is_set():
            return 0
        log.info("practice mode ended: starting")

    from hyeongi.blocklist import Blocklist
    backend, timeout = c["backend"], c["block_timeout"]
    enforcer = Blocklist(backend=backend, default_timeout=timeout)
    bl = None
    if c["enforce"]:
        enforcer.setup()
        bl = enforcer
    log.info(f"hyeongid start: backend={backend} enforce={c['enforce']} "
             f"({'ENFORCING' if bl else 'dry-run'}); log {log_path}")

    workers = []
    from hyeongi.status import Board
    board = Board(c)
    board.restore()
    from hyeongi.netinfo import NetworkPolicy
    _net = c.get("networks") or {}
    policy = NetworkPolicy(_net.get("trusted_gateways") or [])
    if policy.trusted:
        cur = policy.current()
        log.info(f"network gating on: {len(policy.trusted)} trusted gateway(s); "
                 f"here gw={cur['gateway']} mac={cur['mac']} -> "
                 f"{'enforce' if cur['trusted'] else 'observe-only'}")

    # ---- ids ------------------------------------------------------------------
    if c["ids"].get("enabled", True):
        from hyeongi import snort_bridge
        from hyeongi.blocklist import parse_timeout
        from hyeongi.netinfo import LocalInfra
        refresh = parse_timeout(c["block_timeout"]) or 3600
        workers.append(supervised("ids", lambda: snort_bridge.run(
            c["ids"]["alert_file"], bl, c["skip"], c["block_private"],
            log=log.info, stop=stop, ignore_gids=c["ids"].get("ignore_gids") or [],
            ignore_rules=c["ids"].get("ignore_rules") or [], refresh=refresh,
            ignore=Ignore(c["ids"].get("ignore_gids") or [], c["ids"].get("ignore_rules") or [],
                          c["ids"].get("encrypted_ports", ENCRYPTED_PORTS),
                          c["ids"].get("payload_rule_prefixes", PAYLOAD_PREFIXES),
                          c["ids"].get("payload_block", False),
                          c["ids"].get("review_rules", REVIEW_RULES)),
            local=LocalInfra(onlink_local=not c["block_private"]) if c.get("protect_local", True) else None,
            on_event=board.alert, policy=policy), stop, log))

    # ---- flows: ML + flow logging, one capture ---------------------------------
    ml, cap = c["ml"], dict(c["capture"])
    if str(cap.get("enabled")).lower() == "auto":
        import importlib.util
        cap["enabled"] = importlib.util.find_spec("nfstream") is not None
        if not cap["enabled"]:
            log.info("flow logging off: nfstream is not installed (pip install nfstream)")
    model_ok = ml.get("enabled", True) and os.path.exists(ml["model"])
    if ml.get("enabled", True) and not model_ok:
        log.info(f"ml: no model at {ml['model']} yet — classification off")
    if model_ok or cap.get("enabled"):
        def flows():
            from hyeongi import ml_detector
            clf = None
            if model_ok:
                import joblib
                clf = joblib.load(ml["model"])["clf"]
            iface = ml["iface"]
            if os.name == "nt":
                from hyeongi.winnet import capture_device
                iface = capture_device(iface)
            logger = None
            if cap.get("enabled"):
                from hyeongi.flowlog import FlowLogger
                logger = FlowLogger(cap["dir"], int(cap.get("rows_per_file", 50000)),
                                    int(cap.get("keep", 100)))
                _closers.append(logger.close)
                log.info(f"flow logging -> {cap['dir']}")
            on_flow = None
            if logger:
                from hyeongi.collect import paused
                from hyeongi.netinfo import Direction, NetTagger, load_salt, salt_path
                tagger = NetTagger((c.get("networks") or {}).get("names") or {},
                                   load_salt(salt_path(cap["dir"]), create=True))
                direction = Direction()
                last = [None]
                def on_flow(flow):              # hyeongi pause: keep detecting, stop logging
                    if not paused():
                        net = tagger.current()
                        if net != last[0]:
                            log.info(f"flow logging: network tag {net}")
                            last[0] = net
                        logger.write(flow, net, direction(flow.src_ip, flow.dst_ip))
                        board.flow()
            from hyeongi.blocklist import parse_timeout
            from hyeongi.netinfo import LocalInfra
            try:
                ml_detector.run(iface, clf, bl, ml["threshold"], c["block_private"],
                                ml["idle"], ml["active"], log=log.info,
                                on_flow=on_flow, stop=stop, skip=c["skip"],
                                local=(LocalInfra(onlink_local=not c["block_private"])
                                       if c.get("protect_local", True) else None),
                                refresh=parse_timeout(c["block_timeout"]) or 3600,
                                on_event=board.alert, policy=policy,
                                alerts=ml_detector.AlertWriter(ml["alert_file"]) if clf is not None else None)
            finally:
                if logger:
                    logger.close()
        workers.append(supervised("flows", flows, stop, log))

    # ---- expiry ---------------------------------------------------------------
    def expiry():
        from hyeongi.alerts import prune_rotated
        while not stop.wait(c["daemon"]["expiry_interval"]):
            n = enforcer.reconcile()
            if n:
                log.info(f"expired {n} block(s)")
            # rotated alert files pile up 100 MB at a time during a flood
            for path, keep in ((c["ids"].get("alert_file"), c["ids"].get("keep_rotated", 3)),
                               (c["ml"].get("alert_file"), 1)):
                if path:
                    for gone in prune_rotated(path, keep):
                        log.info(f"removed old alert file {gone}")
    workers.append(supervised("expiry", expiry, stop, log))

    # ---- triage (separate process: a hung or crashing LLM call can't hurt us) --
    if c["triage"].get("enabled", True):
        def due():
            # wall-clock schedule from the report's age: survives restarts and
            # suspend (an Event.wait timer stops while a laptop sleeps)
            try:
                age = time.time() - os.path.getmtime(c["triage"]["out"])
            except OSError:
                return True
            return age >= c["daemon"]["triage_interval"]

        def triage():
            if stop.wait(120):                    # let the detectors settle after start
                return
            while True:
                if not due():
                    if stop.wait(60):
                        return
                    continue
                cmd = [sys.executable, "-m", "hyeongi.service", "triage"]
                if a.config:
                    cmd += ["--config", a.config]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                tail = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
                log.info(f"triage exit {r.returncode}: {tail[0]}")
                if not due():
                    continue
                # the run did not refresh the report (e.g. Ollama down and no file
                # written): try again in 10 minutes instead of every minute
                if stop.wait(600):
                    return
        workers.append(supervised("triage", triage, stop, log))

    # ---- status (desktop app, hyeongi stats) --------------------------------
    from hyeongi import status
    def status_worker():
        try:
            readable = enforcer if (bl is not None or enforcer.exists()) else None
        except Exception:
            readable = None
        status.writer(board, readable, stop,
                      flow_dir=cap["dir"] if cap.get("enabled") else None)
    workers.append(supervised("status", status_worker, stop, log))

    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        stop.set()
    log.info("hyeongid stopping")
    time.sleep(1)
    _shutdown(log)


_closers = []   # flushed on shutdown (e.g. the flow CSV)


def _shutdown(log):
    """Exit now. nfstream runs its packet meters in child processes that do not
    react to SIGTERM; a normal interpreter exit waits for them forever and
    systemd ends up SIGKILLing the whole service after 90 s. So: flush what we
    write, kill our own children, and leave without waiting for them."""
    for close in _closers:
        try:
            close()
        except Exception:
            pass
    kids = []
    try:
        import psutil                      # nfstream depends on it
        kids = psutil.Process().children(recursive=True)
    except Exception:
        import multiprocessing
        kids = multiprocessing.active_children()
    for k in kids:
        try:
            k.kill()
        except Exception:
            pass
    if kids:
        log.info(f"stopped {len(kids)} capture worker process(es)")
    logging.shutdown()
    os._exit(0)


if __name__ == "__main__":
    main()

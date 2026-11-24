"""Practice mode: stop HYEONGI completely for attack practice on this host, then
bring it back and check that nothing from the practice reached the training data.

  hyeongi practice start [--target IP ...] [memo...]
  hyeongi practice end
  hyeongi practice status
  hyeongi practice scrub IP         remove flow rows with that address (if end found any)

start
  1. remembers whether hyeongi-capture (raw packet capture) was running, and
     which units start at boot
  2. pauses training-data collection (the window goes to pauses.log)
  3. stops hyeongid, hyeongi-ids, hyeongi-xdp (the XDP program is detached)
     and hyeongi-capture, and turns their start at boot off, so a reboot during
     the practice does not bring them back (systemctl stop alone does not survive
     one: on the test laptop two reboots during an exercise restarted detection
     and XDP for 2.5 hours); checks that they and the XDP pins are gone
  4. records the time and the newest flow log file
  While practice mode is on, hyeongid waits instead of starting if something
  starts it anyway, and `hyeongi start` refuses.
end
  1. turns start at boot back on for the units that had it, starts
     hyeongi-xdp, hyeongi-ids, hyeongid
  2. resumes collection; hyeongi-capture runs again if it ran before start or
     starts at boot (so stopping everything first, then `practice start`, does
     not leave it off)
  3. checks: services up, XDP attached again (backend xdp), the newest flow log
     from before start unchanged, no flow log written during the practice, and
     (with --target) no flow row with a target address
  4. writes the result to practice.log; the exit code is 1 if a check failed

Pausing alone (hyeongi pause) keeps detection running; practice mode is for
when nothing at all should run (an attack from this host, a lab exercise).
Already-blocked IPs: with the XDP backend the blocklist goes with the program;
nftables blocks stay until they expire.
"""
import glob, ipaddress, json, os, subprocess, sys, time

from hyeongi import config
from hyeongi.collect import DATA, main as collect

STATE = os.path.join(DATA, "practice.json")
LOG = os.path.join(DATA, "practice.log")
CORE = ("hyeongi-xdp", "hyeongi-ids", "hyeongid")
CAPTURE = "hyeongi-capture"


def _active(unit):
    if config.WINDOWS:
        return "unknown"
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def _systemctl(action, *units):
    if not config.WINDOWS:
        subprocess.run(["systemctl", action, *units], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _enabled(unit):
    if config.WINDOWS:
        return "unknown"
    r = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def _flow_files(c):
    return sorted(glob.glob(os.path.join(c["capture"]["dir"], "flows-*.csv")), key=os.path.getmtime)


def _rows_with(path, ip):
    """Rows of a flow log whose src_ip or dst_ip is `ip` (compared as addresses)."""
    import csv
    from hyeongi.policy import norm_ip
    ip, n = norm_ip(ip), 0
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        r = csv.reader(fh)
        head = next(r, [])
        if "src_ip" not in head or "dst_ip" not in head:
            return 0
        i, j = head.index("src_ip"), head.index("dst_ip")
        for row in r:
            if len(row) > max(i, j) and ip in (norm_ip(row[i]), norm_ip(row[j])):
                n += 1
    return n


def scrub(ip):
    """Remove flow rows whose src_ip or dst_ip is `ip` from every flow log except
    the newest one while hyeongid is running (it is still being written)."""
    import csv
    from hyeongi.policy import norm_ip
    ipaddress.ip_address(ip)
    c = config.load(config.DEFAULT_PATH)
    files = _flow_files(c)
    if files and _active("hyeongid") == "active":
        files = files[:-1]
    ip, total = norm_ip(ip), 0
    for f in files:
        if not _rows_with(f, ip):
            continue
        with open(f, newline="", encoding="utf-8", errors="replace") as fh:
            rows = list(csv.reader(fh))
        i, j = rows[0].index("src_ip"), rows[0].index("dst_ip")
        keep = [rows[0]] + [r for r in rows[1:]
                            if not (len(r) > max(i, j) and ip in (norm_ip(r[i]), norm_ip(r[j])))]
        st = os.stat(f)
        with open(f + ".tmp", "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(keep)
        os.chmod(f + ".tmp", st.st_mode & 0o777)
        os.replace(f + ".tmp", f)
        total += len(rows) - len(keep)
        print(f"  {os.path.basename(f)}: {len(rows) - len(keep)} rows removed")
    _log(f"scrub {ip}: {total} rows")
    print(f"[+] removed {total} flow rows with {ip}")
    return 0


def state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _log(line):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {line}\n")


def start(memo="", targets=()):
    if state():
        s = state()
        print(f"[=] already in practice mode since {s['start']} ({s.get('memo') or '-'})")
        return 0
    c = config.load(config.DEFAULT_PATH)
    for t in targets:
        ipaddress.ip_address(t)                       # refuse anything that is not an address
    cap = _active(CAPTURE)
    boot = {u: _enabled(u) for u in CORE + (CAPTURE,)}
    on_boot = [u for u, e in boot.items() if e == "enabled"]
    collect(["pause", "practice:", memo or "-"])
    if config.WINDOWS:
        from hyeongi.ctl import stop_all
        stop_all()
    else:
        if on_boot:
            _systemctl("disable", *on_boot)           # a reboot must not bring them back
        _systemctl("stop", *CORE, CAPTURE)
    time.sleep(2)
    from hyeongi import xdp
    states = {u: _active(u) for u in CORE + (CAPTURE,)}
    up = [u for u, st in states.items() if st == "active"]
    pins = os.path.exists(xdp.PIN_DIR) and bool(os.listdir(xdp.PIN_DIR))
    files = _flow_files(c)
    last = {"name": os.path.basename(files[-1]), "mtime": os.path.getmtime(files[-1]),
            "size": os.path.getsize(files[-1])} if files else None
    s = {"start": time.strftime("%Y-%m-%d %H:%M:%S"), "start_epoch": time.time(),
         "memo": memo, "targets": list(targets), "capture_was": cap, "last_flow": last,
         "enabled_before": on_boot}
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=1)
    _log(f"start {memo or '-'} targets={','.join(targets) or '-'} capture_was={cap}")
    print(f"[+] practice mode ON since {s['start']}: collection paused, HYEONGI stopped")
    for u, st in states.items():
        print(f"    {u:<18} {st}" + ("   (start at boot off until practice end)" if u in on_boot else ""))
    print(f"    XDP pins           {'still there' if pins else 'gone'}")
    if last:
        print(f"    newest flow log    {last['name']} ({time.strftime('%H:%M:%S', time.localtime(last['mtime']))})")
    still = [u for u in on_boot if _enabled(u) == "enabled"]
    if up or pins or still:
        print("[!] not fully stopped: " + ", ".join(up + (["XDP pins"] if pins else [])
                                                     + [f"{u} still starts at boot" for u in still]))
        return 1
    print("    end with: sudo hyeongi practice end")
    return 0


def end():
    s = state()
    if not s:
        print("[=] not in practice mode")
        return 0
    c = config.load(config.DEFAULT_PATH)
    t1 = time.time()
    os.unlink(STATE)                                  # lets a waiting hyeongid go on
    if config.WINDOWS:
        from hyeongi.ctl import start_all
        start_all()
    else:
        if s.get("enabled_before"):
            _systemctl("enable", *s["enabled_before"])
        _systemctl("restart", "hyeongi-xdp")        # oneshot: restart = attach again
        _systemctl("start", "hyeongi-ids", "hyeongid")
    collect(["resume"])                               # also starts hyeongi-capture
    if s.get("capture_was") != "active" and CAPTURE not in (s.get("enabled_before") or []):
        _systemctl("stop", CAPTURE)               # was off and does not start at boot: leave it off
    time.sleep(5)

    ok, lines = True, []
    def check(good, text):
        nonlocal ok
        ok = ok and good
        lines.append(f"  [{'OK' if good else '!!'}] {text}")

    states = {u: _active(u) for u in CORE}
    check(all(v == "active" for v in states.values()),
          "services: " + ", ".join(f"{u} {v}" for u, v in states.items()))
    if s.get("enabled_before"):
        back = {u: _enabled(u) for u in s["enabled_before"]}
        check(all(v == "enabled" for v in back.values()),
              "start at boot restored: " + ", ".join(f"{u} {v}" for u, v in back.items()))
    if c["backend"] == "xdp" and not config.WINDOWS:
        from hyeongi import xdp
        on = xdp.loaded() and xdp.attached(xdp.target(c["xdp"]["iface"])[0]) is not False
        check(on, "XDP program attached again" if on else "XDP program not attached")
    from hyeongi.collect import paused
    check(not paused(), "training-data collection resumed" if not paused() else "collection still paused")
    t0 = s["start_epoch"]
    files = _flow_files(c)
    last = s.get("last_flow")
    if last:
        p = os.path.join(c["capture"]["dir"], last["name"])
        same = os.path.exists(p) and os.path.getmtime(p) == last["mtime"] and os.path.getsize(p) == last["size"]
        check(same, f"flow log from before the practice unchanged ({last['name']})")
    during = [os.path.basename(f) for f in files if t0 < os.path.getmtime(f) < t1]
    check(not during, "no flow log written during the practice" if not during
          else "flow logs written during the practice: " + ", ".join(during))
    for t in s.get("targets", []):
        hits = []
        for f in files:
            if os.path.getmtime(f) < t0 - 60:
                continue
            n = _rows_with(f, t)
            if n:
                hits.append(f"{os.path.basename(f)} ({n})")
        check(not hits, f"no flow rows with target {t}" if not hits
              else f"flow rows with target {t}: " + ", ".join(hits))
    mins = (t1 - t0) / 60
    _log(f"end after {mins:.0f} min, checks {'ok' if ok else 'FAILED'}")
    print(f"[+] practice mode OFF ({s['start']} - {time.strftime('%H:%M:%S')}, {mins:.0f} min): "
          "HYEONGI running again")
    print("\n".join(lines))
    print("[+] training data is clean" if ok else
          "[!] a check failed; see above. Rows of a target: sudo hyeongi practice scrub <IP>")
    return 0 if ok else 1


def status():
    s = state()
    if not s:
        print("not in practice mode")
    else:
        print(f"practice mode since {s['start']} ({s.get('memo') or '-'})"
              + (f", targets {', '.join(s['targets'])}" if s.get("targets") else ""))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    cmd = argv[0] if argv else "status"
    rest = argv[1:]
    if cmd == "start":
        targets, memo = [], []
        while rest:
            a = rest.pop(0)
            if a == "--target" and rest:
                targets.append(rest.pop(0))
            else:
                memo.append(a)
        try:
            return start(" ".join(memo), targets)
        except ValueError as e:
            print(f"[x] not an IP address: {e}", file=sys.stderr)
            return 2
    if cmd == "end":
        return end()
    if cmd == "status":
        return status()
    if cmd == "scrub" and len(rest) == 1:
        try:
            return scrub(rest[0])
        except ValueError as e:
            print(f"[x] not an IP address: {e}", file=sys.stderr)
            return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""XDP enforcement backend: build, attach, inspect and detach.

  sudo python3 -m hyeongi.xdp load   [--iface IF] [--mode generic|native] [--config PATH]
  sudo python3 -m hyeongi.xdp unload [--iface IF] [--config PATH]
  sudo python3 -m hyeongi.xdp status

How it works
  * hyeongi/bpf/hyeongi_xdp.c is compiled with clang to an eBPF object.
  * `bpftool prog load ... pinmaps` loads it and pins its maps under
    /sys/fs/bpf/hyeongi, so they outlive this process.
  * `bpftool net attach` hooks it to the interface. The attachment stays in
    the kernel until `unload`, independent of any HYEONGI process - but it is
    lost when the interface itself is removed and created again, while the
    pinned program and maps stay. `attached` and `ensure_attached` check for
    that, so a block is never reported while nothing is dropped.
  * Detectors add/remove blocked IPs by updating the pinned map (see
    hyeongi.blocklist, backend "xdp"); the program drops matching sources before
    the kernel allocates an skb.

Wi-Fi drivers usually lack native XDP, so the default mode is "generic".
Requires: clang, bpftool, libbpf headers (RHEL: clang bpftool libbpf-devel).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "bpf", "hyeongi_xdp.c")
OBJ_DIR = "/usr/local/lib/hyeongi"
OBJ = os.path.join(OBJ_DIR, "hyeongi_xdp.o")
PIN_DIR = "/sys/fs/bpf/hyeongi"
PROG_PIN = os.path.join(PIN_DIR, "prog")
BLOCK_MAP = os.path.join(PIN_DIR, "hyeongi_block")        # IPv4 sources
BLOCK6_MAP = os.path.join(PIN_DIR, "hyeongi_block6")      # IPv6 sources (since 3.0.0rc33)
STATS_MAP = os.path.join(PIN_DIR, "hyeongi_stats")
ATTACH = {"generic": "xdpgeneric", "native": "xdpdrv"}


def _run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr.strip() or r.stdout.strip()}")
    return r


def need(tool, pkg):
    if not shutil.which(tool):
        sys.exit(f"[x] '{tool}' not found — install the '{pkg}' package "
                 "(packaging/install-xdp.sh prints the exact command for your distro)")


IFACE_FILE = "/run/hyeongi-xdp.iface"   # where the program is attached right now: "iface mode"


def loaded():
    return os.path.exists(BLOCK_MAP) and os.path.exists(PROG_PIN)


def has_ipv6():
    """True if the loaded program has the IPv6 map (programs before rc33 do not)."""
    return os.path.exists(BLOCK6_MAP)


def build():
    """Compile the program if the object is missing or older than the source."""
    if os.path.exists(OBJ) and os.path.getmtime(OBJ) >= os.path.getmtime(SRC):
        return
    need("clang", "clang")
    os.makedirs(OBJ_DIR, exist_ok=True)
    arch_inc = f"/usr/include/{os.uname().machine}-linux-gnu"  # Debian layout; harmless elsewhere
    cmd = ["clang", "-O2", "-g", "-target", "bpf", "-c", SRC, "-o", OBJ]
    if os.path.isdir(arch_inc):
        cmd[1:1] = ["-I", arch_inc]
    try:
        _run(cmd)
    except RuntimeError as e:
        if "bpf_helpers.h" in str(e):
            sys.exit("[x] libbpf headers missing — install libbpf-devel (RHEL/openSUSE), "
                     "libbpf-dev (Debian/Ubuntu) or libbpf (Arch)")
        raise
    print(f"[+] built {OBJ}")


def load(iface, mode="generic"):
    need("bpftool", "bpftool")
    if mode not in ATTACH:
        sys.exit(f"[x] mode must be one of {list(ATTACH)}")
    keep = []
    if loaded():
        if has_ipv6():
            was = target()[0]
            if was and was != iface:          # loaded for another interface: move it
                _detach(was)
            state = attached(iface)
            if state is False:                # pins are there, the attachment is not
                attach(iface, mode)
                print(f"[+] already loaded ({PIN_DIR}); attached to {iface} ({mode}), entries kept")
            elif state is None:
                print(f"[=] already loaded ({PIN_DIR}); entries kept "
                      f"(could not verify the attachment to {iface})")
            else:
                _record(iface, mode)
                print(f"[=] already loaded ({PIN_DIR}) and attached to {iface}; entries kept")
            return
        # an older program without the IPv6 map: replace it, keeping the IPv4 blocks
        from hyeongi.blocklist import _xdp_entries
        keep = _xdp_entries()
        print(f"[*] loaded program has no IPv6 map; reloading ({len(keep)} entries kept)")
        unload(iface)
    build()
    os.makedirs(PIN_DIR, exist_ok=True)
    _run(["bpftool", "prog", "load", OBJ, PROG_PIN, "type", "xdp", "pinmaps", PIN_DIR])
    try:
        attach(iface, mode)
    except RuntimeError:
        _cleanup_pins()
        raise
    if keep:
        from hyeongi.blocklist import _xdp_restore
        _xdp_restore(keep)
    print(f"[+] XDP attached to {iface} ({mode}); blocklist map: {BLOCK_MAP}")


def target(iface=None, mode=None):
    """(iface, mode) the program was attached with: what `load` recorded in
    IFACE_FILE (files written before rc43 hold the interface only), else the
    arguments. mode falls back to "generic"."""
    try:
        with open(IFACE_FILE) as f:
            parts = f.read().split()
    except OSError:
        parts = []
    if parts:
        iface = parts[0]
        if len(parts) > 1 and parts[1] in ATTACH:
            mode = parts[1]
    return iface, mode or "generic"


def _record(iface, mode):
    try:
        with open(IFACE_FILE, "w") as f:
            f.write(f"{iface} {mode}\n")
    except OSError:
        pass


def attach(iface, mode="generic"):
    """Attach the pinned program to `iface` and record where it is."""
    _run(["bpftool", "net", "attach", ATTACH[mode], "pinned", PROG_PIN, "dev", iface])
    _record(iface, mode)
    _checked.clear()


def _detach(iface):
    if iface and shutil.which("bpftool"):
        for mode in ("xdpgeneric", "xdpdrv", "xdp"):
            _run(["bpftool", "net", "detach", mode, "dev", iface], check=False)


def prog_id():
    """Kernel id of the pinned program, or None if it cannot be read."""
    r = _run(["bpftool", "-j", "prog", "show", "pinned", PROG_PIN], check=False)
    try:
        return int(json.loads(r.stdout)["id"])
    except (ValueError, KeyError, TypeError):
        return None


def _ids_in(obj):
    """Every integer stored under an "id" key anywhere in a bpftool JSON value."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "id" and isinstance(v, int):
                out.add(v)
            else:
                out |= _ids_in(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _ids_in(v)
    return out


def attached(iface):
    """Is the pinned program attached to `iface`?

    True / False, or None when that cannot be told (bpftool missing, or its
    output not understood): callers then leave things as they are instead of
    guessing. Compares program ids, so another XDP program on the interface
    does not count."""
    if not iface or not loaded() or not os.path.exists(f"/sys/class/net/{iface}"):
        return False
    if not shutil.which("bpftool"):
        return None
    pid = prog_id()
    r = _run(["bpftool", "-j", "net", "show", "dev", iface], check=False)
    if pid is None or r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout or "null")
    except ValueError:
        return None
    entries = []
    for top in (data if isinstance(data, list) else [data]):
        if isinstance(top, dict):
            entries += [e for e in (top.get("xdp") or [])
                        if not isinstance(e, dict) or e.get("devname") in (None, iface)]
    if not entries:
        return False                      # no XDP program on this interface at all
    ids = _ids_in(entries)
    if not ids:
        return None                       # something is attached, but no ids were printed
    return pid in ids


_checked = {}   # last result of ensure_attached: {"at": monotonic seconds, "err": str or None}
_check_lock = threading.Lock()          # the IDS, flow and expiry workers all ask


def ensure_attached(ttl=30, clock=time.monotonic):
    """Make sure the loaded program is on the interface it was loaded for, so
    that a blocklist entry really drops packets. If the attachment is gone it is
    attached again; if that fails, RuntimeError. Looked at once per `ttl`
    seconds at most; the answer in between is the last one."""
    with _check_lock:
        now = clock()
        if not _checked or now - _checked["at"] >= ttl:
            err = _attach_error()
            _checked.update(at=now, err=err)
        err = _checked["err"]
    if err:
        raise RuntimeError(err)


def _attach_error():
    iface, mode = target()
    if not iface:
        return None                       # not attached by `load`: nothing to compare with
    if attached(iface) is not False:
        return None                       # attached, or cannot tell: as before
    try:
        attach(iface, mode)
    except RuntimeError as e:
        if attached(iface):               # another process attached it meanwhile
            return None
        why = (str(e).strip().splitlines() or ["?"])[-1]
        return f"the XDP program is not attached to {iface} and attaching it failed: {why}"
    print(f"[*] the XDP program was not attached to {iface}; attached again ({mode})", flush=True)
    return None


def _cleanup_pins():
    for p in (PROG_PIN, BLOCK_MAP, BLOCK6_MAP, STATS_MAP):
        if os.path.exists(p):
            os.unlink(p)
    if os.path.isdir(PIN_DIR) and not os.listdir(PIN_DIR):
        os.rmdir(PIN_DIR)


def unload(iface):
    # detach from the interface it was actually attached to (the config may
    # already name a different one, e.g. when switching interfaces)
    iface = target(iface)[0]
    _detach(iface)
    _checked.clear()
    try:
        os.unlink(IFACE_FILE)
    except OSError:
        pass
    _cleanup_pins()
    print(f"[+] XDP detached from {iface}; pins removed")


def stats():
    """(dropped, expired) summed over CPUs; (None, None) if not loaded."""
    if not os.path.exists(STATS_MAP):
        return None, None
    out = json.loads(_run(["bpftool", "-j", "map", "dump", "pinned", STATS_MAP]).stdout or "[]")
    totals = [0, 0]
    for e in out:
        f = e.get("formatted", e)
        idx = f.get("key")
        if isinstance(idx, list):
            idx = int(idx[0], 16)
        vals = f.get("values", e.get("values", []))
        s = 0
        for v in vals:
            val = v.get("value")
            if isinstance(val, list):
                val = int.from_bytes(bytes(int(b, 16) for b in val), sys.byteorder)
            s += int(val)
        if idx in (0, 1):
            totals[idx] = s
    return tuple(totals)


def status():
    if not loaded():
        print("XDP enforcement: not loaded")
        return
    from hyeongi.blocklist import Blocklist
    ips = Blocklist(backend="xdp").ips()
    dropped, expired = stats()
    v6 = sum(1 for ip in ips if ":" in ip)
    print(f"XDP enforcement: loaded ({PIN_DIR})")
    print(f"  blocked IPs : {len(ips)} (IPv4 {len(ips) - v6}, IPv6 {v6})"
          + ("" if has_ipv6() else "  [!] no IPv6 map: sudo systemctl restart hyeongi-xdp"))
    print(f"  dropped pkts: {dropped}   expired entries removed: {expired}")
    net = _run(["bpftool", "net", "show"], check=False).stdout.splitlines()
    xdp_lines, in_xdp = [], False
    for line in net:                       # print the "xdp:" section only
        if line.rstrip().endswith(":") and not line.startswith(" "):
            in_xdp = line.strip().lower() == "xdp:"
            continue
        if in_xdp and line.strip():
            xdp_lines.append(line.strip())
    print("  attached to : " + (", ".join(xdp_lines) or "(none found)"))
    iface = target()[0]
    if iface:
        print(f"  loaded for  : {iface}  ->  " + {True: "attached", None: "could not verify",
              False: "NOT attached: blocked IPs are not dropped (sudo systemctl restart hyeongi-xdp)"}[attached(iface)])


def main():
    ap = argparse.ArgumentParser(description="HYEONGI XDP enforcement backend")
    ap.add_argument("cmd", choices=["load", "unload", "status", "build"])
    ap.add_argument("--iface")
    ap.add_argument("--mode", choices=list(ATTACH))
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    if os.geteuid() != 0 and a.cmd != "build":
        sys.exit("[x] needs root")
    if a.cmd in ("load", "unload") and not (a.iface and a.mode):
        from hyeongi import config
        c = config.load(a.config)
        a.iface = a.iface or c["xdp"]["iface"]
        a.mode = a.mode or c["xdp"]["mode"]
    if a.cmd == "build":
        build()
    elif a.cmd == "load":
        load(a.iface, a.mode)
    elif a.cmd == "unload":
        unload(a.iface)
    else:
        status()


if __name__ == "__main__":
    main()

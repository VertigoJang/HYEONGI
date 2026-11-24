#!/usr/bin/env python3
"""Shared enforcement blocklist.

A single kernel-side blocklist that every detector feeds and that drops
matching source traffic. Entries carry a timeout so a dynamic,
detector-driven blocklist expires on its own.

Backends:
  nft  - nftables sets in isolated tables 'ip hyeongi' (IPv4) and 'ip6 hyeongi'
         (IPv6), input hook, prio -150. Separate from firewalld's tables; removed
         with `nft delete table ip hyeongi` / `nft delete table ip6 hyeongi`.
  xdp  - XDP program + pinned eBPF hash maps (/sys/fs/bpf/hyeongi; one for IPv4,
         one for IPv6), loaded by `python3 -m hyeongi.xdp load`. Drops before the
         kernel allocates an skb (native mode). Expiry is checked in-kernel
         against CLOCK_MONOTONIC.
  winfw - Windows Defender Firewall rules (group "HYEONGI"), see hyeongi.winfw.
         Expiry is enforced by hyeongid (reconcile every minute).

CLI:
  python3 -m hyeongi.blocklist [--backend nft|xdp] {setup|add IP|remove IP|list|flush|teardown}
"""
import ipaddress
import json
import re
import subprocess
import sys
import time

TABLE = "hyeongi"
SETNAME = "blocklist"
BACKENDS = ("nft", "xdp", "winfw")
# nft table family and set element type per IP version
NFT = {4: ("ip", "ipv4_addr", "ip"), 6: ("ip6", "ipv6_addr", "ip6")}


def _version(ip):
    return ipaddress.ip_address(ip).version


def _sortkey(ip):
    a = ipaddress.ip_address(ip)
    return (a.version, a)


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timeout(t):
    """'90s' / '30m' / '1h' / '2d' / '1h30m' -> seconds (0 = never)."""
    t = str(t).strip().lower()
    if t in ("0", "never", "none", ""):
        return 0
    parts = re.findall(r"(\d+)([smhd])", t)
    if not parts or "".join(n + u for n, u in parts) != t:
        raise ValueError(f"bad timeout: {t!r} (use e.g. 90s, 30m, 1h, 2d)")
    return sum(int(n) * _UNITS[u] for n, u in parts)


class Blocklist:
    def __init__(self, backend="nft", default_timeout="1h"):
        if backend not in BACKENDS:
            raise ValueError(f"unknown backend {backend!r} (use one of {BACKENDS})")
        self.backend = backend
        self.default_timeout = default_timeout
        self._win = None
        if backend == "winfw":
            from hyeongi.winfw import WinFirewall
            self._win = WinFirewall()

    # ------------------------------------------------------------------ setup
    def exists(self):
        if self.backend == "winfw":
            return True                       # the Windows firewall is always there
        if self.backend == "xdp":
            from hyeongi import xdp
            return xdp.loaded()
        return all(self._nft_has(v) for v in NFT)

    @staticmethod
    def _nft_has(v):
        return _run(["nft", "list", "table", NFT[v][0], TABLE]).returncode == 0

    @staticmethod
    def _nft_create(v):
        fam, typ, match = NFT[v]
        _run(["nft", "delete", "table", fam, TABLE])  # clean slate
        _run(["nft", "add", "table", fam, TABLE])
        _run(["nft", "add", "set", fam, TABLE, SETNAME,
              "{ type %s; flags timeout; }" % typ])
        _run(["nft", "add", "chain", fam, TABLE, "input",
              "{ type filter hook input priority -150; }"])
        _run(["nft", "add", "rule", fam, TABLE, "input",
              match + " saddr @" + SETNAME, "drop"])

    def setup(self, reset=False):
        """Make sure the enforcement point exists.

        nft: create the IPv4 and IPv6 tables/sets/chains/rules. reset=False (what
        detectors use) keeps an existing table and its entries so several
        detectors share one blocklist and a restart doesn't wipe active blocks;
        a missing table (e.g. the IPv6 one after an upgrade) is created.
        reset=True recreates both (CLI `setup`).
        xdp: the program is attached by `hyeongi.xdp load` (hyeongi-xdp service);
        here we only check it is there (reset=True also empties the map).
        """
        if self.backend == "winfw":
            if reset:
                self.flush()
            return
        if self.backend == "xdp":
            if not self.exists():
                import sys
                print("[x] XDP backend not loaded — sudo systemctl start hyeongi-xdp "
                      "(or: sudo python3 -m hyeongi.xdp load)", file=sys.stderr, flush=True)
                sys.exit(2)   # misconfiguration: services don't restart-loop on 2
            if reset:
                self.flush()
            return
        for v in NFT:
            if reset or not self._nft_has(v):
                self._nft_create(v)

    # ------------------------------------------------------------- entries
    def add(self, ip, timeout=None):
        to = timeout or self.default_timeout
        if self.backend == "winfw":
            self._win.add(ip, parse_timeout(to))
            return
        if self.backend == "xdp":
            from hyeongi import xdp
            xdp.ensure_attached()          # else the map is updated and nothing is dropped
            secs = parse_timeout(to)
            expiry = time.monotonic_ns() + secs * 1_000_000_000 if secs else 0
            _xdp_put(ip, expiry)
            return
        _run(["nft", "add", "element", NFT[_version(ip)][0], TABLE, SETNAME,
              "{ %s timeout %s }" % (ip, to)])

    def remove(self, ip):
        if self.backend == "winfw":
            self._win.remove(ip)
            return
        if self.backend == "xdp":
            m, key = _key(ip)
            _run(["bpftool", "map", "delete", "pinned", m, "key"] + key)
            return
        _run(["nft", "delete", "element", NFT[_version(ip)][0], TABLE, SETNAME,
              "{ %s }" % ip])

    def ips(self):
        """Currently blocked IPv4 and IPv6 addresses (expired entries excluded)."""
        if self.backend == "winfw":
            return [ip for ip, _ in self._win.entries()]
        if self.backend == "xdp":
            now = time.monotonic_ns()
            return sorted((ip for ip, exp in _xdp_entries() if exp == 0 or exp > now),
                          key=_sortkey)
        out = set()
        for v in NFT:
            out.update(_nft_elements(v))
        return sorted(out, key=_sortkey)

    def list(self):
        """Human-readable contents (empty string if absent)."""
        if self.backend == "winfw":
            now = time.time()
            return "".join(f"{ip}  (no expiry)\n" if exp == 0 else
                           f"{ip}  (expires in {int(exp - now)}s)\n"
                           for ip, exp in self._win.entries())
        if self.backend == "xdp":
            if not self.exists():
                return ""
            now = time.monotonic_ns()
            lines = []
            for ip, exp in sorted(_xdp_entries(), key=lambda e: _sortkey(e[0])):
                if exp == 0:
                    lines.append(f"{ip}  (no expiry)")
                elif exp > now:
                    lines.append(f"{ip}  (expires in {(exp - now) // 1_000_000_000}s)")
            return "".join(l + "\n" for l in lines)
        return "".join(_run(["nft", "list", "set", NFT[v][0], TABLE, SETNAME]).stdout
                       for v in NFT)

    def flush(self):
        if self.backend == "winfw":
            self._win.flush()
            return
        if self.backend == "xdp":
            for ip, _ in _xdp_entries():
                self.remove(ip)
            return
        for v in NFT:
            _run(["nft", "flush", "set", NFT[v][0], TABLE, SETNAME])

    def reconcile(self):
        """Expire entries where the kernel can't (winfw). No-op elsewhere."""
        return self._win.reconcile() if self.backend == "winfw" else 0

    def teardown(self):
        if self.backend == "winfw":
            self._win.flush()                 # removes all HYEONGI firewall rules
            return
        if self.backend == "xdp":
            raise SystemExit("XDP is detached by: sudo systemctl stop hyeongi-xdp "
                             "(or: sudo python3 -m hyeongi.xdp unload)")
        for v in NFT:
            _run(["nft", "delete", "table", NFT[v][0], TABLE])


def _nft_elements(v):
    """Addresses in the nft set of IP version v (the kernel drops expired ones)."""
    r = _run(["nft", "-j", "list", "set", NFT[v][0], TABLE, SETNAME])
    out = []
    try:
        items = json.loads(r.stdout or "{}").get("nftables", [])
    except ValueError:
        items = []
    for it in items:
        for e in (it.get("set") or {}).get("elem", []) or []:
            val = e["elem"].get("val") if isinstance(e, dict) and "elem" in e else e
            if isinstance(val, str):
                try:
                    out.append(str(ipaddress.ip_address(val)))
                except ValueError:
                    pass
    return out


# ---------------------------------------------------------------- xdp helpers
def _xdp_map(v=4):
    from hyeongi import xdp
    return xdp.BLOCK_MAP if v == 4 else xdp.BLOCK6_MAP


def _hexbytes(b):
    return ["0x%02x" % x for x in b]


def _key(ip):
    """(pinned map, key bytes) for an address: the IPv4 or the IPv6 map, key in
    network byte order as in iphdr->saddr / ipv6hdr->saddr."""
    addr = ipaddress.ip_address(ip)
    m = _xdp_map(addr.version)
    if addr.version == 6:
        import os
        if not os.path.exists(m):
            raise RuntimeError("the loaded XDP program has no IPv6 map (loaded before "
                               "3.0.0rc33) — sudo systemctl restart hyeongi-xdp")
    return m, _hexbytes(addr.packed)


def _xdp_put(ip, expiry_ns):
    m, key = _key(ip)
    r = _run(["bpftool", "map", "update", "pinned", m, "key"] + key
             + ["value"] + _hexbytes(int(expiry_ns).to_bytes(8, sys.byteorder)))
    if r.returncode != 0:
        raise RuntimeError(f"bpftool map update failed: {r.stderr.strip()}")


def _xdp_restore(entries):
    """Put [(ip, expiry_ns)] back after a reload (same boot, so expiries still hold)."""
    for ip, exp in entries:
        try:
            _xdp_put(ip, exp)
        except (RuntimeError, ValueError):
            pass


def _bytes_of(v, n):
    """bpftool JSON field -> raw bytes (accepts ['0x..',...] or an integer)."""
    if isinstance(v, list):
        return bytes(int(x, 16) for x in v)
    return int(v).to_bytes(n, sys.byteorder)


def _xdp_entries():
    """[(ip, expiry_ns)] from the pinned IPv4 and IPv6 maps."""
    import os
    out = []
    for ver, size in ((4, 4), (6, 16)):
        m = _xdp_map(ver)
        if ver == 6 and not os.path.exists(m):
            continue                           # program from before rc33
        r = _run(["bpftool", "-j", "map", "dump", "pinned", m])
        if r.returncode != 0 or not r.stdout.strip():
            continue
        for e in json.loads(r.stdout):
            k = e["key"] if "key" in e else e["formatted"]["key"]
            v = e["value"] if "value" in e else e["formatted"]["value"]
            ip = str(ipaddress.ip_address(_raw_addr(k, size)))
            out.append((ip, int.from_bytes(_bytes_of(v, 8), sys.byteorder)))
    return out


def _raw_addr(k, size):
    """Map key from bpftool JSON -> raw address bytes. Raw dumps give a list of
    hex bytes; with BTF the IPv6 key (struct in6_addr) may come back formatted
    as {"in6_u": {"u6_addr8": [..16 ints..], ...}}."""
    if isinstance(k, dict):
        u = k.get("in6_u", k)
        for name in ("u6_addr8", "s6_addr"):
            if name in u:
                return bytes(int(x) & 0xff for x in u[name])
        raise ValueError(f"unknown key format: {k!r}")
    if isinstance(k, list):
        return bytes(int(x, 16) if isinstance(x, str) else int(x) for x in k)
    if size == 4:
        # BTF-formatted __u32: host-order integer of the network-order bytes
        return int(k).to_bytes(4, sys.byteorder)
    raise ValueError(f"unknown key format: {k!r}")


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="manage the HYEONGI enforcement blocklist")
    ap.add_argument("cmd", choices=["setup", "add", "remove", "list", "flush", "teardown"])
    ap.add_argument("ip", nargs="?")
    ap.add_argument("--timeout", default="1h")
    ap.add_argument("--backend", choices=BACKENDS, default=None,
                    help="default: 'backend' from /etc/hyeongi/hyeongi.yaml, else nft")
    a = ap.parse_args()
    backend = a.backend
    if backend is None:
        try:
            from hyeongi import config
            backend = config.load()["backend"]
        except SystemExit:
            backend = "nft"
    bl = Blocklist(backend=backend, default_timeout=a.timeout)
    if a.cmd == "setup":
        bl.setup(reset=True); print(f"[+] enforcement set up ({backend})")
    elif a.cmd == "add":
        if not a.ip: ap.error("add needs an IP")
        bl.setup()  # create (nft) / verify loaded (xdp); keeps existing entries
        try:
            bl.add(a.ip)
        except RuntimeError as e:
            sys.exit(f"[x] not blocked: {e}")
        print(f"[+] blocked {a.ip} (timeout {a.timeout}, {backend})")
    elif a.cmd == "remove":
        if not a.ip: ap.error("remove needs an IP")
        bl.remove(a.ip); print(f"[+] removed {a.ip}")
    elif a.cmd == "list":
        print(bl.list(), end="")
    elif a.cmd == "flush":
        bl.flush(); print("[+] flushed")
    elif a.cmd == "teardown":
        bl.teardown(); print("[+] torn down")


if __name__ == "__main__":
    _cli()

"""This host's own network: DNS servers, default gateways, own addresses.

Used to never block the host's own infrastructure (`protect_local`), and by
the triage to mark such alerts as false positives without asking the model.
A laptop changes networks, so the bridge re-reads it at most once a minute.
"""
import hashlib, ipaddress, json, os, re, subprocess, time

WINDOWS = os.name == "nt"


def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _ipv4s(text):
    return [ip for ip in _ips(text) if ":" not in ip]


def _ips(text):
    """IPv4 and IPv6 addresses in `text`, canonical form, in order, no duplicates.

    Tokens are split on whitespace, commas and semicolons; an "IP6.DNS[1]:addr"
    prefix (nmcli -t) and a "%zone" suffix are removed first."""
    out = []
    for tok in re.split(r"[\s,;]+", text or ""):
        if "]:" in tok:
            tok = tok.split("]:", 1)[1]
        tok = tok.replace("\\:", ":")          # nmcli -t escapes ':' inside values
        tok = tok.strip("[]").split("%", 1)[0]
        if not tok or not (":" in tok or "." in tok):
            continue
        try:
            ip = str(ipaddress.ip_address(tok))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def _real(ip):
    a = ipaddress.ip_address(ip)
    return not (a.is_loopback or a.is_unspecified)


def local_context():
    """This host's DNS servers, default gateways and own addresses (IPv4 and
    IPv6), plus the on-link IPv6 prefixes of its global addresses.

    "prefixes" exists because IPv6 hosts change their own address on their own
    (privacy/temporary addresses, RFC 8981): an address in one of this host's
    on-link /64s is treated as local even before the next refresh sees it.

    Best effort: anything that can't be read is left empty."""
    dns, gw, own, prefixes = [], [], [], []
    if WINDOWS:
        ps = ["powershell", "-NoProfile", "-Command"]
        dns = _ips(_run(ps + ["Get-DnsClientServerAddress | "
                              "ForEach-Object { $_.ServerAddresses }"]))
        gw = _ips(_run(ps + ["Get-NetRoute -DestinationPrefix 0.0.0.0/0,::/0 "
                             "-ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop }"]))
        for line in _run(ps + ["Get-NetIPAddress | ForEach-Object "
                               "{ $_.IPAddress + '/' + $_.PrefixLength }"]).splitlines():
            addr, _, plen = line.strip().partition("/")
            for ip in _ips(addr):
                if ip not in own:
                    own.append(ip)
                _add_prefix(prefixes, ip, plen)
    else:
        for f in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.startswith("nameserver"):
                            dns += [ip for ip in _ips(line) if ip not in dns]
            except OSError:
                pass
        # systemd-resolved stub (127.0.0.53) hides the real servers; ask NetworkManager too
        dns += [ip for ip in _ips(_run(["nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "dev", "show"]))
                if ip not in dns]
        for fam in ("-4", "-6"):
            try:
                for r in json.loads(_run(["ip", "-j", fam, "route", "show", "default"]) or "[]"):
                    for ip in _ips(r.get("gateway") or ""):
                        if ip not in gw:
                            gw.append(ip)
            except ValueError:
                pass
            try:
                for link in json.loads(_run(["ip", "-j", fam, "addr"]) or "[]"):
                    for a in link.get("addr_info", []):
                        for ip in _ips(a.get("local") or ""):
                            if ip not in own:
                                own.append(ip)
                            if a.get("scope") == "global":
                                _add_prefix(prefixes, ip, a.get("prefixlen"))
            except ValueError:
                pass
    dns = [ip for ip in dns if _real(ip)]
    own = [ip for ip in own if _real(ip)]
    return {"dns": dns, "gateway": gw, "own": own, "prefixes": prefixes}


def _add_prefix(prefixes, ip, plen):
    """Record the on-link network of a global IPv6 address. Prefixes longer than
    /64 (e.g. a DHCPv6 /128) are widened to /64: temporary addresses are made
    inside the /64 the router advertises."""
    try:
        a = ipaddress.ip_address(ip)
        n = int(plen)
    except (ValueError, TypeError):
        return
    if a.version != 6 or a.is_link_local or a.is_loopback or a.is_multicast or n < 0:
        return
    net = str(ipaddress.ip_network(f"{a}/{64 if n > 64 else n}", strict=False))
    if ipaddress.ip_network(net).prefixlen < 48:
        return                                 # not an on-link network; too broad to trust
    if net not in prefixes:
        prefixes.append(net)




class LocalInfra:
    """Cached set of local infrastructure IPs (DNS servers, gateways, own
    addresses), refreshed at most every `ttl` seconds.

    IPv6 hosts make new temporary addresses on their own (RFC 8981), so an
    address inside one of this host's on-link /64s that is not in the cached
    set triggers an immediate re-read (at most every `recheck` seconds): if it
    is this host's new address it is local. Otherwise it is a neighbour on the
    same local network, which counts as local only when `onlink_local` is true
    — the IPv6 counterpart of RFC1918 neighbours, which are not blocked unless
    block_private (pass onlink_local=not block_private)."""

    def __init__(self, ttl=60, probe=None, clock=time.monotonic, onlink_local=True, recheck=2):
        self.ttl, self.probe, self.clock = ttl, probe or local_context, clock
        self.onlink_local, self.recheck = onlink_local, recheck
        self._at, self._ips, self._nets = None, frozenset(), ()

    def _refresh(self, force=False):
        now = self.clock()
        if (self._at is None or now - self._at >= self.ttl
                or (force and now - self._at >= self.recheck)):
            try:
                c = self.probe()
                self._ips = frozenset(_ips(" ".join(c["dns"] + c["gateway"] + c["own"])))
                self._nets = tuple(ipaddress.ip_network(n) for n in c.get("prefixes", ()))
            except Exception:
                pass                      # keep the previous answer
            self._at = now

    def ips(self):
        self._refresh()
        return self._ips

    def prefixes(self):
        self._refresh()
        return self._nets

    def __contains__(self, ip):
        self._refresh()
        found = _ips(ip if isinstance(ip, str) else "")
        if not found:
            return False
        if found[0] in self._ips:
            return True
        a = ipaddress.ip_address(found[0])
        if a.version != 6 or not any(a in n for n in self._nets):
            return False
        self._refresh(force=True)             # maybe a temporary address made since
        if found[0] in self._ips:
            return True
        return self.onlink_local


def default_gateway_mac():
    """(gateway_ip, mac, iface) of the current default route, lowercased MAC,
    or (None, None, None). Linux only; Windows returns empties (gating stays off
    unless a trust list is set, so this does not disable Windows enforcement)."""
    if WINDOWS:
        return None, None, None
    gw_ip = iface = mac = None
    try:
        for r in json.loads(_run(["ip", "-j", "-4", "route", "show", "default"]) or "[]"):
            if r.get("gateway"):
                gw_ip, iface = r["gateway"], r.get("dev"); break
    except ValueError:
        pass
    if gw_ip:
        try:
            for n in json.loads(_run(["ip", "-j", "neigh", "show"]) or "[]"):
                if n.get("dst") == gw_ip and n.get("lladdr"):
                    mac = n["lladdr"].lower(); break
        except ValueError:
            pass
    return gw_ip, mac, iface


class NetworkPolicy:
    """Whether enforcement (real blocking) is allowed on the current network,
    decided by the default gateway's MAC address. Only gateways in `trusted`
    enforce; every other network is observe-only (detect, never block). A laptop
    changes networks, so this is re-read every `ttl` seconds.

    Opt-in: an EMPTY trusted list means the feature is off and enforcement
    follows the config everywhere (unchanged behaviour). Once any gateway is
    trusted, gating is active and unknown/offline networks are observe-only."""

    def __init__(self, trusted=(), ttl=30, clock=time.monotonic, probe=None):
        self.trusted = {str(m).lower() for m in (trusted or ()) if m}
        self.ttl, self.clock = ttl, clock
        self.probe = probe or default_gateway_mac
        self._at = self._mac = self._gw = self._iface = None

    def _refresh(self):
        now = self.clock()
        if self._at is None or now - self._at >= self.ttl:
            try:
                self._gw, mac, self._iface = self.probe()
                self._mac = mac.lower() if mac else None
            except Exception:
                self._gw = self._mac = self._iface = None
            self._at = now

    def allowed(self):
        if not self.trusted:                 # feature off: enforce per config
            return True
        self._refresh()
        return bool(self._mac) and self._mac in self.trusted

    def current(self):
        self._refresh()
        return {"gateway": self._gw, "mac": self._mac, "iface": self._iface,
                "trusted": (not self.trusted) or (bool(self._mac) and self._mac in self.trusted),
                "gating": bool(self.trusted)}


# ---------------------------------------------------------- flow direction ---
def _own_only():
    c = local_context()
    return {"dns": [], "gateway": [], "own": c["own"], "prefixes": c.get("prefixes", [])}


class Direction:
    """Who started a flow, from this host's point of view: "out" when the source
    is one of this host's own addresses, "in" when the destination is, "" when
    neither (forwarded traffic, or the address set lagged behind).

    The live detectors only ever act on the source of a flow and never on this
    host itself, so only "in" flows can lead to a block. Outbound flows that
    look like attacks (this host scanning its own server, connection attempts
    nobody answers) are feature-identical to inbound probes; keeping them apart
    stops them from being learned or counted as benign."""

    def __init__(self, probe=None, **kw):
        self.own = LocalInfra(probe=probe or _own_only, onlink_local=False, **kw)

    def __call__(self, src, dst):
        if src in self.own:
            return "out"
        if dst in self.own:
            return "in"
        return ""


# ------------------------------------------------------- training-data tags ---
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
RESERVED = ("unknown", "gw-")


def valid_label(label):
    """A network name a person may give (`hyeongi ctl name-here`): letters,
    digits, '.', '_', '-', at most 32 characters, and not one of the automatic
    tags ('unknown', 'gw-...')."""
    return bool(label and LABEL_RE.match(label)
                and label != "unknown" and not label.startswith("gw-"))


def salt_path(capture_dir):
    """Where the per-host salt lives: next to the flow directory
    (/var/lib/hyeongi/net-salt for /var/lib/hyeongi/flows)."""
    return os.path.join(os.path.dirname(os.path.normpath(capture_dir)), "net-salt")


def load_salt(path, create=False):
    """Random per-host salt for unnamed network tags, or "" if not readable.

    A bare hash of a MAC address is no protection: the first half is a known
    vendor prefix, so the rest can be tried in seconds. With a random salt
    that never leaves this host, a shared flow CSV says "same network as that
    other row", not which network it was."""
    try:
        with open(path, encoding="ascii") as f:
            s = f.read().strip()
        if s:
            return s
    except OSError:
        pass
    if not create:
        return ""
    s = os.urandom(16).hex()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(s + "\n")
    except FileExistsError:                   # another worker made it first
        return load_salt(path)
    except OSError:
        return ""
    return s


def net_tag(mac, names=None, salt=""):
    """Tag for the network behind default-gateway `mac`: the name a person gave
    it (networks.names), else "gw-" + 8 hex of a salted hash, else "unknown"
    (no default route, gateway MAC not resolved, or Windows)."""
    if not mac:
        return "unknown"
    mac = str(mac).lower()
    for k, v in (names or {}).items():
        if str(k).lower() == mac and valid_label(str(v)):
            return str(v)
    return "gw-" + hashlib.sha256((salt + mac).encode()).hexdigest()[:8]


class NetTagger:
    """The tag of the network this host is on now, re-read every `ttl` seconds.
    A flow is tagged when it ends, so one that spans a network change carries
    the network it ended on."""

    def __init__(self, names=None, salt="", ttl=30, clock=time.monotonic, probe=None):
        self.names, self.salt, self.ttl, self.clock = dict(names or {}), salt, ttl, clock
        self.probe = probe or default_gateway_mac
        self._at, self._tag = None, "unknown"

    def current(self):
        now = self.clock()
        if self._at is None or now - self._at >= self.ttl:
            try:
                _, mac, _ = self.probe()
                self._tag = net_tag(mac, self.names, self.salt)
            except Exception:
                pass                          # keep the previous tag
            self._at = now
        return self._tag

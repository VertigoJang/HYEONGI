"""Privileged actions for the desktop app (run as root / Administrator).

The app runs as the normal user and calls this through pkexec (Linux) or from
an elevated process (Windows). Every argument is validated here; nothing from
the caller reaches a shell.

  checkhook ctl block <ip>            block an IP now, for block_timeout (a person's decision,
                                      e.g. after reading the LLM review; works with enforce off)
  checkhook ctl unblock <ip>          remove an IP from the blocklist now
  checkhook ctl skip-add <ip>         never block this IP (config skip:), restart
  checkhook ctl skip-remove <ip>
  checkhook ctl enforce on|off        turn blocking on/off (config enforce:), restart
  checkhook ctl pause [reason] | resume
  checkhook ctl triage                run the LLM review now
  checkhook ctl trust-here            trust THIS network's gateway: enforce here, observe elsewhere
  checkhook ctl untrust-here          remove this network from the trusted list
  checkhook ctl practice start [--target IP] [memo]   stop everything for attack practice
  checkhook ctl practice end          start again and check the training data is clean
  checkhook ctl name-here <name>      name THIS network (e.g. home, school) in the flow logs'
                                      `net` column, so training data can be split by network
  checkhook ctl unname-here           drop the name; flows here get the automatic gw-xxxxxxxx tag
  checkhook ctl net                   show the current network and whether it enforces
  checkhook ctl start                 start every CheckHook service (detection + enforcement)
  checkhook ctl stop                  stop every CheckHook service; IPs already blocked stay blocked
                                      (clear them with: checkhook flush)
  checkhook ctl restart               restart checkhookd
"""
import ipaddress, os, re, subprocess, sys
import yaml
from checkhook import config


def die(msg, code=2):
    print(f"[x] {msg}", file=sys.stderr)
    sys.exit(code)


def need_ip(s):
    try:
        ip = ipaddress.ip_address(s.strip().strip("[]").split("%", 1)[0])
    except (ValueError, AttributeError):
        die(f"not an IP address: {s!r}")
    return str(ip)


# ------------------------------------------------------------- config edit ---
def _read(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def _write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(tmp, os.stat(path).st_mode & 0o777)
    except OSError:
        pass
    os.replace(tmp, path)


def set_top_key(text, key, value_text):
    """Replace `key: ...` at the top level, keeping a trailing comment; append if missing."""
    pat = re.compile(rf"^{key}:[^\n#]*(#[^\n]*)?$", re.M)
    m = pat.search(text)
    if m:
        comment = m.group(1) or ""
        line = f"{key}: {value_text}"
        if comment:
            line = line.ljust(26) + " " + comment
        return text[:m.start()] + line + text[m.end():]
    return text.rstrip("\n") + f"\n{key}: {value_text}\n"


def edit_skip(path, ip, add):
    text = _read(path)
    cur = (yaml.safe_load(text) or {}).get("skip") or []
    cur = [str(x) for x in cur]
    if add and ip not in cur:
        cur.append(ip)
    if not add:
        cur = [x for x in cur if x != ip]
    _write(path, set_top_key(text, "skip", "[" + ", ".join(cur) + "]"))
    return cur


MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _networks(text):
    net = (yaml.safe_load(text) or {}).get("networks") or {}
    trusted = [str(x).lower() for x in (net.get("trusted_gateways") or [])]
    names = {str(k).lower(): str(v) for k, v in (net.get("names") or {}).items()}
    return trusted, names


def _write_networks(path, text, trusted, names):
    """networks: is written as one flow-style line holding both keys, so editing
    one never drops the other. MACs and names are validated before they get here."""
    t = ", ".join(f'"{m}"' for m in trusted)
    n = ", ".join(f'"{k}": "{v}"' for k, v in sorted(names.items()))
    _write(path, set_top_key(text, "networks", "{trusted_gateways: [" + t + "], names: {" + n + "}}"))


def edit_trusted_gateway(path, mac, add):
    text = _read(path)
    cur, names = _networks(text)
    mac = mac.lower()
    if not MAC_RE.match(mac):
        die(f"not a MAC address: {mac!r}")
    if add and mac not in cur:
        cur.append(mac)
    if not add:
        cur = [x for x in cur if x != mac]
    _write_networks(path, text, cur, names)
    return cur


def edit_net_name(path, mac, name):
    """Set (name) or drop (name=None) the flow-log name of the network behind `mac`."""
    from checkhook.netinfo import valid_label
    text = _read(path)
    trusted, names = _networks(text)
    mac = mac.lower()
    if not MAC_RE.match(mac):
        die(f"not a MAC address: {mac!r}")
    if name is None:
        names.pop(mac, None)
    else:
        if not valid_label(name):
            die(f"bad name {name!r}: letters, digits, . _ - (max 32), not 'unknown' or 'gw-...'")
        names[mac] = name
    _write_networks(path, text, trusted, names)
    return names


def edit_enforce(path, on):
    text = _read(path)
    _write(path, set_top_key(text, "enforce", "true" if on else "false"))


# ----------------------------------------------------------------- actions ---
UNITS = ("checkhookd", "checkhook-ids", "checkhook-xdp", "checkhook-capture")


def _win_task(action):                       # action: Start | Stop
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"{action}-ScheduledTask -TaskName checkhookd -ErrorAction SilentlyContinue"],
                   check=False)


def start_all():
    """Start every CheckHook service. systemd resolves order from their After=."""
    if config.WINDOWS:
        _win_task("Start"); return
    subprocess.run(["systemctl", "start", *UNITS], check=False)


def stop_all():
    """Stop every CheckHook service. The kernel blocklist is left as it is
    (option 1): IPs already blocked stay blocked until block_timeout or a
    manual `checkhook flush`. Stopping only halts detection and new blocks."""
    if config.WINDOWS:
        _win_task("Stop"); return
    subprocess.run(["systemctl", "stop", *UNITS], check=False)


def restart():
    if config.WINDOWS:
        ps = ("$all = Get-CimInstance Win32_Process; "
              "$d = $all | Where-Object { $_.CommandLine -match 'checkhook\\.daemon' }; "
              "foreach ($a in $d) { $all | Where-Object { $_.ParentProcessId -eq $a.ProcessId } | "
              "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }; "
              "Stop-ScheduledTask -TaskName checkhookd -ErrorAction SilentlyContinue; "
              "Start-ScheduledTask -TaskName checkhookd")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)
    else:
        subprocess.run(["systemctl", "restart", "checkhookd"], check=False)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd != "net" and not config.WINDOWS and os.geteuid() != 0:   # net is read-only
        die("needs root (the app asks for it through pkexec)")
    path = config.DEFAULT_PATH
    c = config.load(path)

    if cmd == "block" and args:
        ip = need_ip(args[0])
        from checkhook.netinfo import LocalInfra
        from checkhook.policy import norm_ip
        # a person may block a neighbour on the same IPv6 network; only this host's
        # own addresses, DNS servers and gateways are refused
        if ip in LocalInfra(onlink_local=False) or ip in {norm_ip(str(x)) for x in c["skip"]}:
            die(f"{ip} is this host's own DNS server/gateway/address or in skip:; not blocking it")
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            die("refusing to block a loopback, unspecified or multicast address")
        from checkhook.blocklist import Blocklist
        bl = Blocklist(backend=c["backend"], default_timeout=c["block_timeout"])
        bl.setup()
        bl.add(ip)
        from checkhook.status import log_manual
        log_manual(ip, "block")
        print(f"[+] blocked {ip} for {c['block_timeout']} (manual)")
    elif cmd == "unblock" and args:
        ip = need_ip(args[0])
        from checkhook.blocklist import Blocklist
        Blocklist(backend=c["backend"]).remove(ip)
        from checkhook.status import log_manual
        log_manual(ip, "unblock")
        print(f"[+] unblocked {ip}")
    elif cmd in ("skip-add", "skip-remove") and args:
        ip = need_ip(args[0])
        cur = edit_skip(path, ip, cmd == "skip-add")
        if cmd == "skip-add":
            try:
                from checkhook.blocklist import Blocklist
                Blocklist(backend=c["backend"]).remove(ip)
            except Exception:
                pass
        restart()
        print(f"[+] skip: [{', '.join(cur)}]")
    elif cmd == "enforce" and args and args[0] in ("on", "off"):
        edit_enforce(path, args[0] == "on")
        restart()
        print(f"[+] enforce: {'true' if args[0] == 'on' else 'false'}")
    elif cmd in ("pause", "resume"):
        from checkhook import collect
        return collect.main([cmd] + [re.sub(r"[^\w .:-]", "", a)[:60] for a in args])
    elif cmd == "triage":
        from checkhook import service
        sys.argv = ["checkhook.service", "triage"]
        return service.main() or 0
    elif cmd in ("trust-here", "untrust-here"):
        from checkhook.netinfo import default_gateway_mac
        gw, mac, iface = default_gateway_mac()
        if not mac:
            die("no default-gateway MAC found (offline, or no default route)")
        cur = edit_trusted_gateway(path, mac, cmd == "trust-here")
        restart()
        verb = "trusted" if cmd == "trust-here" else "untrusted"
        print(f"[+] {verb} this network: gateway {gw} (mac {mac}, {iface})")
        print(f"    trusted gateways now: {cur or 'none — enforcement follows enforce: everywhere'}")
        if cmd == "trust-here" and len(cur) == 1:
            print("    gating is now ON: other networks are observe-only (detect, never block)")
    elif cmd in ("name-here", "unname-here"):
        from checkhook.netinfo import default_gateway_mac
        gw, mac, iface = default_gateway_mac()
        if not mac:
            die("no default-gateway MAC found (offline, or no default route)")
        if cmd == "name-here":
            if len(args) != 1:
                die("usage: checkhook name-here <name>   (e.g. home, school)")
            edit_net_name(path, mac, args[0])
            print(f"[+] this network (gateway {gw}, mac {mac}) is now '{args[0]}' in the flow logs")
        else:
            edit_net_name(path, mac, None)
            print(f"[+] name removed for gateway {gw} (mac {mac}); flows here get a gw-xxxxxxxx tag")
        restart()
        print("    flows logged from now on carry it; earlier rows keep the tag they had")
    elif cmd == "net":
        from checkhook.netinfo import NetworkPolicy, load_salt, net_tag, salt_path
        trusted = ((c.get("networks") or {}).get("trusted_gateways")) or []
        pol = NetworkPolicy(trusted); cur = pol.current()
        print(f"gateway: {cur['gateway']}  mac: {cur['mac']}")
        salt = load_salt(salt_path(c["capture"]["dir"]))
        names = (c.get("networks") or {}).get("names") or {}
        tag = net_tag(cur["mac"], names, salt)
        if tag.startswith("gw-") and not salt:
            tag = "(gw-... tag; appears once checkhookd has logged flows)"
        print(f"flow-log tag: {tag}" + ("" if tag in names.values() or not cur["mac"]
                                        else "   (name it: sudo checkhook name-here <name>)"))
        if not cur["gating"]:
            print("gating: off (no trusted gateways) -> enforcement follows enforce: everywhere")
        else:
            print(f"gating: on ({len(trusted)} trusted) -> this network: "
                  + ("ENFORCE (trusted)" if cur["trusted"] else "OBSERVE-ONLY (untrusted)"))
    elif cmd == "practice":
        from checkhook.practice import main as practice
        sys.exit(practice(args))
    elif cmd == "start":
        from checkhook.practice import state as practice_state
        ps = practice_state()
        if ps:
            die(f"practice mode is on since {ps['start']}; end it with: sudo checkhook practice end")
        start_all()
        print("[+] CheckHook started (" + ", ".join(UNITS) + ")")
    elif cmd == "stop":
        stop_all()
        print("[+] CheckHook stopped; already-blocked IPs stay blocked (clear with: checkhook flush)")
    elif cmd == "restart":
        restart()
        print("[+] checkhookd restarted")
    else:
        die(f"unknown or incomplete command: {' '.join(argv)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

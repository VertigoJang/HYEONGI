"""IDS alert parsing shared by the bridge and the triage.

Understands, line by line (auto-detected):
  * Snort 3 alert_json:   {"src_addr": "...", "sid": 1000001, "msg": "...", ...}
  * Suricata eve.json:    {"event_type": "alert", "src_ip": "...",
                           "alert": {"signature_id": 2001219, "signature": "..."}, ...}
Other eve.json events (flow, dns, http, stats ...) are ignored.
"""
import datetime as _dt
import json
import os
import re


def parse_alert(line):
    """Return {"src", "gid", "sid", "msg", "ids", ...} for an alert line, else None.

    Snort/ML lines also carry "dport" (destination port, or None) and "score"
    (the ML attack probability; None for IDS alerts).

    gid: Snort generator id (1 = text rules, 3 = shared-object rules, others
    are built-in inspectors such as the packet decoder or port_scan). Suricata
    rules use gid 1."""
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(ev, dict):
        return None
    if "event_type" in ev:                       # Suricata eve.json
        if ev.get("event_type") != "alert":
            return None
        al = ev.get("alert") or {}
        return {"src": ev.get("src_ip"), "gid": _int(al.get("gid"), 1),
                "sid": al.get("signature_id"), "msg": al.get("signature", ""),
                "ids": "suricata", "dport": _int(ev.get("dest_port"), None),
                "score": None, "ts": ev.get("timestamp")}
    if "src_addr" in ev or "sid" in ev:          # Snort 3 alert_json
        gid = _int(ev.get("gid"), 1)
        dport = ev.get("dst_port")
        if dport is None and isinstance(ev.get("dst_ap"), str) and ":" in ev["dst_ap"]:
            dport = ev["dst_ap"].rsplit(":", 1)[1]          # Snort's "addr:port" field
        return {"src": ev.get("src_addr"), "gid": gid, "sid": ev.get("sid"),
                "msg": ev.get("msg", ""), "ids": "ml" if gid == 9000 else "snort",
                "dport": _int(dport, None), "score": ev.get("score"),
                "ts": ev.get("timestamp")}
    return None


class Ignore:
    """Which alerts never lead to a block: whole generators (Snort gid, e.g. the
    packet decoder) and single rules written "gid:sid" (Suricata rules are gid 1)."""

    def __init__(self, gids=(), rules=()):
        self.gids = {int(g) for g in gids}
        self.rules = set()
        for r in rules:
            g, _, s = str(r).partition(":")
            self.rules.add((int(g), int(s)) if s else (1, int(g)))

    def __call__(self, al):
        gid = al.get("gid", 1)
        return gid in self.gids or (gid, _int(al.get("sid"), -1)) in self.rules

    def __bool__(self):
        return bool(self.gids or self.rules)

    def __str__(self):
        parts = [f"gid {g}" for g in sorted(self.gids)]
        parts += [f"{g}:{s}" for g, s in sorted(self.rules)]
        return ", ".join(parts)


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def iter_back(path, max_bytes=64 * 1024 * 1024, block=1024 * 1024, state=None):
    """Parsed alerts of `path`, newest first, reading backwards in blocks.

    Stops after `max_bytes`, so a multi-GB eve.json full of flow and dns
    events is never read whole; then state["truncated"] is set to True if a
    dict is given."""
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return
    with f:
        end = f.seek(0, os.SEEK_END)
        pos, scanned, rest = end, 0, b""
        while pos > 0 and scanned < max_bytes:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            chunk = f.read(step) + rest
            lines = chunk.split(b"\n")
            rest = lines.pop(0) if pos > 0 else b""   # first piece may be partial
            for raw in reversed(lines):
                al = parse_alert(raw.decode("utf-8", "replace"))
                if al:
                    yield al
            scanned += step
        if pos > 0 and state is not None:
            state["truncated"] = True
            return
        if rest:
            al = parse_alert(rest.decode("utf-8", "replace"))
            if al:
                yield al


def tail_alerts(path, last, want=None, skipped=None, since=None, **kw):
    """The newest `last` alerts in `path`, oldest first.

    want: optional predicate; alerts it rejects are not collected (and do not
    use up the `last` slots), only counted in skipped["n"] if a dict is given.
    This keeps a flood of ignored decoder alerts from pushing real evidence
    out of the window.
    since: optional datetime; reading stops at the first older alert."""
    found = []
    for al in iter_back(path, **kw):
        if since is not None:
            t = alert_time(al.get("ts"))
            if t is not None and t < since:
                break
        if want is not None and not want(al):
            if skipped is not None:
                skipped["n"] = skipped.get("n", 0) + 1
            continue
        found.append(al)
        if len(found) >= last:
            break
    found.reverse()
    return found


_SNORT_TS = re.compile(r"^(\d\d)/(\d\d)-(\d\d):(\d\d):(\d\d)")


def alert_time(ts, now=None):
    """Local naive datetime of an alert timestamp, or None.

    Snort 3 writes "11/14-13:38:40.200636" (no year: the year that keeps the
    time from lying in the future is used); ML lines and Suricata use ISO 8601."""
    if not ts:
        return None
    now = now or _dt.datetime.now()
    m = _SNORT_TS.match(str(ts))
    if m:
        mo, d, h, mi, se = map(int, m.groups())
        try:
            t = _dt.datetime(now.year, mo, d, h, mi, se)
        except ValueError:
            return None
        if t > now + _dt.timedelta(days=1):          # e.g. a Dec 31 alert read on Jan 1
            t = t.replace(year=now.year - 1)
        return t
    try:
        t = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        try:                                         # Suricata "+0900" offsets
            t = _dt.datetime.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if t.tzinfo is not None:
        t = t.astimezone().replace(tzinfo=None)
    return t

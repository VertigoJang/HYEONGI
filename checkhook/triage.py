#!/usr/bin/env python3
"""LLM triage (read-only): the "Check" in CheckHook.

Looks at the IPs the detectors flagged (blocked, or would-be-blocked in
dry-run), compares them with this host's own network infrastructure (DNS
servers, default gateway, own addresses), and asks a local Ollama model which
of them are probably false positives. The report ends with a ready-to-paste
`skip:` line. It never changes the blocklist or the config: applying the
suggestion is left to a person.

  python3 -m checkhook.triage --alert-file /var/log/checkhook/snort/alert_json.txt
  python3 -m checkhook.triage --lang Korean --out report.md --skip 192.168.0.1
  python3 -m checkhook.triage --print-prompt
"""
import argparse, collections, datetime, json, os, re, time, urllib.request
from checkhook.alerts import Ignore, alert_time, iter_back, tail_alerts
from checkhook.policy import should_skip
from checkhook.netinfo import local_context



# ----------------------------------------------------------------- inputs ----
def recent_alerts(paths, last, ignore=None, skipped=None, since=None):
    """Newest `last` alerts per file, aggregated by signature, by source, and per source.

    Alerts the config ignores (decoder/protocol-anomaly gids, noisy rules) are
    left out of the window instead of using up its slots; their number goes to
    skipped["n"]. Before rc17 they were counted in, and a flood of them could
    push real evidence out of the newest-N window."""
    ignore = ignore or Ignore()
    if isinstance(paths, str):
        paths = [paths]
    alerts = []
    for path in paths:                       # IDS alerts, then ML detections (gid 9000)
        alerts += tail_alerts(path, last, want=lambda al: not ignore(al), skipped=skipped, since=since)
    sig = collections.Counter(); src = collections.Counter()
    per_src = collections.defaultdict(collections.Counter)
    for al in alerts:
        key = _key(al)
        sig[key] += 1
        if al["src"]:
            per_src[al["src"]][key] += 1
            src[al["src"]] += 1
    return len(alerts), sig, src, per_src


def _key(al):
    msg = al["msg"]
    if al.get("gid") == 9000:      # one ML line per flow: "p=.. -> dst:port" would make
        msg = ML_MSG               # every line its own signature and hide the pattern
    return (al.get("gid", 1), al["sid"], msg)


# Detections that decide a verdict on their own; always shown, never cut by top-N.
def is_key(gid, sid):
    sid = _int(sid)
    return gid == 122 or (gid == 1 and sid in (1100010, 1100011)) or gid == 9000


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return -1


def ip_summary(paths, ips, minutes=60, ignore=None, now=None, max_bytes=64 * 1024 * 1024):
    """Everything each flagged IP did in the last `minutes`, independent of the
    newest-N window: alert count, distinct destination ports, ML flows and
    their highest p, every signature, first and last time seen.

    Files are read backwards until the first alert older than the cutoff."""
    ignore = ignore or Ignore()
    now = now or datetime.datetime.now()
    cutoff = now - datetime.timedelta(minutes=minutes)
    ips = set(ips)
    out = {ip: {"alerts": 0, "counted": 0, "ports": set(), "ml": 0, "pmax": 0.0,
                "sigs": collections.Counter(), "first": None, "last": None,
                "partial_since": None} for ip in ips}
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        state, oldest = {}, None
        for al in iter_back(path, max_bytes=max_bytes, state=state):
            t = alert_time(al.get("ts"), now)
            if t is not None and t < cutoff:
                break
            if t is not None:
                oldest = t
            s = out.get(al["src"])
            if s is None:
                continue
            s["alerts"] += 1
            if not ignore(al):
                s["counted"] += 1
            if al.get("dport"):                       # None or 0 (e.g. port_scan) is not a port
                s["ports"].add(al["dport"])
            if al.get("gid") == 9000:
                s["ml"] += 1
                try:
                    s["pmax"] = max(s["pmax"], float(al.get("score") or 0))
                except (TypeError, ValueError):
                    pass
            s["sigs"][_key(al)] += 1
            if t is not None:
                s["first"] = t if s["first"] is None or t < s["first"] else s["first"]
                s["last"] = t if s["last"] is None or t > s["last"] else s["last"]
        if state.get("truncated") and oldest is not None:
            # the file was too large to read back to the cutoff: say so instead
            # of presenting a partial count as complete
            for s in out.values():
                if s["partial_since"] is None or oldest > s["partial_since"]:
                    s["partial_since"] = oldest
    return out


def _when(t, now=None):
    now = now or datetime.datetime.now()
    return f"{t:%H:%M:%S}" if t.date() == now.date() else f"{t:%m-%d %H:%M:%S}"


def _summary_line(ip, s, minutes, k=6):
    """One line of evidence for the prompt. Key detections (port scan, SYN
    flood, SSH brute force, ML) come first, then the most frequent others."""
    keys = [(sg, c) for sg, c in s["sigs"].most_common() if is_key(sg[0], sg[1])]
    rest = [(sg, c) for sg, c in s["sigs"].most_common() if not is_key(sg[0], sg[1])]
    shown = keys + rest[:max(0, k - len(keys))]
    parts = [f"gid={g} sid={sid} \"{m}\" x{c}" for (g, sid, m), c in shown]
    hidden = len(s["sigs"]) - len(shown)
    span = ""
    if s["first"] and s["last"]:
        span = f" between {_when(s['first'])} and {_when(s['last'])}"
    line = (f"- {ip}: in the last {minutes} min{span}: {s['alerts']} alerts "
            f"({s['counted']} can lead to a block); "
            f"distinct destination ports: {len(s['ports'])}")
    if s["ml"]:
        line += f"; ML flows: {s['ml']} (highest p {s['pmax']:.2f})"
    line += "; " + "; ".join(parts)
    if hidden > 0:
        line += f"; {hidden} more signature(s) with fewer alerts"
    if s.get("partial_since"):
        line += (f"; NOTE: alert files too large to read completely, counts cover only "
                 f"alerts since {_when(s['partial_since'])}")
    return line


ML_MSG = "CHECKHOOK-ML attack-like flow"


def blocked_ips(backend="nft"):
    """Read-only view of the current blocklist (nft set, XDP map or Windows rules)."""
    from checkhook.blocklist import Blocklist
    try:
        bl = Blocklist(backend=backend)
        return bl.ips() if bl.exists() else []
    except Exception:
        return []


# ----------------------------------------------------------------- analysis --
def flagged_ips(src, blocked, skip, block_private):
    """IPs a detector blocked or would block: blocked ones first, then every
    alerting source that the policy and the skip list would let through."""
    out = list(blocked)
    for ip, _ in src.most_common():
        if ip in out or ip in skip or should_skip(ip, block_private):
            continue
        out.append(ip)
    return out


def infra_hits(flagged, ctx):
    """Flagged IPs that are this host's own DNS server, gateway or address.
    These are false positives no matter what the model says."""
    role = {}
    for ip in ctx["dns"]:
        role.setdefault(ip, []).append("DNS server")
    for ip in ctx["gateway"]:
        role.setdefault(ip, []).append("default gateway")
    for ip in ctx["own"]:
        role.setdefault(ip, []).append("this host")
    return [(ip, role[ip]) for ip in flagged if ip in role]


def skip_line(skip, add):
    merged = list(skip) + [ip for ip in add if ip not in skip]
    return "skip: [" + ", ".join(merged) + "]"


# ----------------------------------------------------------------- prompt ----
LLM_LIMIT = 15          # flagged IPs sent to the model (most alerts first)
VERDICTS = ("false_positive", "attack", "unclear")
CONFIDENCE = ("high", "medium", "low")


def _sigs(counter, k=3):
    return "; ".join(f"gid={g} sid={s} \"{m}\" x{c}" for (g, s, m), c in counter.most_common(k))


def build_prompt(n, sig, src, per_src, flagged, blocked, enforce, ctx, lang,
                 summary=None, minutes=60, skipped=0):
    L = []
    L.append("You review alerts for a host firewall. Detectors flagged the source IPs below; "
             "you judge, for each of them, whether it is a false positive or a real attack. "
             "You cannot change anything; a person reads your answer.\n")
    L.append("Context about this host (these addresses are NOT under review):")
    L.append(f"- its own addresses (attacks on this host are aimed at these): {', '.join(ctx.get('own', [])) or 'unknown'}")
    L.append(f"- its DNS servers: {', '.join(ctx['dns']) or 'unknown'}")
    L.append(f"- its default gateway: {', '.join(ctx['gateway']) or 'unknown'}")
    L.append("Snort gid 1 and 3 are signature rules; other gids are built-in inspectors "
             "(packet decoder, stream, protocol anomalies, port_scan). Protocol anomalies on "
             "ordinary HTTPS/CDN/update traffic are usually not attacks; a port scan is. "
             "gid 9000 is CheckHook's own machine-learning flow classifier; p is its "
             "attack probability for one connection.")
    L.append("How to weigh the evidence: one source reaching many distinct destination ports "
             "in a short window is a port scan; thousands of SYN-flood hits from one source are a "
             "flood; many ML flows at p close to 1.00 support an attack. A private or lab address "
             "can be an attacker, so being private is not by itself a sign of a false positive. "
             "A handful of protocol-anomaly alerts with no such pattern points the other way.\n")
    L.append(f"Alerts of the last {minutes} min that can lead to a block (newest {n})"
             + (f" ({skipped} ignored decoder/anomaly alerts left out)" if skipped else "")
             + ". Most frequent:")
    for (g, s, m), c in sig.most_common(8):
        L.append(f"- gid={g} sid={s} \"{m}\": {c}")
    mode = "blocked" if enforce else "would be blocked (dry-run)"
    L.append(f"\nIPs to review ({mode}):")
    for ip in flagged[:LLM_LIMIT]:
        s = (summary or {}).get(ip)
        if s and s["alerts"]:
            L.append(_summary_line(ip, s, minutes))
        else:
            L.append(f"- {ip}: {src.get(ip, 0)} alerts; {_sigs(per_src[ip]) or 'no alert in window'}")
    L.append(f"""
Answer with JSON only, in this shape:
{{"situation": "<2-3 sentences in {lang}>",
 "verdicts": [{{"ip": "<one of the IPs to review>",
               "verdict": "false_positive" | "attack" | "unclear",
               "confidence": "high" | "medium" | "low",
               "reason": "<one short sentence in {lang}>"}}],
 "actions": ["<up to 3 short follow-ups in {lang}, e.g. a rule to tune>"]}}
Give exactly one verdict per IP to review and no other IPs. Use "unclear" when
the alerts do not say enough. Never claim to have changed anything.""")
    return "\n".join(L)


def parse_review(text, flagged):
    """Validate the model's JSON. Unknown IPs, bad verdicts and duplicates are
    dropped, so the report only ever states things about the reviewed IPs."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        m = re.search(r"\{.*\}", text or "", re.S)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except ValueError:
            return None
    if not isinstance(data, dict):
        return None
    allowed = set(flagged[:LLM_LIMIT]); verdicts = {}
    for v in data.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        ip = str(v.get("ip", "")).strip()
        if ip not in allowed or ip in verdicts or v.get("verdict") not in VERDICTS:
            continue
        conf = v.get("confidence") if v.get("confidence") in CONFIDENCE else "low"
        verdicts[ip] = {"verdict": v["verdict"], "confidence": conf,
                        "reason": str(v.get("reason", "")).strip()[:300]}
    actions = [str(x).strip()[:300] for x in (data.get("actions") or [])
               if isinstance(x, (str, int, float)) and str(x).strip()][:3]
    return {"situation": str(data.get("situation", "")).strip()[:800],
            "verdicts": verdicts, "actions": actions}


def ask_ollama(host, model, prompt, timeout):
    data = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "format": "json", "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get("response", "").strip()


# ----------------------------------------------------------------- report ----
TEXT = {
    "Korean": {
        "title": "# CheckHook 검토 보고서",
        "mode_on": "차단 켜짐", "mode_off": "기록만 함, enforce: false",
        "summary": "경보 {n}건, 차단 대상 IP {f}개 ({mode})",
        "infra": "## 1. 이 컴퓨터의 네트워크 장비와 겹치는 IP",
        "infra_note": "아래 IP는 이 컴퓨터가 지금 쓰는 DNS 서버, 게이트웨이, 자기 주소이므로 오탐입니다. "
                      "`protect_local: true`(기본값)이면 차단되지 않습니다. 이 설정을 껐다면 예외 목록에 넣습니다.",
        "infra_none": "차단 대상 중 이 컴퓨터의 DNS 서버, 게이트웨이, 자기 주소는 없습니다.",
        "llm": "## 2. LLM 판단 ({model})",
        "llm_fail": "LLM에 연결하지 못해 이 부분은 비어 있습니다: {e}",
        "llm_bad": "LLM 답변을 해석하지 못했습니다. 원문:",
        "llm_none": "검토할 IP가 없습니다.",
        "more": "경보가 많은 순서로 {k}개만 LLM에 보냈습니다. 나머지 {r}개는 판단하지 않았습니다.",
        "head": "| IP | 판단 | 확신 | 경보 | 근거 |",
        "verdict": {"false_positive": "오탐", "attack": "공격", "unclear": "불분명"},
        "conf": {"high": "높음", "medium": "보통", "low": "낮음"},
        "nov": "(판단 없음)",
        "actions": "권장 조치 (LLM 제안):",
        "skip": "## 3. 예외 목록 제안",
        "skip_sure": "확실한 것만 (이 컴퓨터의 네트워크 장비):",
        "skip_llm": "LLM이 확신 '높음'으로 오탐이라고 본 IP까지 포함:",
        "skip_none": "제안할 예외가 없습니다.",
        "apply": "적용은 사람이 합니다. 설정 파일의 `skip:` 줄을 바꾼 뒤 `sudo systemctl restart checkhookd`를 실행합니다.",
        "roles": {"DNS server": "DNS 서버", "default gateway": "게이트웨이", "this host": "이 컴퓨터"},
    },
    "English": {
        "title": "# CheckHook triage report",
        "mode_on": "enforcing", "mode_off": "log only, enforce: false",
        "summary": "{n} alerts, {f} flagged IPs ({mode})",
        "infra": "## 1. Flagged IPs that are this host's own network infrastructure",
        "infra_note": "These are this host's current DNS servers, gateway or own addresses, so false "
                      "positives. With `protect_local: true` (default) they are never blocked.",
        "infra_none": "No flagged IP is this host's DNS server, gateway or own address.",
        "llm": "## 2. LLM review ({model})",
        "llm_fail": "Could not reach the LLM, so this part is empty: {e}",
        "llm_bad": "Could not parse the LLM answer. Raw text:",
        "llm_none": "No IP to review.",
        "more": "Only the {k} IPs with the most alerts were sent to the LLM; {r} were not reviewed.",
        "head": "| IP | verdict | confidence | alerts | reason |",
        "verdict": {"false_positive": "false positive", "attack": "attack", "unclear": "unclear"},
        "conf": {"high": "high", "medium": "medium", "low": "low"},
        "nov": "(no verdict)",
        "actions": "Suggested actions (from the LLM):",
        "skip": "## 3. Suggested skip list",
        "skip_sure": "Certain only (this host's network infrastructure):",
        "skip_llm": "Also with the IPs the LLM called false positives with high confidence:",
        "skip_none": "Nothing to suggest.",
        "apply": "A person applies it: change the `skip:` line in the config, then restart checkhookd.",
        "roles": {},
    },
}


def render(t, model, n, flagged, review_ips, src, enforce, hits, skip, review, llm_raw, llm_err):
    mode = t["mode_on"] if enforce else t["mode_off"]
    L = [t["title"], "", t["summary"].format(n=n, f=len(flagged), mode=mode), ""]
    L.append(t["infra"])
    if hits:
        L.append(t["infra_note"]); L.append("")
        for ip, roles in hits:
            L.append(f"- {ip}: {', '.join(t['roles'].get(r, r) for r in roles)}")
    else:
        L.append(t["infra_none"])
    L.append(""); L.append(t["llm"].format(model=model))
    llm_fp = []
    if not review_ips:
        L.append(t["llm_none"])
    elif llm_err:
        L.append(t["llm_fail"].format(e=llm_err))
    elif review is None:
        L.append(t["llm_bad"]); L.append(""); L.append("```"); L.append((llm_raw or "")[:2000]); L.append("```")
    else:
        if review["situation"]:
            L.append(review["situation"]); L.append("")
        L.append(t["head"]); L.append("|---|---|---|---|---|")
        for ip in review_ips[:LLM_LIMIT]:
            v = review["verdicts"].get(ip)
            if v:
                if v["verdict"] == "false_positive" and v["confidence"] == "high":
                    llm_fp.append(ip)
                reason = v["reason"].replace("|", "/").replace("\n", " ")
                L.append(f"| {ip} | {t['verdict'][v['verdict']]} | {t['conf'][v['confidence']]} "
                         f"| {src.get(ip, 0)} | {reason} |")
            else:
                L.append(f"| {ip} | {t['nov']} | | {src.get(ip, 0)} | |")
        if len(review_ips) > LLM_LIMIT:
            L.append(""); L.append(t["more"].format(k=LLM_LIMIT, r=len(review_ips) - LLM_LIMIT))
        if review["actions"]:
            L.append(""); L.append(t["actions"])
            L += [f"- {x}" for x in review["actions"]]
    L.append(""); L.append(t["skip"])
    sure = [ip for ip, _ in hits]
    if sure or llm_fp:
        if sure:
            L.append(t["skip_sure"]); L.append("```yaml"); L.append(skip_line(skip, sure)); L.append("```")
        if llm_fp:
            L.append(t["skip_llm"]); L.append("```yaml"); L.append(skip_line(skip, sure + llm_fp)); L.append("```")
        L.append(t["apply"])
    else:
        L.append(t["skip_none"])
    return "\n".join(L) + "\n"


def settle(paths, ignore, quiet=20, max_wait=90, log=print, sleep=time.sleep, now=time.time):
    """Wait while detectors are still writing alerts that can lead to a block.

    The ML detector judges a connection only after it ended (idle timeout), so
    right after an attack its verdicts are still arriving; a review started then
    sees only part of them. Waits until the newest such alert is `quiet`
    seconds old, at most `max_wait` seconds. Returns the seconds waited."""
    waited = 0
    while waited < max_wait:
        newest = None
        for p in paths:
            try:
                if now() - os.path.getmtime(p) > quiet:
                    continue                     # file untouched lately: nothing new
            except OSError:
                continue
            for al in tail_alerts(p, 1, want=lambda al: not ignore(al), max_bytes=4 * 1024 * 1024):
                t = alert_time(al.get("ts"))
                if t is not None:
                    age = (datetime.datetime.now() - t).total_seconds()
                    newest = age if newest is None else min(newest, age)
        if newest is None or newest >= quiet:
            return waited
        if waited == 0:
            log(f"[*] detectors are still reporting (newest alert {newest:.0f}s old); "
                f"waiting up to {max_wait}s so the review sees all of it")
        sleep(5); waited += 5
    return waited


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-file", action="append", default=None,
                    help="alert file (repeatable: IDS alerts, ML detections)")
    ap.add_argument("--last", type=int, default=500,
                    help="newest N alerts per file that can lead to a block")
    ap.add_argument("--summary-minutes", type=int, default=60,
                    help="per-IP evidence covers this many minutes, independent of --last")
    ap.add_argument("--settle", type=int, default=20,
                    help="wait until the newest alert is this many seconds old (0 = do not wait)")
    ap.add_argument("--max-wait", type=int, default=90, help="upper bound for --settle")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--lang", default="English")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default=None, help="write report to file (else stdout)")
    ap.add_argument("--print-prompt", action="store_true", help="just print the prompt and exit")
    ap.add_argument("--backend", choices=["nft", "xdp", "winfw"], default="nft",
                    help="which blocklist to read (read-only)")
    ap.add_argument("--skip", default="", help="comma-separated never-block IPs (config skip:)")
    ap.add_argument("--block-private", action="store_true")
    ap.add_argument("--enforce", action="store_true", help="enforcement is on (else dry-run)")
    ap.add_argument("--ignore-gids", default="",
                    help="comma-separated Snort gids that never lead to a block (config ids.ignore_gids)")
    ap.add_argument("--ignore-rules", default="",
                    help='comma-separated "gid:sid" rules that never lead to a block (config ids.ignore_rules)')
    a = ap.parse_args(argv)

    skip = [s.strip() for s in a.skip.split(",") if s.strip()]
    ignore = Ignore([g for g in a.ignore_gids.split(",") if g.strip()],
                    [r for r in a.ignore_rules.split(",") if r.strip()])
    files = a.alert_file or ["/var/log/checkhook/snort/alert_json.txt"]
    if a.settle > 0 and not a.print_prompt:
        settle(files, ignore, a.settle, a.max_wait)
    skipped = {}
    since = datetime.datetime.now() - datetime.timedelta(minutes=a.summary_minutes)
    n, sig, src, per_src = recent_alerts(files, a.last, ignore, skipped, since)
    blocked = blocked_ips(a.backend)
    flagged = flagged_ips(src, blocked, skip, a.block_private)
    ctx = local_context()
    hits = infra_hits(flagged, ctx)
    infra = {ip for ip, _ in hits}
    review_ips = [ip for ip in flagged if ip not in infra]   # infra is decided without the LLM
    summary = ip_summary(files, review_ips[:LLM_LIMIT], a.summary_minutes, ignore)
    prompt = build_prompt(n, sig, src, per_src, review_ips, blocked, a.enforce, ctx, a.lang,
                          summary, a.summary_minutes, skipped.get("n", 0))
    if a.print_prompt:
        print(prompt); return 0
    print(f"[*] triage: {n} alerts, {len(flagged)} flagged IPs, "
          f"{len(hits)} on local infrastructure -> {a.model}")
    llm_raw, llm_err, review = "", "", None
    if review_ips:
        try:
            llm_raw = ask_ollama(a.host, a.model, prompt, a.timeout)
            review = parse_review(llm_raw, review_ips)
        except Exception as e:  # Ollama down, model missing, timeout...
            llm_err = f"{a.host}: {e} (check: curl {a.host}/api/tags)"
            print(f"[!] Ollama request failed: {llm_err}")
    t = TEXT.get(a.lang, TEXT["English"])
    counts = collections.Counter(src)
    for ip, sm in summary.items():           # the report shows the full count, not the window's
        counts[ip] = max(counts[ip], sm["counted"])
    out = render(t, a.model, n, flagged, review_ips, counts, a.enforce, hits, skip, review, llm_raw, llm_err)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] wrote {a.out}")
    else:
        print("\n" + out)
    return 1 if llm_err else 0


if __name__ == "__main__":
    raise SystemExit(main())

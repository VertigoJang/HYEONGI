"""Score LLM models on the triage task with cases whose answer is known.

    python3 -m hyeongi.triage_eval --models qwen2.5:1.5b,qwen2.5:3b,qwen2.5:7b --repeat 3

Every case is a flagged IP built from patterns seen on real hosts, with the
verdict a person gave it after checking (whois, logs, the lab): lab attackers
are attacks; CDN servers matched by payload rules, package mirrors, a QUIC
server, P2P peers answering ICMP port unreachable and a DNS server are false
positives. The prompt is built by the same code as a real review
(hyeongi.triage.build_prompt), several IPs per prompt, so the model sees
what it would see in practice.

Scores: correct verdicts, attacks caught, false positives recognised,
"unclear" answers, missing or invalid answers, JSON failures, and how often
repeated runs of the same prompt disagree. "unclear" counts as not correct:
for a person reading the report it does not decide anything.

Read-only: talks to Ollama only. Results go to stdout and, with --out, JSON.
"""
import argparse, collections, datetime, json, statistics, sys

from hyeongi.triage import (ML_MSG, ask_ollama, build_prompt, parse_review,
                              review_only_ips)
from hyeongi.alerts import PAYLOAD_PREFIXES, REVIEW_RULES

NOW = datetime.datetime(2026, 11, 17, 12, 0, 0)
CTX = {"own": ["192.168.35.166"], "dns": ["210.220.163.82", "219.250.36.130"],
       "gateway": ["192.168.35.1"]}

S = lambda g, sid, msg: (g, sid, msg)
SYN = S(1, 1100010, "HYEONGI possible SYN flood")
SSH = S(1, 1100011, "HYEONGI possible SSH brute force")
TEL = S(1, 1100001, "HYEONGI inbound telnet attempt")
SMB = S(1, 1100002, "HYEONGI inbound SMB attempt")
TSCAN = S(122, 1, "(port_scan) TCP portscan")
TFSCAN = S(122, 5, "(port_scan) TCP filtered portscan")
ML = S(9000, 1, ML_MSG)

# ip -> (truth, what a person found, signatures {sig: count}, ports, ml, pmax, minutes span)
CASES = {
    # attacks ------------------------------------------------------------------
    "10.199.0.2": ("attack", "lab attacker (netns): nmap -sS and hping3 SYN flood",
                   {SYN: 3, TSCAN: 1, TEL: 1, SMB: 1, ML: 118}, 997, 118, 1.00, 6),
    "172.28.128.10": ("attack", "lab VM: hydra against ssh",
                      {SSH: 5, ML: 40}, 1, 40, 0.97, 4),
    "91.240.118.7": ("attack", "internet scanner: TCP scan with telnet probe, no reply traffic",
                     {TSCAN: 2, TEL: 1, S(1, 1100003, "HYEONGI inbound RDP attempt"): 1}, 312, 0, 0.0, 3),
    "10.199.0.3": ("attack", "lab attacker against a host that answers RST: ML just under threshold",
                   {TFSCAN: 1, ML: 30}, 1000, 30, 0.81, 2),
    # false positives ----------------------------------------------------------
    "13.225.134.105": ("false_positive", "AWS CloudFront, TLS on 443 matched a payload rule",
                       {S(1, 649, "INDICATOR-SHELLCODE x86 setgid 0"): 1}, 1, 0, 0.0, 0),
    "185.125.190.82": ("false_positive", "Canonical package mirror, HTTP download during a container build",
                       {S(1, 1390, "INDICATOR-SHELLCODE x86 inc ebx NOOP"): 1}, 1, 0, 0.0, 0),
    "160.79.104.10": ("false_positive", "api.anthropic.com, QUIC on UDP 443",
                      {S(122, 21, "(port_scan) UDP filtered portscan"): 1}, 0, 0, 0.0, 0),
    "153.117.48.253": ("false_positive", "P2P peer answering this host's UDP with ICMP port unreachable",
                       {S(122, 17, "(port_scan) UDP portscan"): 1,
                        S(1, 402, "PROTOCOL-ICMP destination unreachable port unreachable"): 67}, 0, 0, 0.0, 14),
    "151.101.192.223": ("false_positive", "Fastly CDN answering HTTP 403 Forbidden",
                        {S(1, 1201, "INDICATOR-COMPROMISE 403 Forbidden"): 1}, 1, 0, 0.0, 0),
    "168.126.63.1": ("false_positive", "KT public DNS server (other Wi-Fi), DNS answers with short TTL",
                     {S(1, 254, "PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority"): 40},
                     1, 0, 0.0, 30),
}

# several IPs per prompt, attacks mixed with false positives
SCENARIOS = [
    ["10.199.0.2", "13.225.134.105", "185.125.190.82", "168.126.63.1"],
    ["172.28.128.10", "160.79.104.10", "153.117.48.253", "151.101.192.223"],
    ["91.240.118.7", "10.199.0.3", "13.225.134.105", "160.79.104.10"],
]

IGNORED = {(1, 402)}                 # in the default ignore list: does not count toward a block


def _summary(ip):
    truth, _, sigs, ports, ml, pmax, span = CASES[ip]
    sigs = collections.Counter(sigs)
    alerts = sum(sigs.values())
    counted = sum(c for (g, sid, _), c in sigs.items() if (g, sid) not in IGNORED)
    last = NOW - datetime.timedelta(minutes=2)
    return {"alerts": alerts, "counted": counted, "ports": set(range(ports)), "ml": ml,
            "pmax": pmax, "sigs": sigs, "first": last - datetime.timedelta(minutes=span),
            "last": last, "partial_since": None}


def prompt_for(ips, lang="English"):
    summary = {ip: _summary(ip) for ip in ips}
    sig = collections.Counter(); src = collections.Counter()
    per_src = {}
    for ip, s in summary.items():
        sig.update(s["sigs"]); src[ip] = s["alerts"]; per_src[ip] = s["sigs"]
    ro = review_only_ips(per_src, set(), PAYLOAD_PREFIXES, REVIEW_RULES)
    return build_prompt(sum(src.values()), sig, src, per_src, list(ips), [], False, CTX, lang,
                        summary, 60, 0, ro)


def run(models, repeat, host, timeout, num_ctx, log=print):
    results = {}
    for m in models:
        rows = []
        for si, ips in enumerate(SCENARIOS):
            p = prompt_for(ips)
            for r in range(repeat):
                st = {}
                try:
                    raw = ask_ollama(host, m, p, timeout, num_ctx, "5m", 1, st)
                    rev = parse_review(raw, ips)
                    err = None if rev is not None else "invalid JSON"
                except Exception as e:                 # Ollama down, timeout ...
                    raw, rev, err = "", None, str(e)
                for ip in ips:
                    v = (rev or {}).get("verdicts", {}).get(ip) if rev else None
                    rows.append({"scenario": si, "run": r, "ip": ip, "truth": CASES[ip][0],
                                 "verdict": v["verdict"] if v else None,
                                 "confidence": v["confidence"] if v else None,
                                 "error": err, "wall": st.get("wall"), "gpu": st.get("gpu")})
                log(f"  {m:24} scenario {si + 1} run {r + 1}: "
                    + (err or f"{st.get('wall', 0):.0f}s, GPU {100 * (st.get('gpu') or 0):.0f}%"))
        results[m] = rows
    return results


def score(rows):
    n = len(rows)
    ok = sum(1 for x in rows if x["verdict"] == x["truth"])
    att = [x for x in rows if x["truth"] == "attack"]
    fp = [x for x in rows if x["truth"] == "false_positive"]
    by_case = collections.defaultdict(set)
    for x in rows:
        by_case[(x["scenario"], x["ip"])].add(x["verdict"])
    walls = sorted({(x["scenario"], x["run"]): x["wall"] for x in rows if x["wall"]}.values())
    return {
        "correct": ok / n if n else 0,
        "attacks_caught": sum(x["verdict"] == "attack" for x in att) / len(att) if att else 0,
        "attacks_called_fp": sum(x["verdict"] == "false_positive" for x in att),
        "fp_recognised": sum(x["verdict"] == "false_positive" for x in fp) / len(fp) if fp else 0,
        "unclear": sum(x["verdict"] == "unclear" for x in rows) / n if n else 0,
        "missing": sum(x["verdict"] is None for x in rows),
        "json_fail": len({(x["scenario"], x["run"]) for x in rows if x["error"]}),
        "unstable_cases": sum(1 for v in by_case.values() if len(v) > 1),
        "median_s": statistics.median(walls) if walls else None,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--models", required=True, help="comma-separated Ollama model names")
    ap.add_argument("--repeat", type=int, default=3, help="runs per scenario (checks stability)")
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--num-ctx", type=int, default=4096)
    ap.add_argument("--out", help="write every verdict as JSON")
    ap.add_argument("--print-prompt", type=int, metavar="N", help="print scenario N's prompt and exit")
    a = ap.parse_args(argv)
    if a.print_prompt:
        print(prompt_for(SCENARIOS[a.print_prompt - 1])); return 0
    models = [m.strip() for m in a.models.split(",") if m.strip()]
    print(f"[*] {len(SCENARIOS)} scenarios x {a.repeat} runs, {len(CASES)} cases "
          f"({sum(c[0] == 'attack' for c in CASES.values())} attacks)")
    res = run(models, a.repeat, a.host, a.timeout, a.num_ctx)
    print(f"\n{'model':24} {'correct':>7} {'attacks':>7} {'att->FP':>7} {'FP ok':>6} "
          f"{'unclear':>7} {'miss':>4} {'JSONx':>5} {'unstable':>8} {'median s':>8}")
    for m, rows in res.items():
        s = score(rows)
        print(f"{m:24} {s['correct']:7.0%} {s['attacks_caught']:7.0%} {s['attacks_called_fp']:7d} "
              f"{s['fp_recognised']:6.0%} {s['unclear']:7.0%} {s['missing']:4d} {s['json_fail']:5d} "
              f"{s['unstable_cases']:8d} {s['median_s'] or 0:8.0f}")
    print("\nper case (verdicts over all runs):")
    for ip, c in CASES.items():
        line = f"  {ip:16} {c[0]:15}"
        for m, rows in res.items():
            vs = collections.Counter(x["verdict"] or "-" for x in rows if x["ip"] == ip)
            line += f" | {m.split(':')[-1]}: " + " ".join(f"{k[:6]}x{v}" for k, v in vs.most_common())
        print(line)
    if a.out:
        with open(a.out, "w") as f:
            json.dump({"cases": {ip: c[:2] for ip, c in CASES.items()}, "results": res}, f, indent=1)
        print(f"\n[+] wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

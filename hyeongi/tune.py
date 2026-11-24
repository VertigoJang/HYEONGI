#!/usr/bin/env python3
"""Pick the LLM review model and the flow-log budget from this machine's resources.

  hyeongi tune              show what this machine has and what HYEONGI would use
  sudo hyeongi tune --apply write the recommended values into the config, restart

Config values may also be the word `auto` (triage.model, triage.fallback_model,
triage.num_ctx, triage.timeout, capture.keep); they are resolved the same way each
time the config is loaded, so a config copied to another machine adapts to it.

What decides what
  memory      Ollama on an integrated GPU uses system RAM, and the model must fit
              next to everything else the laptop runs. 7B needs about 5 GB, 3B about
              2 GB, 1.5B about 1 GB (q4, num_ctx 4096).
                >= 14 GB  qwen2.5:7b,   fallback qwen2.5:3b     (a 16 GB machine)
                >=  7 GB  qwen2.5:3b,   fallback qwen2.5:1.5b   (8 GB)
                 <  7 GB  qwen2.5:1.5b, no fallback, num_ctx 2048
              triage_eval on the 16 GB test laptop: 7B caught every attack; 3B and
              1.5B called obvious lab attacks false positives. Below 14 GB the review
              is therefore weaker, and the report says so through the model name.
  GPU         the last report records the GPU share of the review. If it ran mostly
              on the CPU (< 50 %), one tier lower and a longer timeout.
  disk        flow logs: 10 % of the free space where they are kept, between 0.5 and
              4 GB, at about 20 MB per 50 000-row file.
"""
import argparse, json, os, re, shutil, sys, urllib.request

TIERS = [  # (min RAM GB, model, fallback, num_ctx)
    (14, "qwen2.5:7b", "qwen2.5:3b", 4096),
    (7, "qwen2.5:3b", "qwen2.5:1.5b", 4096),
    (0, "qwen2.5:1.5b", "", 2048),
]
AUTO_KEYS = {"triage": ("model", "fallback_model", "num_ctx", "timeout"), "capture": ("keep",)}
FILE_MB = 20                                 # ~ one 50 000-row flow CSV


# ------------------------------------------------------------------ probes ---
def ram_gb():
    """Total physical memory in GB (None if unknown)."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1024 / 1024
    except OSError:
        pass
    if os.name == "nt":
        import ctypes

        class MS(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong),
                        ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                        ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                        ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                        ("ext", ctypes.c_ulonglong)]
        m = MS(); m.l = ctypes.sizeof(MS)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            return m.total / 1024 ** 3
    return None


def last_gpu_share(report_path):
    """GPU share (0..1) recorded by the last LLM review, or None."""
    try:
        with open(report_path, encoding="utf-8") as f:
            text = f.read(20000)
    except OSError:
        return None
    m = re.search(r"GPU (\d+)%", text)
    return int(m.group(1)) / 100 if m else None


def free_gb(path):
    p = os.path.abspath(path)
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    try:
        return shutil.disk_usage(p or "/").free / 1024 ** 3
    except OSError:
        return None


def installed_models(host, timeout=3):
    """Model names Ollama has, or None if it does not answer."""
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=timeout) as r:
            return {m.get("name") for m in json.loads(r.read()).get("models", [])}
    except Exception:
        return None


# --------------------------------------------------------- recommendation ---
def recommend(ram, gpu_share, free, cpu_only_hint=False):
    """{'triage': {...}, 'capture': {...}, 'why': [...]} for these resources."""
    why = []
    if ram is None:
        idx = 0
        why.append("memory unknown: assuming a 16 GB machine")
    else:
        idx = next(i for i, (gb, *_r) in enumerate(TIERS) if ram >= gb)
        why.append(f"{ram:.1f} GB RAM -> {TIERS[idx][1]}")
    timeout = 300
    if gpu_share is not None and gpu_share < 0.5:
        idx = min(idx + 1, len(TIERS) - 1)
        timeout = 600
        why.append(f"last review ran {gpu_share:.0%} on the GPU (mostly CPU) -> one tier lower, "
                   "timeout 600 s")
    elif gpu_share is not None:
        why.append(f"last review ran {gpu_share:.0%} on the GPU")
    _, model, fallback, ctx = TIERS[idx]
    if free is None:
        keep = 100
        why.append("free disk unknown: keeping 100 flow files (~2 GB)")
    else:
        budget = min(max(free * 0.10, 0.5), 4.0)
        keep = max(10, int(budget * 1024 / FILE_MB))
        why.append(f"{free:.0f} GB free for flow logs -> {keep} files (~{keep * FILE_MB / 1024:.1f} GB)")
    return {"triage": {"model": model, "fallback_model": fallback, "num_ctx": ctx,
                       "timeout": timeout},
            "capture": {"keep": keep}, "why": why}


def probe(c):
    return recommend(ram_gb(), last_gpu_share(c["triage"]["out"]), free_gb(c["capture"]["dir"]))


def resolve_auto(c, rec=None):
    """Replace 'auto' values in a loaded config with the recommendation (in place)."""
    pending = [(s, k) for s, keys in AUTO_KEYS.items() for k in keys
               if str((c.get(s) or {}).get(k, "")).strip().lower() == "auto"]
    if not pending:
        return c
    rec = rec or probe(c)
    for s, k in pending:
        c[s][k] = rec[s][k]
    return c


# ------------------------------------------------------------ config write ---
def set_key(text, section, key, value):
    """Set `  key: value` inside top-level `section:`, keeping a trailing comment."""
    m = re.search(rf"^{section}:[^\n]*\n((?:[ \t#][^\n]*\n|\n)*)", text, re.M)
    if not m:
        return text.rstrip("\n") + f"\n{section}:\n  {key}: {value}\n"
    body = m.group(1)
    pat = re.compile(rf"^  {key}:[^\n#]*(#[^\n]*)?$", re.M)
    hit = pat.search(body)
    if hit:
        comment = hit.group(1) or ""
        line = f"  {key}: {value}"
        if comment:
            line = line.ljust(26) + comment
        body = body[:hit.start()] + line + body[hit.end():]
    else:
        body = f"  {key}: {value}\n" + body
    return text[:m.start(1)] + body + text[m.end(1):]


def main(argv=None):
    ap = argparse.ArgumentParser(description="fit HYEONGI's LLM review and flow logs to this machine")
    ap.add_argument("--apply", action="store_true", help="write the values into the config and restart")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    from hyeongi import config
    path = a.config or config.DEFAULT_PATH
    c = config.load(path)
    ram, gpu, free = ram_gb(), last_gpu_share(c["triage"]["out"]), free_gb(c["capture"]["dir"])
    rec = recommend(ram, gpu, free)
    print("this machine:")
    print(f"  RAM          : {ram:.1f} GB" if ram else "  RAM          : unknown")
    print(f"  CPU threads  : {os.cpu_count()}")
    print(f"  last review  : " + (f"GPU {gpu:.0%}" if gpu is not None else "no report yet"))
    print(f"  free disk    : " + (f"{free:.0f} GB at {c['capture']['dir']}" if free is not None else "unknown"))
    for w in rec["why"]:
        print(f"  -> {w}")
    with open(path, encoding="utf-8-sig") as f:
        raw = __import__("yaml").safe_load(f) or {}
    print("\n  setting                 now            recommended")
    changes = []
    for s in ("triage", "capture"):
        for k, v in rec[s].items():
            cur = (raw.get(s) or {}).get(k, c[s].get(k))
            mark = "" if str(cur) == str(v) or str(cur).lower() == "auto" else "  <-"
            if mark:
                changes.append((s, k, v))
            print(f"  {s + '.' + k:<22}  {str(cur):<13}  {v!s:<13}{mark}")
    have = installed_models(c["triage"]["host"])
    need = [m for m in (rec["triage"]["model"], rec["triage"]["fallback_model"]) if m]
    if have is None:
        print(f"\n  Ollama at {c['triage']['host']} did not answer; models not checked")
    else:
        missing = [m for m in need if m not in have]
        for m in missing:
            print(f"\n  [!] model {m} is not installed: ollama pull {m}")
    if not changes:
        print("\n[=] the config already fits this machine")
        return 0
    if not a.apply:
        print("\n  apply with: sudo hyeongi tune --apply   (or set these keys to auto)")
        return 0
    if os.name != "nt" and os.geteuid() != 0:
        sys.exit("[x] --apply needs root")
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    for s, k, v in changes:
        text = set_key(text, s, k, f'"{v}"' if isinstance(v, str) else v)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    print(f"[+] wrote {len(changes)} value(s) to {path}")
    from hyeongi.ctl import restart
    restart()
    print("[+] hyeongid restarted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Turn PCAP(s) or agent flow CSVs into a labelled nfstream flow dataset.

A flow is labelled attack (1) if its source OR destination IP is in the given
attacker set (exact IPs and/or CIDRs); otherwise benign (0). This works for
self-generated lab captures (you know the attacker IP) and for CIC-IDS2017
PCAPs (use the documented attacker IPs; note external attacks are NAT'd and
appear as 172.16.0.1 in victim-side captures).

  python3 -m ml.make_dataset --pcap attack.pcap --pcap benign.pcap \
      --attacker-ip 203.0.113.66 --out flows.csv
  python  -m ml.make_dataset --flows "C:/ProgramData/HYEONGI/flows/*.csv" --label 0 --out benign.csv

Networks: flow logs since 3.0.0rc34 carry a `net` column (the name given with
`hyeongi name-here`, else gw-xxxxxxxx, else unknown); older rows and PCAPs
get "unknown" unless --set-net names them. The output keeps the column, so
you can train on some networks and evaluate on others:

  python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --net home --out home.csv
  python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --exclude-net home --out other.csv
  python3 -m ml.make_dataset --pcap lab.pcap --attacker-ip 10.199.0.2 --set-net lab --out lab.csv

Direction: flow logs since 3.0.0rc37 carry `dir` ("in" = another host started
the flow, "out" = this host did). For older logs and PCAPs it is inferred per
file: this host's addresses are the ones present in most flows. The live
detectors only act on inbound flows, so build benign training/evaluation data
from those:

  python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --dir in --out benign-in.csv

Part: flow logs since 3.0.0rc46 carry `part`: "start" (the connection starts in
this record), "cont" (a later piece of a connection seen before) or "mid" (a
piece of a connection nobody saw start). The live detector only judges "start"
records, and before rc46 `dir` came from the source of each record, so in
older logs the later pieces of this host's own connections are marked "in".
Older rows and PCAPs have an empty `part`.

  python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --dir in --part start --out benign-in.csv
"""
import argparse, ipaddress
import numpy as np
import pandas as pd
from hyeongi.features import FEATURES

def matcher(ips, nets):
    ipset = set(ips); nets = [ipaddress.ip_network(n) for n in nets]
    def m(s):
        try: ip = ipaddress.ip_address(s)
        except ValueError: return False
        return s in ipset or any(ip in n for n in nets)
    return m

def own_addresses(df, min_share=0.5, min_rows=0.05):
    """This host's addresses in a host capture: the address present in most
    flows, then the most present in the flows left, and so on while one covers
    at least `min_share` of what is left (a laptop has one IPv4 address per
    network it was on, plus its IPv6 addresses)."""
    own, rest, n = set(), df[["src_ip", "dst_ip"]].astype(str), len(df)
    while len(rest) >= max(1, min_rows * n):
        counts = pd.concat([rest.src_ip, rest.dst_ip]).value_counts()
        if counts.empty or counts.iloc[0] < min_share * len(rest):
            break
        ip = counts.index[0]
        own.add(ip)
        rest = rest[(rest.src_ip != ip) & (rest.dst_ip != ip)]
    return own


def infer_dir(df):
    own = own_addresses(df)
    src, dst = df["src_ip"].astype(str), df["dst_ip"].astype(str)
    return pd.Series(np.where(src.isin(own), "out", np.where(dst.isin(own), "in", "")),
                     index=df.index), own


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", action="append", default=[], help="PCAP file (repeatable)")
    ap.add_argument("--flows", action="append", default=[],
                    help="flow CSV written by the agent's flow logging (repeatable; globs ok)")
    ap.add_argument("--attacker-ip", nargs="*", default=[])
    ap.add_argument("--attacker-net", nargs="*", default=[])
    ap.add_argument("--label", type=int, choices=[0, 1], default=None,
                    help="force this label on all flows (else label by attacker IP)")
    ap.add_argument("--net", action="append", default=[],
                    help="keep only flows from this network tag (repeatable)")
    ap.add_argument("--exclude-net", action="append", default=[],
                    help="drop flows from this network tag (repeatable)")
    ap.add_argument("--set-net", default=None,
                    help="tag for rows that have none (PCAPs, flow logs before rc34)")
    ap.add_argument("--rename-net", action="append", default=[], metavar="OLD=NEW",
                    help="read network tag OLD as NEW (e.g. gw-9824f64c=school, rows logged "
                         "before the network was named); the logs are not changed")
    ap.add_argument("--dir", choices=["in", "out"], default=None,
                    help="keep only flows started by another host (in) or by this host (out)")
    ap.add_argument("--part", action="append", choices=["start", "cont", "mid"], default=[],
                    help="keep only these parts of a connection (repeatable; flow logs since rc46)")
    ap.add_argument("--out", default="flows.csv")
    a = ap.parse_args()
    renames = {}
    for r in a.rename_net:
        old, sep, new = r.partition("=")
        if not sep or not old or not new:
            ap.error(f"--rename-net wants OLD=NEW, got {r!r}")
        renames[old] = new
    import glob
    flow_files = [f for pat in a.flows for f in sorted(glob.glob(pat))]
    if not a.pcap and not flow_files:
        ap.error("give at least one --pcap or --flows file")
    att = matcher(a.attacker_ip, a.attacker_net)
    parts = []
    sources = [("pcap", p) for p in a.pcap] + [("flows", f) for f in flow_files]
    for kind, pc in sources:
        if kind == "pcap":
            from nfstream import NFStreamer   # only needed for PCAP input
            df = NFStreamer(source=pc, statistical_analysis=True).to_pandas()
        else:
            df = pd.read_csv(pc)
        if a.label is not None:
            lbl = pd.Series(a.label, index=df.index)
        else:
            lbl = (df["src_ip"].apply(att) | df["dst_ip"].apply(att)).astype(int)
        net = df["net"].fillna("").astype(str) if "net" in df.columns else pd.Series("", index=df.index)
        net = net.where(net != "", a.set_net or "unknown").replace(renames)
        d = df["dir"].fillna("").astype(str) if "dir" in df.columns else pd.Series("", index=df.index)
        part = df["part"].fillna("").astype(str) if "part" in df.columns else pd.Series("", index=df.index)
        inferred = ""
        if (d == "").all():
            d, own = infer_dir(df)
            inferred = f", direction inferred (this host: {', '.join(sorted(own)) or 'not found'})"
        extra = [c for c in ("dst_port", "protocol") if c in df.columns]   # for ml.fp_report
        df = df[FEATURES + ["src_ip", "dst_ip"] + extra].copy(); df["label"] = lbl; df["net"] = net
        df["dir"] = d
        df["part"] = part
        n0 = len(df)
        if a.net:
            df = df[df["net"].isin(a.net)]
        if a.exclude_net:
            df = df[~df["net"].isin(a.exclude_net)]
        if a.dir:
            df = df[df["dir"] == a.dir]
        if a.part:
            df = df[df["part"].isin(a.part)]
        parts.append(df)
        kept = "" if len(df) == n0 else f" (kept {len(df)} of {n0} by network/direction/part)"
        print(f"[+] {pc}: {len(df)} flows, attack={int(df['label'].sum())}{kept}{inferred}")
    out = pd.concat(parts, ignore_index=True)
    out.to_csv(a.out, index=False)
    print(f"[+] wrote {a.out}: {len(out)} flows, attack={int(out['label'].sum())}, benign={int((out['label']==0).sum())}")
    if len(out):
        print("    by network: " + ", ".join(
            f"{k}={v}" for k, v in out["net"].value_counts().items()))
        print("    by direction: " + ", ".join(
            f"{k or 'unknown'}={v}" for k, v in out["dir"].value_counts().items()))
        print("    by part: " + ", ".join(
            f"{k or 'not recorded'}={v}" for k, v in out["part"].value_counts().items()))

if __name__ == "__main__":
    main()

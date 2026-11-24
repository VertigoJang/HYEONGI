#!/usr/bin/env python3
"""Which benign traffic does the model over-flag? (false-positive anatomy)

  python3 -m ml.fp_report --model model.joblib --data benign-eval.csv [--data attack-eval.csv] \
      [--threshold 0.90] [--top 15]

Run it on HELD-OUT benign flows (not the ones the model was trained on). It
prints, at the operating threshold:
  1. false positives by service (protocol / destination port) and by network
     (`net` column, rc34+), so you see whether a few kinds of traffic cause most
     of the FPR;
  2. the size of flows: packets, bytes and duration for true negatives, false
     positives and (if attack flows are given) true positives. If false
     positives look like the attacks (few packets, few bytes, short) and unlike
     the other benign flows, the model has learned "small flow = attack";
  3. the features the forest relies on most.
Datasets made before rc35 have no dst_port/protocol columns; part 1 then shows
networks only. With a `dir` column (rc37) it also splits false positives into
inbound (a detector could block the source) and outbound (this host's own
connections, never blocked).
"""
import argparse
import numpy as np
import pandas as pd
import joblib
from checkhook.features import FEATURES

PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
SIZE = [("bidirectional_packets", "packets"), ("bidirectional_bytes", "bytes"),
        ("bidirectional_duration_ms", "duration ms")]


def attack_proba(clf, X):
    classes = list(clf.classes_)
    return clf.predict_proba(X)[:, classes.index(1)] if 1 in classes else clf.predict(X).astype(float)


def service(row):
    p = PROTO.get(int(row["protocol"]), str(int(row["protocol"])))
    return f"{p}/{int(row['dst_port'])}" if p in ("TCP", "UDP") else p


def table(title, counts, total_fp, total, top):
    print(f"\n{title}")
    print(f"  {'':<22} {'FP':>7} {'of all FP':>9} {'flows':>8} {'FP rate':>8}")
    for key, (fp, n) in sorted(counts.items(), key=lambda kv: -kv[1][0])[:top]:
        if fp == 0:
            continue
        print(f"  {str(key)[:22]:<22} {fp:>7} {fp / total_fp:>9.1%} {n:>8} {fp / n:>8.1%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", action="append", required=True)
    ap.add_argument("--threshold", type=float, default=0.90)
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()
    d = joblib.load(a.model)
    clf, feats = d["clf"], d.get("features", FEATURES)
    df = pd.concat([pd.read_csv(f) for f in a.data], ignore_index=True)
    y = df["label"].astype(int).values
    p = attack_proba(clf, df[feats].fillna(0.0).values)
    flag = p >= a.threshold
    ben, atk = y == 0, y == 1
    fp, tn, tp = flag & ben, ~flag & ben, flag & atk
    nb, nfp = int(ben.sum()), int(fp.sum())
    print(f"[i] threshold {a.threshold:.2f}: benign {nb}, false positives {nfp} "
          f"({nfp / nb:.2%})" if nb else "[!] no benign flows given")
    # flows this host started are never acted on: judge on the others
    act = (df["dir"].fillna("").astype(str) != "out").values if "dir" in df.columns \
        else np.ones(len(df), bool)
    if not act.all():
        nba, nfpa = int((ben & act).sum()), int((fp & act).sum())
        print(f"    of which a detector could act on (not started by this host): benign {nba}, "
              f"false positives {nfpa}" + (f" ({nfpa / nba:.2%})" if nba else ""))
        if nba and nfpa == 0:
            print(f"    0 of {nba}: with this many flows the true rate is below about "
                  f"{3 / nba:.2%} (95 %, rule of three)")
    if atk.any():
        print(f"    attacks {int(atk.sum())}, caught {int(tp.sum())} ({tp.sum() / atk.sum():.2%})")
    if not nfp:
        return

    b = df[ben]
    if {"dst_port", "protocol"} <= set(df.columns):
        svc = b.apply(service, axis=1)
        counts = {k: (int(fp[ben][svc.values == k].sum()), int((svc.values == k).sum()))
                  for k in svc.unique()}
        table("1a. false positives by service (protocol/destination port)", counts, nfp, nb, a.top)
    else:
        print("\n1a. (no dst_port/protocol columns: rebuild the dataset with ml.make_dataset from rc35)")
    if "net" in df.columns:
        nets = b["net"].fillna("unknown").astype(str).values
        counts = {k: (int(fp[ben][nets == k].sum()), int((nets == k).sum())) for k in set(nets)}
        table("1b. false positives by network", counts, nfp, nb, a.top)
    if "dir" in df.columns:
        dirs = b["dir"].fillna("").astype(str).replace("", "unknown").values
        counts = {k: (int(fp[ben][dirs == k].sum()), int((dirs == k).sum())) for k in set(dirs)}
        table("1c. false positives by direction (only 'in' can lead to a block)", counts, nfp, nb, a.top)

    print("\n2. flow size (median, and 90th percentile)")
    groups = [("benign, not flagged (TN)", tn & act), ("benign, flagged (FP)", fp & act)]
    if not act.all() and (fp & ~act).any():
        groups.append(("FP started by this host", fp & ~act))
    if atk.any():
        groups.append(("attack, flagged (TP)", tp))
    print(f"  {'':<26}" + "".join(f"{lbl:>22}" for _, lbl in SIZE))
    for name, m in groups:
        cells = []
        for col, _ in SIZE:
            v = df.loc[m, col] if col in df.columns else pd.Series(dtype=float)
            cells.append(f"{v.median():>10.0f} / {v.quantile(0.9):>8.0f}" if len(v) else f"{'-':>21}")
        print(f"  {name:<26}" + "".join(f"{c:>22}" for c in cells))
    if atk.any() and "bidirectional_packets" in df.columns:
        small = lambda m: float((df.loc[m, "bidirectional_packets"] <= 3).mean()) if m.any() else 0.0
        fpa, tna = fp & act, tn & act
        print(f"\n  share of flows with <= 3 packets:  TN {small(tna):.1%}   FP {small(fpa):.1%}   "
              f"TP {small(tp):.1%}" + ("" if act.all() else "   (TN/FP: flows not started by this host)"))
        if not fpa.any() and not act.all():
            print("  -> every false positive was started by this host: none of them could lead to a block.")
        elif small(fpa) > 0.8 and small(tp) > 0.8 and small(tna) < 0.5:
            print("  -> false positives are small flows like the attacks, unlike most benign flows:\n"
                  "     the model is using flow size as the attack signal. More kinds of attack\n"
                  "     (not only scans and floods) and more small benign flows in training are the fix.")

    imp = getattr(clf, "feature_importances_", None)
    if imp is not None:
        top = sorted(zip(feats, imp), key=lambda x: -x[1])[:10]
        print("\n3. features the model relies on most")
        for f, w in top:
            print(f"  {f:<34} {w:.3f}")


if __name__ == "__main__":
    main()

# ml — dataset preparation and training

The ML detector uses nfstream statistical flow features (see `hyeongi/features.py`,
57 features). Training and live inference use the **same** feature extraction,
so there is no feature-space mismatch.

## 1. Build a labelled dataset (nfstream + labels)

A flow is labelled attack if its source or destination IP is in the attacker
set. This works two ways:

**Self-generated data (recommended first — labels are exact).** Capture a
benign PCAP and an attack PCAP, then label each whole capture with `--label`:

```bash
python3 -m ml.make_dataset --pcap benign.pcap --label 0 --out benign.csv
python3 -m ml.make_dataset --pcap attack.pcap --label 1 --out attack.csv
```

(If attack and benign come from distinct IPs in one PCAP, label by attacker IP
instead: `--attacker-ip 10.200.0.5`.)

**CIC-IDS2017 (optional, broader coverage):** download the PCAPs and label by
the documented attacker IPs. Note: external attacks are NAT'd through the
firewall and appear in victim-side captures as `172.16.0.1`.
Attackers: Kali `205.174.165.73`, Win `205.174.165.69/70/71`; NAT `172.16.0.1`.

```bash
python3 -m ml.make_dataset --pcap monday.pcap --pcap wednesday.pcap \
    --attacker-ip 205.174.165.73 172.16.0.1 --out flows.csv
```

**Split by network.** Flow logs since 3.0.0rc34 carry a `net` column (the name
given with `sudo hyeongi name-here home`, else a salted `gw-xxxxxxxx`, else
`unknown`). Keep or drop networks, and tag rows that have none (PCAPs, older
logs) with `--set-net`:

```bash
python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --net home --out home.csv
python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/*.csv" --label 0 --exclude-net home --out other.csv
python3 -m ml.eval --model model.joblib --data other.csv --data attack.csv --by-net
```

`--by-net` prints FPR and TPR per network at `--threshold` (default 0.90), so
over-flagging that comes from one network shows up as such.

**Direction matters.** The detectors only act on flows another host started.
Build benign data from those (`--dir in`), and split by time rather than by
random flows (flows of one session are near-identical):

```bash
python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/flows-202611[01]*.csv" --label 0 --dir in --out benign-train.csv
python3 -m ml.make_dataset --flows "/var/lib/hyeongi/flows/flows-2026112*.csv"   --label 0 --out benign-eval.csv
python3 -m ml.eval --model model.joblib --data benign-eval.csv --by-dir
```

**Where do false positives come from?** On held-out benign flows (and,
optionally, attack flows):

```bash
python3 -m ml.fp_report --model model.joblib --data benign-eval.csv --data attack-eval.csv
```

It lists false positives by service and network, compares flow sizes of benign
flows the model passed, benign flows it flagged and attacks, and says when the
model is using "small flow" as the attack signal.

## 2. Train

```bash
python3 -m ml.train --data benign.csv --data attack.csv --out model.joblib
```

## 3. Detect live (feeds the shared blocklist)

```bash
sudo python3 -m hyeongi.ml_detector -i eth0 --model model.joblib --dry-run
sudo python3 -m hyeongi.ml_detector -i eth0 --model model.joblib --backend nft --threshold 0.9
```

Requirements: `pip install nfstream scikit-learn joblib` (nfstream needs
libpcap). Live capture needs root.

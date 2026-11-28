# Changelog

## 3.0.0 (in testing)

**A pause or practice mode undone by something else**
- rc47: three cases.
  - `practice end` resumed collection even when it had been paused before the practice
    began (`hyeongi pause`, then `practice start`): the earlier pause was gone and the
    capture unit ran again. It now resumes only a pause the practice made itself (the
    pause file says "practice: ..."). An earlier pause stays, and the result says so;
    `practice start` reports it and records it as `paused_before`. A practice started
    by an older version is handled the same way.
  - `hyeongi start` listed all four services as started even when hyeongi-capture had
    been skipped because collection is paused. It now lists the units that are active
    and names the others, with the cause when it is known.
  - The installers enabled and started their unit during practice mode, which turns
    start at boot off on purpose: `install-xdp.sh` would attach the XDP program,
    `install-snort.sh` would start Snort. Every installer now ends with
    `enable_and_restart` (packaging/lib/common.sh), which only installs the unit while
    practice mode is on; `install-snort.sh` and `use-suricata.sh` leave hyeongid alone
    then.
- Tests: 11 more (60).

**Who started the connection**
- rc46: a flow record now says which part of a connection it is, and `dir` in the flow
  logs comes from whoever started the connection. nfstream cuts a connection into
  several records (after 15 s without a packet, and every 120 s); each names as its
  source whoever sent the first packet of that record. So the later pieces of a
  download this host started were logged as flows "in" from the server, and classified
  as such. Found by counting a laptop's logs: of 1,967 inbound TCP rows, 1,962 had no
  SYN, and all 1,967 went to an ephemeral port of this host, where nothing listens.
  - `hyeongi.flowpart.Origins` remembers who started each connection (TCP: the side
    that sent a SYN without ACK; other protocols: the first record) for an hour (TCP)
    or five minutes, at most 50,000 connections.
  - The flow logs gain `part`: "start", "cont" (a later piece; the starter is
    remembered) or "mid" (a TCP piece of a connection nobody saw start: `dir` is empty).
  - The ML detector classifies only "start" records. Later pieces and "mid" records
    are logged, not judged: the source of such a record is not who started it.
  - `ml.make_dataset` keeps `part` and has `--part`. Logs written before rc46 are not
    changed: their `dir` is wrong for later pieces, and their `part` is empty.
  - The model in use was trained on those logs. Its benign "inbound" examples were
    pieces of this host's own connections, so it should be trained again on logs
    written since rc46; until then its scores for real inbound connections are untested.
- rc46: flow logs are deleted for the disk they take, not for how many there are. A new
  file starts with every daemon start, so a daemon restarted often reached the limit of
  100 files with 1,800 rows a file and began deleting the oldest. Now the oldest files
  go only when all of them together take more than `capture.keep` full files would
  (`keep` x `rows_per_file` x 400 bytes; 2 GB with the defaults).
- Tests: 14 more (49), for the rules above and the disk limit.

**Tests**
- rc45: the first automated tests (`tests/`, run with `python3 -m pytest -q tests`): 35
  cases for the rc43 fixes - the XDP attachment check, the retry after a failed block,
  `hyeongi net`, `practice end` and `demo on`. They need no root, network or bpftool;
  every outside command is replaced by a fake. Whether packets are really dropped is
  still checked by hand (docs/testing.md).

**Screenshots**
- rc44: the README shows the terminal menu and the desktop app under the new name
  (`docs/figures/terminal-menu.png`, new `docs/figures/app-status.png`). One Korean
  particle after the name in the README is fixed.

**Reported blocks are real blocks**
- rc43: fixes for cases where HYEONGI said more than it did.
  - XDP: the pinned program and maps outlive the attachment (an interface that is removed
    and created again loses it), and `xdp load` answered "already loaded" without looking.
    A map update then succeeded and was logged as `[BLOCK]` while nothing was dropped.
    Now `load` attaches again when the attachment is missing. Every block first checks,
    by program id, that the program is on the interface it was loaded for (`bpftool net
    show`, at most every 30 s) and attaches it again if not; if that fails, the block is
    logged as `[would-block] (block failed: ...)`. hyeongid repeats the check every
    `expiry_interval` for the entries already in the map and logs when blocked IPs are
    not being dropped. `hyeongi xdp` has a `loaded for` line, and `practice end` checks
    the attachment, not only the pins. When bpftool's answer cannot be read, nothing
    changes compared with before. `/run/hyeongi-xdp.iface` now holds "iface mode".
  - The interfaces are still the ones in the config. `hyeongi net` names the watched one
    and warns when the default route is on another (traffic there is not inspected);
    hyeongid warns at start when `ml.iface` and `xdp.iface` differ. Following the default
    route is not in this version.
  - A block that failed was remembered as handled for the whole `block_timeout`, so that
    source was not tried again for an hour. It is tried again after 60 s (IDS bridge and
    ML detector).
  - `hyeongi net` showed "ENFORCE (trusted)" on a trusted network even with
    `enforce: false`. It shows what really happens: ENFORCE, or OBSERVE-ONLY with the
    reason.
  - `hyeongi pause` did not survive a reboot for the packet capture: the unit was stopped
    but still enabled, and benign-*.pcap files were written during a pause on the test
    laptop. The capture unit now has an ExecCondition on the pause flag and does not
    start while it exists. Installed units: run `install-capture.sh` again.
  - `practice end` left hyeongi-capture stopped when everything had been stopped before
    `practice start`. It runs again if it ran before or starts at boot.
  - `demo on` refuses during practice mode (hyeongid only waits then, so Snort would run
    with nothing reading its alerts).
  - The menu said "Enforcement is never automatic", which is not what `enforce: true`
    does. It says: blocking is off until `enforce: true`; once on, detectors block
    without asking.
  - Docs: the repository is `VertigoJang/HYEONGI`.
  - Tested with fake commands and made-up bpftool answers (single and multi-attachment
    form) only; not yet run on a machine with the program attached.

**Name**
- rc42: the project is called HYEONGI: Host-based, Your-network-gated Enforcement with
  On-device Network Guard & Inspection.
  - Every name follows it: the launcher `hyeongi`, the daemon `hyeongid`, the Python
    package, the units `hyeongi-ids`, `hyeongi-xdp` and `hyeongi-capture`, the nftables
    tables `ip hyeongi` and `ip6 hyeongi`, the XDP pin directory and its maps, the paths
    `/etc/hyeongi`, `/var/lib/hyeongi`, `/var/log/hyeongi` and `/usr/local/lib/hyeongi`,
    the `HYEONGI_*` environment variables, the Windows folder, tasks and firewall group,
    and the lab names of `lab-netns.sh` (`hy-host`, `hy-atk`, `hyatk`, `hylab`).
  - An install made under the earlier name is not migrated: uninstall it with that
    version's scripts and install again. Keep `net-salt` next to the flow logs when
    moving data, or every `gw-` network tag changes.
  - New logo (the shield with an H) and banner. Nothing else changes in behaviour.

**Inspection: the LLM review now does what the name says**
- rc41: the app and `hyeongi stats` show whether the services run now, not what the
  last status file said.
  - Found on the test laptop: after "전체 중단" (or `hyeongi stop`) the app kept showing
    every service as running, and the power button stayed "전체 중단", so the app could
    stop HYEONGI but not start it again. hyeongid writes status.json itself; once it
    stops, the file keeps its last "active" states.
  - Linux: the app and `hyeongi stats` ask systemd directly (`systemctl is-active`, no
    root needed). Windows: the file is used while it is fresh; once it is older than a
    minute the states are shown as unknown instead of repeated.
  - While hyeongid is stopped the app says so ("전체 중단됨") and marks the numbers as
    the last values from before the stop.
- rc40: practice mode survives reboots, and DNS-spoof alerts no longer block on their own.
  - Found during the first real use: the laptop rebooted twice during a 6-hour exercise
    and the services, enabled at boot, came back (13:11-15:43 and 16:03-16:04): detection
    and XDP ran for 2.5 hours although practice mode meant "everything off". Training
    data stayed clean only because the pause flag is a file.
  - `practice start` now also turns start-at-boot off for the units that had it (and
    remembers which); `practice end` turns it back on, restarts hyeongi-xdp (oneshot:
    attach again) and checks that start-at-boot was restored. hyeongid started by
    hand during practice mode waits until it ends; `hyeongi start` refuses.
  - `1:254` (PROTOCOL-DNS SPOOF, TTL of 1 min) joins the default `ids.review_rules`:
    logged and reviewed, never a block on its own. The source of a spoofed DNS answer
    is the resolver it imitates, so blocking it cuts off DNS rather than the attacker;
    the one IDS would-block of the first day of the live model was 8.8.8.8 for this rule.
    Installed configs keep their own list: add "1:254" there.
  - `ml.make_dataset --rename-net OLD=NEW` reads a network tag under another name (rows
    logged before the network was named); the logs are not changed.
- rc39: practice mode, for attack practice from this host (the procedure first done by hand
  for a Metasploitable2 web-attack exercise).
  - `sudo hyeongi practice start [--target IP ...] [memo]`: remembers whether
    hyeongi-capture was running, pauses collection (window in pauses.log), stops
    hyeongid, hyeongi-ids, hyeongi-xdp (program detached) and hyeongi-capture,
    checks that they and the XDP pins are gone, and records the time and the newest
    flow log.
  - `sudo hyeongi practice end`: starts the services again, resumes collection,
    leaves hyeongi-capture as it was, and checks: services up, XDP attached
    (backend xdp), the newest flow log from before unchanged, no flow log written
    during the practice, no flow row with a target address. Result in practice.log;
    exit code 1 when a check fails.
  - `sudo hyeongi practice scrub IP` removes rows with that address from the flow
    logs (not the one hyeongid is writing).
  - The app has a "실습 모드 시작 / 종료" button next to "전체 중단": it asks for a memo
    and optional target IPs, shows the check results at the end, and while practice
    mode is on it says so (instead of "hyeongid may have stopped") and disables the
    power button. The practice state is read from its own file, so the app shows it
    even when the status file is stale or missing.
- rc38: the last two would-block entries in the test laptop's whole history are explained
  and fixed, and the evaluation tools judge only flows a detector acts on.
  - `1:451` (PROTOCOL-ICMP Timestamp Reply) joins the default `ids.ignore_rules`, next to
    1:408 (Echo Reply). Both would-blocks (11-16 23:39, 11-17 11:24) were this host's own
    server answering the ICMP timestamp probe that nmap sends during host discovery,
    while this host scanned that server. A timestamp *request* arriving (recon of this
    host) still counts. Installed configs keep their own list: add "1:451" there.
  - `ml.eval`: with a `dir` column, the FPR table and the threshold recommendation use
    only flows not started by this host, and it says how many outbound benign flows it
    left out; `--by-dir` still shows all directions. Before, this host's own scans in
    the benign set made it report that no threshold could reach 1 %.
  - `ml.fp_report`: the headline adds the false-positive rate on flows a detector could
    act on, with a rule-of-three bound when it is 0; the flow-size comparison and the
    "small flow = attack" verdict use those flows, and outbound false positives are
    listed apart. When every false positive was started by this host it says so
    instead of diagnosing a bias.
- rc37: flow direction. The flow logs gain `dir`: "in" when another host started the
  flow, "out" when this host did (netinfo.Direction, from this host's own addresses).
  Found while tracing the 9.74% false-positive rate of the model-v3 experiment: 3,983 of
  its 3,985 false positives were this host's own nmap scans (top 1,000 ports, four
  runs) of its own server, labelled benign because the whole flow log was taken as
  benign. An unanswered outbound SYN is feature-identical to a scan probe against a
  silent host, so the model flagged it, and a model trained on such rows as benign
  misses those probes. The live detectors never act on flows this host started (the
  source is a local address), so those rows were neither real false positives nor
  useful benign examples.
  - `ml.make_dataset --dir in|out` keeps one direction; older logs and PCAPs get the
    direction inferred per file (this host's addresses are the ones present in most
    flows, found greedily: one IPv4 address per network plus IPv6 addresses), and the
    addresses it settled on are printed. Output counts flows per direction.
  - `ml.eval --by-dir` and `ml.fp_report` (part 1c) split false positives into inbound
    (could lead to a block) and outbound (never blocked).
  - Training and evaluation data for the detector should be inbound benign flows plus
    attacks: `--label 0 --dir in`. Evaluate by time (older log files for training,
    newer for evaluation); a random split of flows put 42.5 % of evaluation rows
    verbatim into training on the test laptop.
- rc36: fit to the machine, and see where false positives come from.
  - `hyeongi tune` shows RAM, CPU threads, the GPU share of the last review and the
    free disk, and the LLM model / fallback / num_ctx / timeout and flow-log size that
    fit them; `sudo hyeongi tune --apply` writes them (comments kept) and restarts.
    Tiers by RAM (Ollama on an integrated GPU shares system memory): >= 14 GB
    qwen2.5:7b + 3b, >= 7 GB qwen2.5:3b + 1.5b, below that qwen2.5:1.5b with num_ctx
    2048; one tier lower and a 600 s timeout when the last review ran mostly on the
    CPU. Flow logs get 10 % of the free disk, 0.5–4 GB. Missing models are named with
    the `ollama pull` command. The same keys may be set to `auto` and are then resolved
    each time the config is loaded.
  - `python3 -m ml.fp_report --model M --data held-out.csv [--data attack.csv]`: false
    positives at the operating threshold by service (protocol/port) and by network,
    flow size (packets, bytes, duration) of true negatives vs false positives vs true
    positives, the share of flows with <= 3 packets in each, and the features the
    forest relies on. It says so when false positives are small flows like the attacks
    and unlike other benign flows (the "small flow = attack" bias seen in the v3
    experiments).
  - `ml.make_dataset` keeps `dst_port` and `protocol` for that report.
- rc35: two problems found by attacking HYEONGI from the netns lab (IPv4 and IPv6).
  - Fixed (from rc33): an IPv6 attacker on the same /64 as this host was never flagged.
    rc33 counted every address in this host's on-link IPv6 networks as local, to cover
    temporary addresses; in the lab (fd99:199::/64 on both ends) Snort raised 6 alerts
    for fd99:199::2 and the bridge skipped them all, while 10.199.0.2 was flagged. Now
    an address in an on-link /64 that is not in the cached set triggers an immediate
    re-read of this host's addresses (at most every 2 s): a new temporary address of
    this host is still local, a neighbour is not. Neighbours are treated like RFC1918
    neighbours: not blocked by default, blocked with `block_private` (demo mode).
    `hyeongi ctl block` may block such a neighbour (a person's decision).
  - The LLM review answered a Korean report with Chinese reasons (qwen2.5:7b). The
    prompt now states the language in that language as well, and an answer that still
    contains Chinese characters is asked again once; the report says when that
    happened, or that the reasons are still partly Chinese.
- rc34: every logged flow says which network it came from. The flow logs gain a `net`
  column, so training data from home, a campus Wi-Fi or a cafe can be told apart,
  filtered and evaluated separately (FPR found in the v3 experiments may come from one
  network rather than the model everywhere).
  - The tag is the name given with `sudo hyeongi name-here <name>` (e.g. home,
    school), stored per default-gateway MAC in `networks.names`; `unname-here` drops
    it. An unnamed network gets `gw-` + 8 hex of a salted hash of the gateway MAC;
    no gateway (offline) or no MAC (Windows) gives `unknown`. The salt is random per
    host (`/var/lib/hyeongi/net-salt`) and never written to the flow logs: a bare
    hash of a MAC is reversible in seconds (the first half is a vendor prefix), a
    salted one is not, so a shared CSV says "same network as that row", not which.
  - The tag is re-read every 30 s and set when a flow ends; hyeongid logs each
    change ("flow logging: network tag ..."). `hyeongi net` shows the tag here.
  - `ml.make_dataset` keeps the column and adds `--net` / `--exclude-net` (keep or
    drop networks) and `--set-net` (tag rows that have none: PCAPs, logs before
    rc34, which become `unknown` otherwise); it prints the flow count per network.
  - `ml.eval --by-net [--threshold 0.90]` adds FPR and TPR per network.
  - Editing `networks:` (trust-here, name-here) now rewrites both keys together;
    before, trust-here wrote only `trusted_gateways`.
  - Earlier flow logs cannot be tagged after the fact: they mix networks and carry
    no gateway information.
- rc33: IPv6 sources are blocked. Before, every detector skipped IPv6 sources on
  purpose (the blocklist was IPv4-only), so an attacker reaching this host over IPv6 was
  detected but never blocked.
  - XDP: a second pinned map `hyeongi_block6` (16-byte source address, same expiry
    value) next to `hyeongi_block`; the program checks IPv6 packets against it.
    Loaded and run through the kernel verifier and `BPF_PROG_TEST_RUN` on 6.18:
    listed v6 source dropped, other v6 passed, expired entry passed and deleted,
    truncated v6 header passed, IPv4 unchanged. A program attached before rc33 has no
    IPv6 map: `hyeongi xdp` says so, IPv6 blocks fail with a log line instead of
    stopping the detector, and `sudo systemctl restart hyeongi-xdp` attaches the
    new one (`hyeongi.xdp load` over an old program reloads it and keeps the IPv4
    entries).
  - nftables: a second isolated table `ip6 hyeongi` (same set/chain/priority -150).
    Detectors create it when it is missing, without touching the IPv4 table, so an
    upgrade keeps active IPv4 blocks. `ips()` reads both sets through `nft -j`.
  - Windows firewall rules accept IPv6 addresses too (not yet tested on Windows).
  - Never blocked, as with IPv4: loopback, link-local (fe80::/10), multicast,
    unspecified, IPv4-mapped (::ffff:0:0/96), site-local; unique-local fc00::/7 is
    treated like RFC1918 (blocked only with `block_private`).
  - Local infrastructure (`protect_local`) now includes this host's IPv6 addresses
    and IPv6 DNS servers, and any address inside this host's on-link IPv6 networks
    (/64): IPv6 hosts make new temporary addresses on their own (RFC 8981), so an
    exact-address list would lag behind by up to a minute. Other hosts in the same
    /64 are therefore not blocked either, as RFC1918 neighbours are not by default.
  - Addresses are compared in canonical form (Snort, Suricata, nfstream, `skip:`
    and `hyeongi ctl block` may spell the same IPv6 address differently).
  - `hyeongi ctl block/unblock/skip-add` accept IPv6. The LLM review is told the
    on-link IPv6 networks.
  - Limit: an IPv6 entry is one address (/128). An attacker that rotates addresses
    inside its own /64 needs one entry per address; prefix blocking is not done yet.
  - `lab-netns.sh up` also gives the lab IPv6 addresses (fd99:199::1 host side,
    ::2 attacker) when the host has IPv6, and `mode drop|reject` now applies to
    both families (table `inet hylab`, `reject with icmpx`; same ICMP answer for
    IPv4 as before). The self-test adds and removes 2001:db8::250 as well.
- rc32: `lab-netns.sh mode rst|drop|reject` sets how the victim (hy-host) answers an
  attack, in an isolated nft table `ip hylab` that only matches traffic arriving on
  hy-host. rst = host default (closed TCP->RST, closed UDP->ICMP unreachable, like Kali);
  drop = silent (firewalld/Windows); reject = ICMP admin-prohibited (a REJECT firewall).
  Snort sniffs the link before netfilter, so it still sees every attack packet — only the
  answer changes. This is the environment switch for collecting ML training data across
  response modes (model v3), all inside the isolated netns, independent of the real
  network. `down` and `mode rst` clear the table; `status` shows the current mode.
- rc31: `hyeongi net` (read-only) no longer needs root; only the commands that
  change state (trust-here, untrust-here, block, enforce, ...) still do.
- rc30: per-network enforcement. HYEONGI now decides whether to actually block
  by the current network's default-gateway MAC. `hyeongi ctl trust-here` adds the
  network you are on (home) to `networks.trusted_gateways`; from then on every other
  network (school, cafe) is observe-only -- detection and the report run as usual, but
  nothing is added to the kernel blocklist, so an unfamiliar network's quirks or a
  stray practice packet can never cause a block you did not intend. Re-read every 30 s,
  so moving between networks switches mode on its own. Opt-in: an empty trusted list
  leaves blocking to `enforce:` everywhere (unchanged). Gated in both the IDS and ML
  block paths. `hyeongi net` shows the current network and whether it enforces;
  `hyeongi services` shows it too; `hyeongi ctl untrust-here` removes a network.
- rc29: a master on/off switch for the whole stack. `hyeongi start` / `hyeongi stop`
  (root) start or stop every service at once (hyeongid, ids, xdp, capture); the desktop
  app gets a "전체 가동 / 전체 중단" button next to the service list. Stopping halts
  detection and new blocks but leaves the kernel blocklist as it is — IPs already blocked
  stay blocked until block_timeout or `hyeongi flush` (option 1). `hyeongi ctl start|stop`
  is the privileged path the app calls through pkexec.
- rc28: the LLM verdict table marks IPs whose only block-capable alerts are review-only
  rules (UDP port scans, payload rules on plain ports) as "(차단 안 됨) / (not blocked)".
  The model can still call such an IP an attack -- in the eval all models wrongly called a
  P2P peer (one UDP port-scan alert + many ICMP-unreachable, i.e. this host's own outbound
  UDP) an attack -- but the rule layer does not block it, and now the person reading the
  report sees that, so a wrong LLM verdict cannot mislead them into unblocking a real one.
  The rc27 prompt wording that tried to teach the model this case is reverted: it had no
  effect (both 3b and 7b still called the peer an attack), confirming the fix belongs in the
  rule layer, not the prompt. The default review model stays qwen2.5:7b.
- rc27: the review falls back to a lighter model. If the main model (`triage.model`,
  default qwen2.5:7b) fails or runs mostly on the CPU (GPU share < 0.5 from /api/ps),
  the request is retried once on `triage.fallback_model` (default qwen2.5:3b); the
  report and log name the model that answered and why it fell back. On a 16 GB laptop
  the eval (triage_eval) ranked qwen2.5:7b clearly above 3b/1.5b: 7b caught every
  attack and never called one a false positive, while the small models called obvious
  lab attacks (SYN flood + port scan + ML p=1.00) false positives. So the default stays
  7b, with 3b only as a degraded fallback. The prompt now says a UDP port-scan alert
  paired with many ICMP-unreachable (1:402) from one source is this host's own outbound
  UDP, not a scan of it (all three models had wrongly called such a peer an attack).
  Every LLM section carries a one-line caveat: advisory only, blocking is decided by the
  rules and ML, and an LLM can invent its reasons.
- rc26: `python3 -m hyeongi.triage_eval --models a,b,c --repeat 3` scores models on
  the review with 10 cases whose answer is known (4 attacks from the lab and an
  internet scan, 6 false positives seen on the laptop: CDN payload matches, a package
  mirror, a QUIC server, a P2P peer, an HTTP 403, a DNS server), three prompts of four
  IPs built by the real prompt code. It reports correct verdicts, attacks caught,
  attacks called false positive, "unclear", invalid JSON, verdicts that change between
  runs, and time. Read-only; meant to pick the model per hardware class.
- rc25: the review is tuned for a GPU Ollama shared with another project on the laptop
  (one model loaded at a time, OLLAMA_MAX_LOADED_MODELS=1). Each request sends
  `keep_alive` (default 5m) and `num_ctx` (4096); the timeout is 300 s instead of 180
  (a request can queue behind another client's, then cold-load: one measured run took
  190 s); a refused connection or 5xx is retried once after 10 s. The report and the
  log record where and how fast the review ran: GPU share from `/api/ps`, load/prompt/
  generate seconds, tokens against the context, with a warning when part ran on the CPU
  or the prompt filled the context. New `triage:` keys `timeout`, `num_ctx`,
  `keep_alive`, `retries`; the default host is 127.0.0.1. `hyeongid.service` no longer
  orders after the system `ollama.service` (Ollama now runs as a user service).
- Reviews the IPs that were blocked, or with `enforce: false` would have been
  blocked; before, dry-run left nothing to review.
- Compares flagged IPs with this host's DNS servers, default gateway and own
  addresses (Linux and Windows) and marks those as false positives without
  waiting for the model.
- Gives the model each flagged IP with its top signatures plus the local
  network context, and asks for false positives and likely real attacks.
- rc17: the evidence per IP no longer depends on the newest-N window. For
  each flagged IP the review counts everything of the last
  `triage.summary_minutes` (default 60): all alerts, distinct destination
  ports, ML flows with the highest probability, first and last time seen.
  Key detections (port scan, SYN flood, SSH brute force, ML) are always
  listed; before, only the top three signatures were, and a single port-scan
  alert could be cut. Times from another day carry the date, and if an
  alert file is too large to read back to the start of the span, the prompt
  says from when the counts are complete instead of passing them off as whole.
- rc17: alerts the config ignores (decoder and protocol-anomaly gids, noisy
  rules) no longer use up the newest-N window; the prompt says how many were
  left out. The window is also limited to the same time span, so an old
  flood no longer shows up as recent.
- rc17: right after an attack the review waits until detectors stop
  reporting (`triage.settle`, default 20 s, at most 90 s). The ML detector
  judges a connection only after it ended, so a review started at once saw
  only part of its verdicts.
- rc18: the review also reads the rotated generations of an alert file
  (Snort renames a full alert_json to `<name>.<time>`), so a span that
  crosses a rotation is counted whole.

**IDS capture length**
- rc24: `1:1201` (a web server answering HTTP 403 Forbidden) joins `review_rules`. It
  made two CDN servers (Fastly and another) would-block IPs on the laptop: a refused
  request of this host, not an attack on it. Checked on Kali after rc20: Snort runs with
  `-s 65535`, and since that restart 116:6 / 116:275 / 137:2 are 0 while other rules
  (1:254, 129:15, port_scan, the lab rules) keep alerting.
- rc23: Snort UDP port-scan alerts (122:17, 18, 20, 21, 22, 24) are review-only
  (`ids.review_rules`), like payload rules on plain ports. Replaying a week of laptop
  alerts, all ten external would-block IPs were UDP port scans: nine were peers in
  ISP networks whose alerts were otherwise ICMP port unreachable (1:402), i.e. answers
  to this host's own UDP; one was a server on UDP 443 (QUIC). TCP port scans still block.
  The triage prompt explains both cases.
- rc22: payload signatures (`INDICATOR-SHELLCODE*`, `SHELLCODE*`) on plain ports are
  review-only: logged as `[review]`, counted on the status board and shown to the
  triage, but they never block by themselves. On the laptop all six would-block IPs of
  one day other than the lab attacker came from such rules on CDN and package servers
  (CloudFront, Fastly, Cloudflare, Google, Canonical port 80 during a container build).
  Other alerts from the same IP still block as before. The triage prompt marks such IPs
  "[review only]" and explains why plain-HTTP downloads match these rules.
  `ids.payload_block: true` restores the old behaviour.
- rc21: fewer false alarms that cannot be acted on.
  `1:396` and `1:449` (ICMP unreachable / TTL exceeded replies) join the default
  `ignore_rules`. Payload rules (`INDICATOR-SHELLCODE*`, `SHELLCODE*`) are ignored only
  when either port is a TLS port (`encrypted_ports`): there the matched bytes are
  ciphertext from a CDN, not shellcode. The same rule on port 80 still counts.
  Alerts are parsed with `sport` as well as `dport`. Alerts whose source is this host
  are dropped (as before, through the local-address set); devices that reach you on
  purpose, such as a tablet using VNC, belong in `skip`. The netns guide now says
  `nmap -n`.
- rc20: Snort runs with `-s 65535`. With GRO on (the default for most NICs and
  wifi drivers), the kernel hands Snort merged packets far larger than its
  default 1518-byte snaplen. Snort cut them and raised 116:6 "IPv4 datagram
  length > captured length" (70 % of all alerts on the laptop) and 137:2 TLS
  anomalies, and the cut-off payload was never inspected. Side by side on the
  same traffic for 3 minutes: 116:6 63 -> 0, 137:2 26 -> 0, while unrelated
  signatures matched (129:15 8/10, 1:254 8/8). Re-run `install-snort.sh` to
  regenerate the service.

**Lab**
- rc20: `packaging/lab-netns.sh up|down|status` builds an attacker without a VM:
  network namespace `hyatk` (10.199.0.2) joined to the host by a veth pair
  (`hy-host`, 10.199.0.1), no route anywhere else. `hyeongi demo on hy-host`
  watches it. veth supports native XDP, so generic and native can be compared
  on one machine.

**Status**
- rc19: manual blocks (app button or `hyeongi ctl block`) are counted. They
  are logged to `/var/lib/hyeongi/manual-blocks.log`; `hyeongi stats` and
  the app show today's blocks as automatic + manual. Before, a manual block
  left "blocked today: 0".
- rc19: the reason shown for a flagged IP is its strongest detection with
  counts (SYN flood, then port scan, SSH brute force, ML, then the most
  frequent), built from every alert of that IP, e.g.
  `HYEONGI possible SYN flood x3 · (port_scan) TCP filtered portscan x1 (+2종)`.
  Before, it was whichever alert happened to trigger the flag (often a telnet
  probe from the start of a port scan).
- rc19: `hyeongi stats` shows "차단 중" for a flagged IP that is in the
  kernel blocklist, as the app already did.

**Alert floods**
- rc18: `install-snort.sh` adds a Snort `event_filter` that reports the SYN
  flood (1100010) and SSH brute-force (1100011) rules at most once a minute
  per source. `detection_filter` alone fires on every packet past the
  threshold: one lab flood wrote about 290,000 alerts (190 MB). Detection,
  blocking and re-blocking after `block_timeout` need only one alert. If
  `snort -T` rejects the filter, the script falls back without it.
- rc18: hyeongid deletes rotated alert files beyond `ids.keep_rotated`
  (default 3, i.e. about 300 MB of Snort alerts) and keeps one rotated ML
  alert file.
- rc18 fix: re-running `install-snort.sh` rewrote every `alert_file:` line in
  the config, including `ml.alert_file`; it now changes only the `ids:` and
  `triage:` sections.
- The model now sees the evidence per IP: how many distinct destination
  ports it reached, how many ML flows it triggered and the highest ML
  probability. ML detections are counted as one signature instead of one per
  port, and the prompt names this host's own addresses (rc16: a clear port
  scan plus SYN flood from the lab VM had come back as "unclear").
- The report ends with a ready-to-paste `skip:` line. Still read-only: the
  blocklist and the config are only changed by a person.
- If Ollama is unreachable the report is still written (local part only) and
  the run exits non-zero.
- Reports in Korean when `triage.lang: Korean`.
- The model answers in JSON (one verdict per reviewed IP: false positive,
  attack or unclear, with confidence and reason). Verdicts about IPs that were
  not under review are dropped, so the report never states things about the
  gateway, the skip list or made-up addresses. The host's own DNS servers and
  gateway are decided without the model and are not sent for review.
- The skip suggestion comes in two lines: certain (local infrastructure) and
  with the IPs the model called false positives with high confidence.

**Detection**
- `ids.ignore_gids` (default 116 decoder, 119 http_inspect, 128 ssh,
  129 stream_tcp, 137 ssl) and `ids.ignore_rules` ("gid:sid"): alerts that
  never lead to a block. The triage still sees them. Alerts now carry their
  gid. On the RHEL test machine these inspectors produced most alerts and, with
  ssl alone, 505 distinct "attacker" IPs from ordinary HTTPS traffic.
- `protect_local` (default on): never block this host's current DNS servers,
  default gateway and own addresses; re-read every minute so it follows a
  laptop between networks. On the test machine the DNS-spoof rule 1:254 fired
  on four different resolvers over two networks, which a static skip list
  cannot keep up with.
- Default `ids.ignore_rules`: 1:402 (ICMP port unreachable) and 1:408 (ICMP
  echo reply), replies to this host's own traffic.
- A source that keeps alerting is blocked again once its block expired. Before,
  each source was acted on only once per daemon run.

**Testing**
- `packaging/selftest.sh` and `packaging/windows/selftest.ps1`: end-to-end
  checks (config, services, enforcement round trip with 203.0.113.250,
  alert parsing, capture, local network, Ollama). `docs/testing.md`.
- `hyeongi.diag`: read-only probes used by the self-tests.

**Capture**
- Fixed: every restart of `hyeongi-capture` (each boot) started the ring
  buffer again at `benign.pcap00`, overwriting what earlier boots captured, so
  the benign data set never grew past one session. Files are now named
  `benign-<start time>.pcapNN`; old files are removed only to stay near the size
  cap (default 4 GB, `HYEONGI_CAPTURE_GB`). Reinstall with
  `install-capture.sh` to switch.
- Flow logging now also runs on Linux (`capture.enabled: auto`, on when
  nfstream is installed): one CSV row of features per finished flow. Raw
  headers on the test machine grew by about 1 GB per hour of heavy use, so the
  packet ring only ever held the last hour or so; flow rows are what builds a
  multi-week benign set. `capture.rows_per_file` and `capture.keep` bound the
  disk use (default ~2 GB). The self-test reports how many flows are logged.
- The flow CSV header is written at once and rows reach the disk at least
  every 30 s.

**Shutdown**
- Fixed: stopping or restarting hyeongid took 90 s and ended in SIGKILL once
  flow logging was on, because nfstream's capture worker processes ignore
  SIGTERM and Python waited for them at exit. The daemon now flushes the flow
  CSV, kills its own worker processes and exits at once; the unit also sets
  `TimeoutStopSec=15`.

**ML detector**
- Fixed: the ML detector ignored `skip:` and `protect_local`, and never acted
  on a source again after its block expired. It now follows the same rules as
  the IDS bridge.
- ML detections are written to `ml.alert_file` in the Snort JSON format with
  gid 9000, so the LLM triage reviews them with the IDS alerts, and they show
  in the app and `hyeongi stats`.

**Human-in-the-loop blocking**
- `hyeongi ctl block <ip>` and a "선택한 IP 차단" button in the app: a person
  blocks an IP for `block_timeout` after reading the LLM review, also with
  `enforce: false`. Refuses this host's DNS servers, gateway, own addresses,
  skip-listed and loopback IPs.
- The app shows IPs currently in the kernel list as "차단 중" and the XDP
  dropped-packet counter.

**Demo mode**
- `hyeongi demo on <iface>` / `off`: move IDS, ML and XDP to an isolated lab
  interface (e.g. a VirtualBox host-only network), with enforce off,
  block_private on and training-data collection paused; `off` restores the
  saved config and Snort unit.
- `hyeongi demo on <iface> --model FILE`: use an ML model only while in
  demo mode; `off` removes it again or restores the model that was there.
- `ml.eval` no longer prints the old `hyeongi detect` command, warns when
  the held-out benign set is too small to support a 0% false-positive claim,
  and says so when no held-out attacks were given.
- Fixed: `hyeongi-xdp` stop detached from the interface named in the config
  instead of the one it was attached to, so switching interfaces left the old
  attachment behind.
- local.rules: SYN flood and SSH brute-force rules (detection_filter).
- Default `ids.ignore_rules` extended with what the test laptop raised on
  ordinary use and on plain pings: 1:399 (ICMP host unreachable), the
  informational PING rules 1:366/1:384/1:480/1:29456, and the port_scan sweep
  alerts 122:3/7/19/23. Port scans against this host still block.
- SYN-flood rule threshold raised to 1500 SYN in 2 s: at 200 a plain
  `nmap -sS` scan already triggered it.

**Desktop app**
- `hyeongi gui` (PySide6, Linux and Windows): status, alerts, blocked and
  would-be-blocked IPs with unblock and add-to-skip, the LLM report with a
  run-now button, enforce on/off and collection pause/resume. Runs as the
  user; changes go through `hyeongi ctl` with pkexec (Linux) or UAC (Windows).
- hyeongid writes `status.json` (world-readable) every 5 s: today's alert,
  block and would-block counts, recent alerts with the action taken, flow
  count, services, blocklist.
- `hyeongi stats`: the same summary in the terminal.
- Today's counts, flagged IPs and recent alerts survive daemon restarts.

**Triage schedule**
- Fixed: the hourly LLM review only ran after a full hour of uninterrupted
  uptime, and its timer stopped while a laptop was suspended, so on the test
  machine the report was a day old. It is now scheduled by the report's age
  (checked every minute, first run 2 minutes after start), retrying after
  10 minutes if a run produced no report.
- Menu entries: "HYEONGI" opens the app, "HYEONGI (terminal)" the banner
  launcher. Windows installs PySide6 and both Start-menu shortcuts.

**Collection control**
- `hyeongi pause [reason]` / `hyeongi resume` (Linux and Windows): stop
  saving training data during attack practice on the same host while detection
  keeps running. Pauses are logged to `pauses.log`.

**Other**
- The terminal banner (Linux and Windows) shows only the logo, the name and
  the version; the taglines are gone.
- `install-capture.sh` picks the default-route interface when none is given.
- The example config uses `eth0` instead of a machine-specific interface.

## 2.0.0

First public release of HYEONGI.

**Daemon**
- `hyeongid`: one daemon with supervised workers: IDS alert bridge, ML flow
  detection with flow logging, block expiry, and hourly local-LLM triage.
- Enforcement is off by default (`enforce: false`, log only). Private,
  loopback, link-local and multicast addresses are never blocked unless
  `block_private: true`. Every block expires after `block_timeout`.
- The triage (Ollama) is read-only: it reads alerts and the block list and
  writes a report.

**Detection**
- Reads Snort 3 `alert_json` and Suricata `eve.json` (auto-detected per line),
  following rotation and truncation.
- `hyeongi-ids`: a Snort 3 sensor managed by HYEONGI (generated config,
  `port_scan`, local rules, optional community rules; validated with `-T`).
- ML detector: nfstream statistical features and a RandomForest classifier;
  `ml.make_dataset`, `ml.train` and `ml.eval` (false-positive rate and
  threshold choice).
- `hyeongi-capture`: boot-time benign-traffic capture (headers only, ring
  buffer), with SELinux and AppArmor handling.

**Enforcement**
- nftables: isolated table `ip hyeongi`, input hook at priority -150, set
  with timeouts.
- XDP: `hyeongi_xdp.c` with pinned maps in `/sys/fs/bpf/hyeongi`; expiry
  is checked in the kernel. `hyeongi-xdp` re-attaches it at boot.
- Windows: Windows Defender Firewall rules in group `HYEONGI`, expiry
  reconciled by the daemon.

**Platforms**
- Linux: RHEL/Rocky/Fedora, Debian/Ubuntu, Arch, openSUSE. Installers detect
  the distro and print the right package names. Tested on RHEL 10.2.
- Windows 10/11: `install.ps1`, scheduled tasks `hyeongid` and
  `hyeongi-suricata`, Npcap capture. Not yet tested on real hardware.

**Tools**
- `hyeongi` launcher with banner and menu (`services`, `logs`, `report`,
  `xdp`), desktop entry and icon.
- `benchmark/`: enforcement-layer benchmarks (nftables vs XDP).

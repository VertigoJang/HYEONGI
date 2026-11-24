#!/usr/bin/env bash
# lab-netns.sh — an isolated attacker for testing CheckHook on this host, without a VM.
#
#   sudo bash packaging/lab-netns.sh up       # create netns "ckatk" + veth pair
#   sudo bash packaging/lab-netns.sh status
#   sudo bash packaging/lab-netns.sh mode rst|drop|reject   # how the victim answers
#   sudo bash packaging/lab-netns.sh down     # remove everything it created
#
# Topology (no route to any other network; nothing is forwarded or NATed):
#
#   host netns                      netns "ckatk"
#   ck-host 10.199.0.1/24  <=veth=>  ck-atk 10.199.0.2/24
#           fd99:199::1/64            fd99:199::2/64   (IPv6, if enabled on this host)
#
# fd99:199::/64 is unique-local (the IPv6 counterpart of RFC1918): CheckHook blocks it
# only with block_private, which `checkhook demo on ck-host` turns on.
#
# Victim response mode (for ML training across environments) only affects traffic
# arriving on ck-host, in an isolated table "inet cklab" (IPv4 and IPv6, priority -140):
#   rst    - no firewall: closed TCP -> RST, closed UDP -> ICMP port-unreachable (Kali)
#   drop   - silent: new inbound dropped, host never answers (firewalld / Windows)
#   reject - explicit: new inbound -> ICMP admin-prohibited (a REJECT firewall)
# Snort sniffs the link before netfilter, so it still sees every attack packet;
# only the victim's *answer* changes. Clear with: mode rst (or down).
#
# Run the attacker side with:   sudo ip netns exec ckatk <command>
#   e.g. sudo ip netns exec ckatk nmap -sS -p 1-1000 10.199.0.1
#        sudo ip netns exec ckatk nmap -6 -sS -p 1-1000 fd99:199::1
# Point CheckHook at the host side: sudo checkhook demo on ck-host [--model FILE]
#
# veth supports native XDP, so `xdp.mode: native` can be compared with generic
# on the same link (see benchmark/).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo." >&2; exit 1; }

NS=ckatk; H=ck-host; A=ck-atk; LABTBL=cklab
HIP=10.199.0.1; AIP=10.199.0.2; PFX=24
HIP6=fd99:199::1; AIP6=fd99:199::2

clear_mode() {   # current table, and the IPv4-only one from before rc33
  nft delete table inet "$LABTBL" 2>/dev/null || true
  nft delete table ip "$LABTBL" 2>/dev/null || true
}

conflict() {   # refuse if 10.199.0.0/24 is already used elsewhere on this host
  ip -4 -o addr show | awk '{print $2, $4}' | grep -v "^$H " | grep -q " 10\.199\.0\." 
}

case "${1:-}" in
  up)
    if ip netns list | grep -qw "$NS"; then echo "[=] $NS already exists"; exec bash "$0" status; fi
    conflict && { echo "[x] 10.199.0.0/24 is already in use on this host; edit HIP/AIP." >&2; exit 1; }
    ip netns add "$NS"
    ip link add "$H" type veth peer name "$A"
    ip link set "$A" netns "$NS"
    ip addr add "$HIP/$PFX" dev "$H"
    ip link set "$H" up
    ip netns exec "$NS" ip addr add "$AIP/$PFX" dev "$A"
    ip netns exec "$NS" ip link set "$A" up
    ip netns exec "$NS" ip link set lo up
    # IPv6 too, if this host has it; nodad = usable at once (no duplicate-address wait)
    V6=0
    if ip addr add "$HIP6/64" dev "$H" nodad 2>/dev/null \
       && ip netns exec "$NS" ip addr add "$AIP6/64" dev "$A" nodad 2>/dev/null; then V6=1; fi
    # the attacker has no default route: it can reach the host side and nothing else
    for i in 1 2 3 4 5; do ip netns exec "$NS" ping -c1 -W1 "$HIP" >/dev/null 2>&1 && break; sleep 1; done
    echo "[+] $NS ready: attacker $AIP ($A) -> host $HIP ($H)"
    if [[ $V6 == 1 ]]; then echo "    IPv6   : attacker $AIP6 -> host $HIP6"
    else echo "    IPv6   : not available on this host (IPv4 lab only)"; fi
    echo "    attack : sudo ip netns exec $NS nmap -sS -p 1-1000 $HIP"
    echo "    watch  : sudo checkhook demo on $H [--model FILE]"
    ;;
  mode)
    ip netns list | grep -qw "$NS" || { echo "[x] bring the lab up first: $0 up" >&2; exit 1; }
    clear_mode
    case "${2:-}" in
      rst|"")
        echo "[+] victim mode: rst (host default — closed TCP->RST, closed UDP->ICMP unreachable)" ;;
      drop)
        nft add table inet "$LABTBL"
        nft add chain inet "$LABTBL" input '{ type filter hook input priority -140; policy accept; }'
        nft add rule  inet "$LABTBL" input iif "$H" ct state new drop
        echo "[+] victim mode: drop (new inbound on $H silently dropped — no answer)" ;;
      reject)
        nft add table inet "$LABTBL"
        nft add chain inet "$LABTBL" input '{ type filter hook input priority -140; policy accept; }'
        nft add rule  inet "$LABTBL" input iif "$H" ct state new reject with icmpx type admin-prohibited
        echo "[+] victim mode: reject (new inbound on $H -> ICMP admin-prohibited)" ;;
      *) echo "[x] mode must be: rst | drop | reject" >&2; exit 2 ;;
    esac
    echo "    attacker sees this response; Snort still sees every attack packet on $H"
    ;;
  down)
    clear_mode
    ip netns del "$NS" 2>/dev/null && echo "[+] removed netns $NS (its veth end goes with it)" || echo "[=] no netns $NS"
    ip link del "$H" 2>/dev/null || true
    ;;
  status)
    ip netns list | grep -w "$NS" || { echo "no netns $NS"; exit 0; }
    ip -br addr show "$H"
    ip netns exec "$NS" ip -br addr show "$A"
    ip netns exec "$NS" ip route
    ip -d link show "$H" | grep -o "xdp[a-z]* .*prog/xdp id [0-9]*" || echo "(no XDP program on $H)"
    T=""
    for fam in inet ip; do nft list table "$fam" "$LABTBL" >/dev/null 2>&1 && { T="$fam"; break; }; done
    if [[ -n $T ]]; then
      nft list table "$T" "$LABTBL" | grep -q "drop" && echo "victim mode: drop" \
        || { nft list table "$T" "$LABTBL" | grep -q "reject" && echo "victim mode: reject" || echo "victim mode: (custom)"; }
    else echo "victim mode: rst (default)"; fi
    ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac

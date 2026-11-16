#!/usr/bin/env bash
# lab-netns.sh — an isolated attacker for testing CheckHook on this host, without a VM.
#
#   sudo bash packaging/lab-netns.sh up       # create netns "ckatk" + veth pair
#   sudo bash packaging/lab-netns.sh status
#   sudo bash packaging/lab-netns.sh down     # remove everything it created
#
# Topology (no route to any other network; nothing is forwarded or NATed):
#
#   host netns                      netns "ckatk"
#   ck-host 10.199.0.1/24  <=veth=>  ck-atk 10.199.0.2/24
#
# Run the attacker side with:   sudo ip netns exec ckatk <command>
#   e.g. sudo ip netns exec ckatk nmap -sS -p 1-1000 10.199.0.1
# Point CheckHook at the host side: sudo checkhook demo on ck-host [--model FILE]
#
# veth supports native XDP, so `xdp.mode: native` can be compared with generic
# on the same link (see benchmark/).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo." >&2; exit 1; }

NS=ckatk; H=ck-host; A=ck-atk
HIP=10.199.0.1; AIP=10.199.0.2; PFX=24

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
    # the attacker has no default route: it can reach 10.199.0.1 and nothing else
    for i in 1 2 3 4 5; do ip netns exec "$NS" ping -c1 -W1 "$HIP" >/dev/null 2>&1 && break; sleep 1; done
    echo "[+] $NS ready: attacker $AIP ($A) -> host $HIP ($H)"
    echo "    attack : sudo ip netns exec $NS nmap -sS -p 1-1000 $HIP"
    echo "    watch  : sudo checkhook demo on $H [--model FILE]"
    ;;
  down)
    ip netns del "$NS" 2>/dev/null && echo "[+] removed netns $NS (its veth end goes with it)" || echo "[=] no netns $NS"
    ip link del "$H" 2>/dev/null || true
    ;;
  status)
    ip netns list | grep -w "$NS" || { echo "no netns $NS"; exit 0; }
    ip -br addr show "$H"
    ip netns exec "$NS" ip -br addr show "$A"
    ip netns exec "$NS" ip route
    ip -d link show "$H" | grep -o "xdp[a-z]* .*prog/xdp id [0-9]*" || echo "(no XDP program on $H)"
    ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac

#!/usr/bin/env bash
# Shared settings and helpers. Source this file; do not execute it.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

HOSTS=(1 2 3 4)       # virtual hosts vh1..vh4
CONTAINERS=(1 2 3)    # containers per host: c<host><n>
OVERLAY_MTU="${LAB_OVERLAY_MTU:-1450}"   # VXLAN over a 1500 MTU underlay

# Underlay: one /24 per plane.
a_ip() { echo "10.10.1.1$1"; }
b_ip() { echo "10.20.1.1$1"; }

# Overlay: one /24 per host (10.100.<host>.0/24), gateway .1, containers .2 .3 .4
host_subnet() { echo "10.100.$1.0/24"; }
host_gw()     { echo "10.100.$1.1"; }
cont_name()   { echo "c$1$2"; }
cont_ip()     { echo "10.100.$1.$(( $2 + 1 ))"; }

# Per-host VTEP identity used for routed VXLAN (Flannel style).
vtep_ip()  { echo "10.200.0.$1"; }
vtep_mac() { printf '02:00:00:00:00:%02x' "$1"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "run as root: sudo -E $0" >&2
    exit 1
  fi
}

# Remove only the overlay (containers, bridge, VXLAN). Leaves the underlay.
overlay_down() {
  local ns i
  while read -r ns _; do
    case "$ns" in c[0-9]*) ip netns del "$ns" ;; esac
  done < <(ip netns list)
  for i in "${HOSTS[@]}"; do
    ip -n "vh$i" link del vxlan100 2>/dev/null || true
    ip -n "vh$i" link del br-c 2>/dev/null || true
  done
}

# Remove virtual hosts and underlay routers.
underlay_down() {
  local ns
  while read -r ns _; do
    case "$ns" in vh[0-9]*|r1|r2) ip netns del "$ns" ;; esac
  done < <(ip netns list)
}

# Veth ends that may be left in the root namespace after a partial failure.
cleanup_root_veths() {
  local i j dev
  for i in "${HOSTS[@]}"; do
    for dev in "a${i}h" "a${i}r" "b${i}h" "b${i}r"; do
      ip link del "$dev" 2>/dev/null || true
    done
    for j in "${CONTAINERS[@]}"; do
      for dev in "h${i}${j}" "p${i}${j}"; do
        ip link del "$dev" 2>/dev/null || true
      done
    done
  done
}

# apply_netem <router ns> <port prefix a|b> <delay ms> <loss %> <rate mbit>
# Applied on each router-side port, egress toward the host. A unicast packet
# crosses exactly one such port, so delay applies once per direction
# (RTT = 2 x delay). All zeros removes the qdisc.
apply_netem() {
  local ns=$1 prefix=$2 delay=$3 loss=$4 rate=$5
  local i dev
  local -a args
  for i in "${HOSTS[@]}"; do
    dev="${prefix}${i}r"
    tc -n "$ns" qdisc del dev "$dev" root 2>/dev/null || true
    args=()
    if [[ $delay != 0 ]]; then args+=(delay "${delay}ms"); fi
    if [[ $loss  != 0 ]]; then args+=(loss "${loss}%"); fi
    if [[ $rate  != 0 ]]; then args+=(rate "${rate}mbit"); fi
    if (( ${#args[@]} > 0 )); then
      tc -n "$ns" qdisc add dev "$dev" root netem "${args[@]}"
    fi
  done
}

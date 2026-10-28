#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

on_error() {
  local rc=$?
  echo "lab-up failed (exit $rc); cleaning partial lab state" >&2
  "$ROOT/scripts/lab-down.sh" || true
  exit "$rc"
}
trap on_error ERR

"$ROOT/scripts/lab-down.sh"

# Underlay routers: each plane is an isolated L2 bridge in its own namespace.
ip netns add r1
ip netns add r2
ip -n r1 link set lo up
ip -n r2 link set lo up
ip -n r1 link add br-a type bridge
ip -n r2 link add br-b type bridge
ip -n r1 link set br-a up
ip -n r2 link set br-b up

for i in "${HOSTS[@]}"; do
  h="vh$i"
  ip netns add "$h"
  ip -n "$h" link set lo up
  # Hosts forward packets (overlay gateway). rp_filter off for multipath later.
  ip netns exec "$h" sysctl -qw \
    net.ipv4.ip_forward=1 \
    net.ipv4.conf.all.rp_filter=0 \
    net.ipv4.conf.default.rp_filter=0 \
    net.ipv6.conf.all.disable_ipv6=1

  # Plane A
  ip link add "a${i}h" type veth peer name "a${i}r"
  ip link set "a${i}h" netns "$h"
  ip link set "a${i}r" netns r1
  ip -n "$h" link set "a${i}h" name ua0
  ip -n r1 link set "a${i}r" master br-a
  ip -n r1 link set "a${i}r" up
  ip -n "$h" addr add "$(a_ip "$i")/24" dev ua0
  ip -n "$h" link set ua0 up

  # Plane B
  ip link add "b${i}h" type veth peer name "b${i}r"
  ip link set "b${i}h" netns "$h"
  ip link set "b${i}r" netns r2
  ip -n "$h" link set "b${i}h" name ub0
  ip -n r2 link set "b${i}r" master br-b
  ip -n r2 link set "b${i}r" up
  ip -n "$h" addr add "$(b_ip "$i")/24" dev ub0
  ip -n "$h" link set ub0 up
done

apply_netem r1 a "${LAB_A_DELAY_MS:-0}" "${LAB_A_LOSS_PERCENT:-0}" "${LAB_A_RATE_MBIT:-0}"
apply_netem r2 b "${LAB_B_DELAY_MS:-0}" "${LAB_B_LOSS_PERCENT:-0}" "${LAB_B_RATE_MBIT:-0}"

trap - ERR
echo "Underlay up: vh1-vh4, plane A (r1, 10.10.1.0/24), plane B (r2, 10.20.1.0/24)."
echo "Next: sudo scripts/overlay-b1.sh"

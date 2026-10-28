#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

if ! ip netns list | grep -q '^vh1'; then
  echo "underlay not found; run scripts/lab-up.sh first" >&2
  exit 1
fi

overlay_down

# For Milestone M2: 2 hosts only, no VXLAN, MTU 1440
M2_HOSTS=(1 2)
M2_CONTAINERS=(1 2 3)
OVERLAY_MTU=1440

# Assign static deterministic MACs to ua0 so peer addresses are known
ip -n vh1 link set ua0 address 02:00:0a:0a:01:11
ip -n vh2 link set ua0 address 02:00:0a:0a:01:12

for i in "${M2_HOSTS[@]}"; do
  h="vh$i"

  # Local bridge and gateway for this host's containers
  ip -n "$h" link add br-c address "02:00:0a:64:0${i}:01" type bridge
  ip -n "$h" addr add "$(host_gw "$i")/24" dev br-c
  ip -n "$h" link set br-c mtu "$OVERLAY_MTU" up

  # Containers
  for j in "${M2_CONTAINERS[@]}"; do
    c="$(cont_name "$i" "$j")"
    left="h${i}${j}"    # host side veth
    right="p${i}${j}"   # container side veth
    c_mac="02:00:0a:64:0${i}:0$(( j + 1 ))"
    h_mac="02:00:10:0${i}:0${i}:0$(( j + 1 ))"

    ip netns add "$c"
    ip -n "$c" link set lo up
    ip netns exec "$c" sysctl -qw net.ipv6.conf.all.disable_ipv6=1

    ip link add "$left" address "$h_mac" type veth peer name "$right" address "$c_mac"
    ip link set "$left" netns "$h"
    ip link set "$right" netns "$c"

    ip -n "$h" link set "$left" master br-c
    ip -n "$h" link set "$left" mtu "$OVERLAY_MTU" up

    ip -n "$c" link set "$right" name eth0
    ip -n "$c" link set eth0 mtu "$OVERLAY_MTU"
    ip -n "$c" addr add "$(cont_ip "$i" "$j")/24" dev eth0
    ip -n "$c" link set eth0 up
    ip -n "$c" route add default via "$(host_gw "$i")"

    # Turn off offloads on host veth and container eth0
    ip netns exec "$h" ethtool -K "$left" gso off tso off gro off 2>/dev/null || true
    ip netns exec "$c" ethtool -K eth0 gso off tso off gro off 2>/dev/null || true
  done
done

echo "M2 overlay up: 2 hosts (vh1, vh2), 3 containers each, MTU $OVERLAY_MTU, offloads disabled."
echo "No VXLAN configured; ready for meshlink eBPF datapath."

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

if ! ip netns list | grep -q '^vh1'; then
  echo "underlay not found; run scripts/lab-up.sh first" >&2
  exit 1
fi

overlay_down

for i in "${HOSTS[@]}"; do
  h="vh$i"

  # Local bridge and gateway for this host's containers.
  ip -n "$h" link add br-c type bridge
  ip -n "$h" addr add "$(host_gw "$i")/24" dev br-c
  ip -n "$h" link set br-c mtu "$OVERLAY_MTU" up

  # VXLAN device on plane A, no learning: all state is static.
  ip -n "$h" link add vxlan100 address "$(vtep_mac "$i")" type vxlan \
    id 100 local "$(a_ip "$i")" dstport 4789 dev ua0 nolearning
  ip -n "$h" addr add "$(vtep_ip "$i")/32" dev vxlan100
  ip -n "$h" link set vxlan100 up

  # Routes to every other host's subnet via its VTEP.
  for j in "${HOSTS[@]}"; do
    if [[ "$i" != "$j" ]]; then
      ip -n "$h" neigh replace "$(vtep_ip "$j")" \
        lladdr "$(vtep_mac "$j")" dev vxlan100 nud permanent
      ip netns exec "$h" bridge fdb replace "$(vtep_mac "$j")" \
        dev vxlan100 dst "$(a_ip "$j")" self permanent
      ip -n "$h" route replace "$(host_subnet "$j")" \
        via "$(vtep_ip "$j")" dev vxlan100 onlink
    fi
  done

  # Containers.
  for j in "${CONTAINERS[@]}"; do
    c="$(cont_name "$i" "$j")"
    left="h${i}${j}"    # host side (unique name in root ns while moving)
    right="p${i}${j}"
    ip netns add "$c"
    ip -n "$c" link set lo up
    ip netns exec "$c" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip link add "$left" type veth peer name "$right"
    ip link set "$left" netns "$h"
    ip link set "$right" netns "$c"
    ip -n "$h" link set "$left" master br-c
    ip -n "$h" link set "$left" mtu "$OVERLAY_MTU" up
    ip -n "$c" link set "$right" name eth0
    ip -n "$c" link set eth0 mtu "$OVERLAY_MTU"
    ip -n "$c" addr add "$(cont_ip "$i" "$j")/24" dev eth0
    ip -n "$c" link set eth0 up
    ip -n "$c" route add default via "$(host_gw "$i")"
  done
done

echo "B1 up: routed VXLAN (VNI 100) on plane A. Container MTU $OVERLAY_MTU."
echo "Verify: sudo scripts/lab-check.sh"

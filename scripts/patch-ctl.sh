#!/usr/bin/env bash
# Simulate pulling or restoring an underlay "cable".
#   path-ctl.sh <a|b> <down|up> [host-index]
# Takes the router-side port down, so the host sees NO-CARRIER like a real
# cable pull. Without a host index, the whole plane is affected.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

usage() { echo "usage: $0 <a|b> <down|up> [host-index 1-4]" >&2; exit 2; }
[[ $# -ge 2 ]] || usage

case "$1" in
  a) ns=r1; prefix=a ;;
  b) ns=r2; prefix=b ;;
  *) usage ;;
esac
case "$2" in
  up|down) action=$2 ;;
  *) usage ;;
esac

if [[ -n "${3:-}" ]]; then targets=("$3"); else targets=("${HOSTS[@]}"); fi
for i in "${targets[@]}"; do
  ip -n "$ns" link set "${prefix}${i}r" "$action"
done
echo "plane $1 ${action}: hosts ${targets[*]}"

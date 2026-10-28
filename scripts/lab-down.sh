#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

overlay_down
underlay_down
cleanup_root_veths
echo "Lab removed."

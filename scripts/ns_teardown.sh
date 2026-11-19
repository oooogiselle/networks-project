#!/usr/bin/env bash
# ns_teardown.sh - stop everything running in the test namespaces and delete
# them. Safe to run when nothing exists.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"

need_root

# Processes keep a namespace alive, so kill them first (tunwall, servers).
for sig in TERM KILL; do
    for ns in "$NS_INSIDE" "$NS_FW" "$NS_OUTSIDE"; do
        pids=$(ip netns pids "$ns" 2>/dev/null || true)
        [ -n "$pids" ] && kill -s "$sig" $pids 2>/dev/null
    done
    [ "$sig" = TERM ] && sleep 0.3
done

for ns in "$NS_INSIDE" "$NS_FW" "$NS_OUTSIDE"; do
    if ip netns list | grep -qw "$ns"; then
        ip netns del "$ns" && say "deleted namespace $ns"
    fi
done

# Leftover temporary veth names (only if setup died half way).
for dev in tw-in-a tw-in-b tw-out-a tw-out-b; do
    ip link del "$dev" 2>/dev/null || true
done
rm -f "$RUN_DIR"/*.pid 2>/dev/null || true
exit 0

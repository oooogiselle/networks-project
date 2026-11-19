#!/usr/bin/env bash
# ns_diag.sh - dump the full state of the test network. Paste the output
# when asking for help debugging routing.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"

need_root

section() { printf '\n===== %s =====\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1; }

section "host"
run uname -r
run ip netns list

for ns in "$NS_INSIDE" "$NS_FW" "$NS_OUTSIDE"; do
    if ! ip netns list | grep -qw "$ns"; then
        section "$ns: MISSING"
        continue
    fi
    section "$ns"
    run ip -n "$ns" -br addr
    run ip -n "$ns" route
    run ip -n "$ns" -s -br link
    printf 'processes: %s\n' "$(ip netns pids "$ns" | xargs -r ps -o pid=,comm= -p 2>/dev/null | tr '\n' ' ')"
done

if ip netns list | grep -qw "$NS_FW"; then
    section "$NS_FW policy routing"
    run ip -n "$NS_FW" rule
    run ip -n "$NS_FW" route show table 100
    run ip -n "$NS_FW" route show table 200
    run ip -n "$NS_FW" route get "$SERVER" from "$CLIENT_A" iif veth-in
    run ip -n "$NS_FW" route get "$CLIENT_A" from "$SERVER" iif veth-out

    section "$NS_FW TUN devices (NO-CARRIER = tunwall not attached)"
    run ip -n "$NS_FW" -d link show tun-in
    run ip -n "$NS_FW" -d link show tun-out
    run ip -n "$NS_FW" -s link show tun-in
    run ip -n "$NS_FW" -s link show tun-out

    section "$NS_FW sysctls"
    for k in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter \
             net.ipv4.conf.default.rp_filter net.ipv4.conf.all.forwarding; do
        run ip netns exec "$NS_FW" sysctl "$k"
    done
    for dev in veth-in veth-out tun-in tun-out; do
        printf '%s: rp_filter=%s forwarding=%s\n' "$dev" \
            "$(ip netns exec "$NS_FW" cat /proc/sys/net/ipv4/conf/$dev/rp_filter 2>/dev/null)" \
            "$(ip netns exec "$NS_FW" cat /proc/sys/net/ipv4/conf/$dev/forwarding 2>/dev/null)"
    done
    section "$NS_FW kernel drop counters"
    run ip netns exec "$NS_FW" nstat -az IpInDiscards IpInAddrErrors IpOutNoRoutes TcpExtIPReversePathFilter 2>/dev/null
fi

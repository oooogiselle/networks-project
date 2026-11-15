#!/usr/bin/env bash
# ============================================================================
# File Name:   netns.sh
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Builds (up) or removes (down) the test topology from the spec:
#
#   inside ns          firewall ns                       outside ns
#   10.0.1.2, .3 --- veth-in 10.0.1.1   veth-out 10.0.2.1 --- 10.0.2.2, .3
#                         |                  |
#                       tun-in  <- tunwall -> tun-out
#
# Policy routing sends every packet that arrives on veth-in into tun-in and
# every packet that arrives on veth-out into tun-out, so the kernel never
# forwards between the two sides itself: tunwall is the only path. Packets
# tunwall writes to the opposite tun device are routed out the right veth by
# the main table. The tun devices are PERSISTENT: if tunwall is not running
# the kernel drops whatever it routes to them, so no traffic gets through.
#
# "up kernel" builds the same topology WITHOUT the policy routing, so the kernel
# forwards between the two sides itself: the baseline for the benchmarks.
#
# Usage: sudo scripts/netns.sh up [kernel] | down | status
# Start the firewall with: sudo ip netns exec firewall build/tunwall -r <rules>
# ============================================================================
set -eu

IN=inside; FW=firewall; OUT=outside

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0 $*)" >&2; exit 1; }; }

fw()  { ip netns exec "$FW" "$@"; }

down() {
    for ns in "$IN" "$FW" "$OUT"; do ip netns del "$ns" 2>/dev/null || true; done
}

up() {
    local mode=${1:-firewall}
    down
    for ns in "$IN" "$FW" "$OUT"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

    # veth pairs: client side in its namespace, firewall side in the firewall's
    ip link add veth-cin  netns "$IN"  type veth peer name veth-in  netns "$FW"
    ip link add veth-sout netns "$OUT" type veth peer name veth-out netns "$FW"

    # inside hosts: client A and client B (a second address on one interface)
    ip -n "$IN" addr add 10.0.1.2/24 dev veth-cin
    ip -n "$IN" addr add 10.0.1.3/24 dev veth-cin
    ip -n "$IN" link set veth-cin up
    ip -n "$IN" route add default via 10.0.1.1

    # outside hosts: the web/DNS server and the attacker
    ip -n "$OUT" addr add 10.0.2.2/24 dev veth-sout
    ip -n "$OUT" addr add 10.0.2.3/24 dev veth-sout
    ip -n "$OUT" link set veth-sout up
    ip -n "$OUT" route add default via 10.0.2.1

    # firewall namespace
    ip -n "$FW" addr add 10.0.1.1/24 dev veth-in
    ip -n "$FW" addr add 10.0.2.1/24 dev veth-out
    ip -n "$FW" link set veth-in up
    ip -n "$FW" link set veth-out up
    for t in tun-in tun-out; do
        fw ip tuntap add dev "$t" mode tun       # persistent: outlives tunwall
        ip -n "$FW" link set "$t" up
    done

    # Forward packets, but do not let the kernel's reverse-path filter drop the
    # ones tunwall writes back (their source is not "reachable" via the tun
    # device they arrive on), and never answer pings aimed at the firewall's own
    # addresses: those would bypass the rules.
    fw sysctl -qw net.ipv4.ip_forward=1
    fw sysctl -qw net.ipv4.icmp_echo_ignore_all=1
    # IPv4 only (the firewall drops IPv6): without this the kernel sends IPv6
    # neighbour discovery into the tun devices, which only clutters the log.
    fw sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    fw sysctl -qw net.ipv6.conf.default.disable_ipv6=1
    for ifc in tun-in tun-out veth-in veth-out; do
        fw sysctl -qw "net.ipv6.conf.$ifc.disable_ipv6=1"
    done
    for ifc in all default veth-in veth-out tun-in tun-out; do
        fw sysctl -qw "net.ipv4.conf.$ifc.rp_filter=0"
    done

    # Everything arriving from a side goes to that side's tun device (unless
    # this is the kernel-forwarding baseline).
    if [ "$mode" != kernel ]; then
        ip -n "$FW" rule add iif veth-in  lookup 100 pref 100
        ip -n "$FW" rule add iif veth-out lookup 200 pref 101
        ip -n "$FW" route add default dev tun-in  table 100
        ip -n "$FW" route add default dev tun-out table 200
    fi

    # Offloads would hand tunwall oversized or half-checksummed packets.
    for pair in "$IN:veth-cin" "$FW:veth-in" "$FW:veth-out" "$OUT:veth-sout"; do
        ip netns exec "${pair%%:*}" ethtool -K "${pair##*:}" tso off gso off gro off \
            tx off rx off >/dev/null 2>&1 || true
    done
    echo "namespaces up ($mode): inside=10.0.1.2,.3  firewall=10.0.1.1/10.0.2.1  outside=10.0.2.2,.3"
}

status() {
    for ns in "$IN" "$FW" "$OUT"; do
        echo "== $ns"; ip -n "$ns" -br addr 2>&1 | sed 's/^/   /'
    done
    echo "== firewall rules"; ip -n "$FW" rule 2>&1 | sed 's/^/   /'
}

case "${1:-}" in
    up)     need_root "$@"; up "${2:-firewall}" ;;
    down)   need_root "$@"; down ;;
    status) need_root "$@"; status ;;
    *) echo "usage: sudo $0 up | down | status" >&2; exit 2 ;;
esac

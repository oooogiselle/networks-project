#!/usr/bin/env bash
# ns_setup.sh - build the three-namespace test network (spec Figure 1).
#
#   inside (10.0.1.2, .3) --veth-- fw [veth-in  tun-in | tun-out veth-out] --veth-- outside (10.0.2.2, .3)
#
# In the fw namespace, policy routing sends everything arriving from the
# inside into tun-in and everything arriving from the outside into tun-out,
# so tunwall (attached to both TUNs) is the only path between the sides.
# Blackhole rules make it fail closed: if the TUN route is unusable, packets
# are dropped instead of being forwarded directly.
#
# Idempotent: tears down any previous instance first.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"

need_root
check_deps ip
"$HERE/ns_teardown.sh" >/dev/null 2>&1 || true

say "creating namespaces: $NS_INSIDE $NS_FW $NS_OUTSIDE"
for ns in "$NS_INSIDE" "$NS_FW" "$NS_OUTSIDE"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    # IPv4 only (spec): keep kernel IPv6 chatter (router solicitations, MLD)
    # out of tunwall's drop counters. Interfaces created later inherit this.
    in_ns "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
    in_ns "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
done

say "creating veth links"
# Create in the root namespace under temporary names, then move and rename.
ip link add tw-in-a type veth peer name tw-in-b
ip link set tw-in-a netns "$NS_FW"
ip link set tw-in-b netns "$NS_INSIDE"
ip -n "$NS_FW" link set tw-in-a name veth-in
ip -n "$NS_INSIDE" link set tw-in-b name eth0

ip link add tw-out-a type veth peer name tw-out-b
ip link set tw-out-a netns "$NS_FW"
ip link set tw-out-b netns "$NS_OUTSIDE"
ip -n "$NS_FW" link set tw-out-a name veth-out
ip -n "$NS_OUTSIDE" link set tw-out-b name eth0

say "addressing"
ip -n "$NS_INSIDE" addr add "$CLIENT_A/24" dev eth0
ip -n "$NS_INSIDE" addr add "$CLIENT_B/24" dev eth0
ip -n "$NS_INSIDE" link set eth0 up
ip -n "$NS_INSIDE" route add default via "$FW_INSIDE"

ip -n "$NS_OUTSIDE" addr add "$SERVER/24" dev eth0
ip -n "$NS_OUTSIDE" addr add "$ATTACKER/24" dev eth0
ip -n "$NS_OUTSIDE" link set eth0 up
ip -n "$NS_OUTSIDE" route add default via "$FW_OUTSIDE"

ip -n "$NS_FW" addr add "$FW_INSIDE/24" dev veth-in
ip -n "$NS_FW" addr add "$FW_OUTSIDE/24" dev veth-out
ip -n "$NS_FW" link set veth-in up
ip -n "$NS_FW" link set veth-out up

say "creating persistent TUN devices tun-in, tun-out in $NS_FW"
ip -n "$NS_FW" tuntap add dev tun-in mode tun
ip -n "$NS_FW" tuntap add dev tun-out mode tun
ip -n "$NS_FW" link set tun-in up
ip -n "$NS_FW" link set tun-out up

say "sysctls in $NS_FW: forwarding on, reverse-path filtering off"
# Packets re-enter the kernel on the TUN facing the "wrong" side (a packet
# from 10.0.1.2 arrives on tun-out), so strict rp_filter would drop them.
in_ns "$NS_FW" sysctl -qw net.ipv4.ip_forward=1
for dev in all default veth-in veth-out tun-in tun-out; do
    in_ns "$NS_FW" sh -c "echo 0 > /proc/sys/net/ipv4/conf/$dev/rp_filter"
done

say "policy routing in $NS_FW"
ip -n "$NS_FW" route add default dev tun-in table 100
ip -n "$NS_FW" route add default dev tun-out table 200
ip -n "$NS_FW" rule add pref 100 iif veth-in lookup 100
ip -n "$NS_FW" rule add pref 101 iif veth-in blackhole
ip -n "$NS_FW" rule add pref 200 iif veth-out lookup 200
ip -n "$NS_FW" rule add pref 201 iif veth-out blackhole

# Offloads: make every packet fully checksummed and MTU-sized on the wire,
# so tunwall sees exactly what a real link would carry. Best effort.
if command -v ethtool >/dev/null 2>&1; then
    for spec in "$NS_INSIDE eth0" "$NS_OUTSIDE eth0" "$NS_FW veth-in" "$NS_FW veth-out"; do
        set -- $spec
        in_ns "$1" ethtool -K "$2" tx off tso off gso off gro off >/dev/null 2>&1 || true
    done
else
    warn "ethtool not found; leaving offloads on (sudo apt-get install -y ethtool)"
fi

say "done. Start the firewall with:"
echo "   sudo ip netns exec $NS_FW ./tunwall -r config/rules.example.conf -v"
echo "   (until it runs, no traffic passes between $NS_INSIDE and $NS_OUTSIDE)"

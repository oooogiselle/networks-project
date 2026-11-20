#!/usr/bin/env bash
# ============================================================================
# File Name:   netns.sh
# Author:      Eva Tate and Giselle Wu
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
# "up nat" is the firewall topology plus a path to the real Internet for the
# demo: the outside namespace becomes a NAT gateway (10.0.3.2) to the host
# (10.0.3.1), which masquerades out of its normal uplink. It changes the HOST:
# a veth pair, ip_forward, and three iptables rules, every one tagged with the
# comment "tunwall-demo", and `down` removes exactly those and restores the
# previous ip_forward. The inside namespace gets a resolv.conf pointing at
# 10.0.2.2, where scripts/dns_forwarder.py answers (the example rules only let
# the inside use that one resolver).
#
# 10.0.2.254 is set aside as the source NAT address (tunwall -n 10.0.2.254).
#
# Usage: sudo scripts/netns.sh up [kernel|nat] | down | status
# Start the firewall with: sudo ip netns exec firewall build/tunwall -r <rules>
# ============================================================================
set -euE      # -E: the ERR trap in up() also fires inside functions

IN=inside; FW=firewall; OUT=outside
STATE=/run/tunwall-netns        # what "up nat" changed on the host, so down can undo it
TAG=tunwall-demo

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0 $*)" >&2; exit 1; }; }

fw()  { ip netns exec "$FW" "$@"; }

# The three host rules for the Internet path (add with -I, remove with -D).
host_rules() { # host_rules -I|-D <uplink>
    local op=$1 up=$2
    iptables -t nat "$op" POSTROUTING -s 10.0.3.0/24 -o "$up" -m comment --comment $TAG -j MASQUERADE
    iptables "$op" FORWARD -i veth-host -o "$up" -m comment --comment $TAG -j ACCEPT
    iptables "$op" FORWARD -i "$up" -o veth-host -m conntrack --ctstate RELATED,ESTABLISHED \
        -m comment --comment $TAG -j ACCEPT
}

# Undo whatever "up nat" did to the host. Safe to run when it did nothing.
internet_down() {
    if [ -f "$STATE/uplink" ]; then
        local up; up=$(cat "$STATE/uplink")
        while host_rules -D "$up" 2>/dev/null; do :; done
    fi
    [ -f "$STATE/ip_forward" ] && sysctl -qw net.ipv4.ip_forward="$(cat "$STATE/ip_forward")" || true
    if [ -f "$STATE/created" ]; then
        while read -r f; do rm -f "$f"; rmdir "$(dirname "$f")" 2>/dev/null || true; done < "$STATE/created"
    fi
    rm -rf "$STATE"
    ip link del veth-host 2>/dev/null || true
}

down() {
    internet_down
    for ns in "$IN" "$FW" "$OUT"; do ip netns del "$ns" 2>/dev/null || true; done
}

# The outside namespace becomes a NAT gateway to the host's Internet.
internet_up() {
    local uplink
    uplink=$(ip route show default | awk '/default/ {print $5; exit}')
    [ -n "$uplink" ] || { echo "netns.sh: the host has no default route, so there is no Internet to share" >&2; return 1; }
    mkdir -p "$STATE"
    echo "$uplink" > "$STATE/uplink"
    sysctl -n net.ipv4.ip_forward > "$STATE/ip_forward"

    ip link add veth-host type veth peer name veth-wan netns "$OUT"
    ip addr add 10.0.3.1/24 dev veth-host
    ip link set veth-host up
    ip -n "$OUT" addr add 10.0.3.2/24 dev veth-wan
    ip -n "$OUT" link set veth-wan up
    ip -n "$OUT" route replace default via 10.0.3.1          # the Internet is via the host
    ip -n "$OUT" route add 10.0.1.0/24 via 10.0.2.1          # the inside is via the firewall
    ip netns exec "$OUT" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$OUT" iptables -t nat -A POSTROUTING -o veth-wan -j MASQUERADE
    ip -n "$FW" route add default via 10.0.2.2               # the firewall hands the rest to "outside"

    sysctl -qw net.ipv4.ip_forward=1
    host_rules -I "$uplink"

    # ip netns exec uses /etc/netns/<ns>/resolv.conf when it exists. Never
    # overwrite one that is already there.
    local ns
    for ns in "$IN" "$OUT"; do
        local f=/etc/netns/$ns/resolv.conf
        if [ -e "$f" ]; then echo "netns.sh: keeping your existing $f" >&2; continue; fi
        mkdir -p "/etc/netns/$ns"
        if [ "$ns" = "$IN" ]; then echo "nameserver 10.0.2.2" > "$f"; else echo "nameserver 1.1.1.1" > "$f"; fi
        echo "$f" >> "$STATE/created"
    done
    echo "Internet path up: outside=10.0.3.2 -> host 10.0.3.1 -> $uplink (DNS: run scripts/dns_forwarder.py in the outside namespace)"
}

up() {
    local mode=${1:-firewall}
    down
    # Never leave a half-built topology behind: a failure anywhere tears it all
    # down again instead of leaving, say, forwarding on and the rules missing.
    trap 'echo "netns.sh: setup failed, tearing down" >&2; down' ERR
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
        # Persistent (outlives tunwall) and owned by root, so no other user can
        # attach to it while tunwall is down.
        fw ip tuntap add dev "$t" mode tun user root group root
        ip -n "$FW" link set "$t" up
    done

    # Do not let the kernel's reverse-path filter drop the packets tunwall
    # writes back (their source is not "reachable" via the tun device they
    # arrive on), and never answer pings aimed at the firewall's own addresses.
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
        ip -n "$FW" route add default dev tun-in  table 100
        ip -n "$FW" route add default dev tun-out table 200
        ip -n "$FW" rule add iif veth-in  lookup 100 pref 100
        ip -n "$FW" rule add iif veth-out lookup 200 pref 101
        # Fail closed: if a tun device is deleted or goes down, its table has no
        # route and a plain "lookup" rule would fall through to the main table,
        # where the kernel would forward straight between the two sides. These
        # terminal rules drop (silently) whatever the lookups did not take.
        ip -n "$FW" rule add iif veth-in  blackhole pref 102
        ip -n "$FW" rule add iif veth-out blackhole pref 103
        # The kernel's "local" table (addresses of the firewall itself) is
        # consulted first by default, so packets aimed at 10.0.1.1 / 10.0.2.1
        # would be answered by the kernel and never reach tunwall (ports there
        # would show as closed, not filtered). Consult it after the iif rules.
        ip -n "$FW" rule add from all lookup local pref 1000
        ip -n "$FW" rule del pref 0
        # ...but the kernel answers ARP for its own address only when its input
        # route lookup says "local", which the iif rules now pre-empt. So the
        # hosts get their gateway's MAC as a permanent neighbour entry instead
        # of asking for it. (The firewall still resolves the hosts normally.)
        local mac_in mac_out
        mac_in=$(ip -n "$FW" link show veth-in  | awk '/link\/ether/ {print $2}')
        mac_out=$(ip -n "$FW" link show veth-out | awk '/link\/ether/ {print $2}')
        ip -n "$IN"  neigh replace 10.0.1.1 lladdr "$mac_in"  dev veth-cin  nud permanent
        ip -n "$OUT" neigh replace 10.0.2.1 lladdr "$mac_out" dev veth-sout nud permanent
        # Source NAT address for "tunwall -n 10.0.2.254". No interface owns it:
        # the outside reaches it through veth-out (so it lands in tun-out like
        # any other packet from the outside), and ICMP errors the firewall's own
        # kernel sends to it (e.g. "fragmentation needed" for a translated
        # packet) are routed into tun-out too, so tunwall translates them back
        # to the inside host. Harmless without -n: tunwall drops such packets.
        ip -n "$OUT" neigh replace 10.0.2.254 lladdr "$mac_out" dev veth-sout nud permanent
        ip -n "$FW" route add 10.0.2.254/32 dev tun-out src 10.0.2.1
    fi

    # Forwarding goes on LAST, once everything that must govern it is in place.
    fw sysctl -qw net.ipv4.ip_forward=1
    [ "$mode" = nat ] && internet_up
    trap - ERR

    # Offloads would hand tunwall oversized or half-checksummed packets.
    for pair in "$IN:veth-cin" "$FW:veth-in" "$FW:veth-out" "$OUT:veth-sout" "$OUT:veth-wan"; do
        [ "$mode" = nat ] || [ "${pair##*:}" != veth-wan ] || continue
        if ! ip netns exec "${pair%%:*}" ethtool -K "${pair##*:}" tso off gso off gro off \
                tx off rx off >/dev/null 2>&1; then
            echo "netns.sh: warning: could not turn offloads off on ${pair##*:} (is ethtool installed?); TCP may misbehave" >&2
        fi
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
    up)     need_root "$@"
            case "${2:-firewall}" in firewall|kernel|nat) ;; *) echo "usage: sudo $0 up [kernel|nat]" >&2; exit 2 ;; esac
            up "${2:-firewall}" ;;
    down)   need_root "$@"; down ;;
    status) need_root "$@"; status ;;
    *) echo "usage: sudo $0 up | down | status" >&2; exit 2 ;;
esac

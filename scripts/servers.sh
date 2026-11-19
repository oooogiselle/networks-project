#!/usr/bin/env bash
# servers.sh start|stop - helper services for testing (run after ns_setup.sh).
#
#   outside 10.0.2.2:80   HTTP (python3 http.server) serving $RUN_DIR/www,
#                         including a random 1 MiB file "blob"
#   outside 10.0.2.2:53   DNS (dnsmasq): web.test -> 10.0.2.2
#   inside  10.0.1.3:22   TCP listener (stands in for SSH; rules expose it)
#   inside  10.0.1.3:3389 TCP listener (NOT exposed; must look filtered)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"

need_root

start_bg() { # name ns cmd... : start in background, record pid
    local name=$1 ns=$2; shift 2
    in_ns "$ns" "$@" >"$RUN_DIR/$name.log" 2>&1 &
    echo $! >"$RUN_DIR/$name.pid"
}

stop() {
    local f
    for f in "$RUN_DIR"/http.pid "$RUN_DIR"/dns.pid "$RUN_DIR"/ssh.pid "$RUN_DIR"/rdp.pid; do
        [ -f "$f" ] || continue
        kill "$(cat "$f")" 2>/dev/null || true
        rm -f "$f"
    done
}

start() {
    check_deps python3 dnsmasq
    ip netns list | grep -qw "$NS_OUTSIDE" || die "run scripts/ns_setup.sh first"
    stop
    mkdir -p "$RUN_DIR/www"
    head -c 1048576 /dev/urandom >"$RUN_DIR/www/blob"
    echo "hello from the outside" >"$RUN_DIR/www/index.html"

    say "HTTP on $SERVER:80"
    start_bg http "$NS_OUTSIDE" python3 -m http.server 80 --bind "$SERVER" \
        --directory "$RUN_DIR/www"
    say "DNS on $SERVER:53 (web.test -> $SERVER)"
    start_bg dns "$NS_OUTSIDE" dnsmasq --keep-in-foreground --conf-file=/dev/null \
        --no-resolv --no-hosts --bind-interfaces --listen-address="$SERVER" \
        --port=53 --address=/web.test/"$SERVER" --pid-file= --user=root
    say "TCP listeners on $CLIENT_B:22 and $CLIENT_B:3389"
    start_bg ssh "$NS_INSIDE" python3 "$HERE/listener.py" "$CLIENT_B" 22
    start_bg rdp "$NS_INSIDE" python3 "$HERE/listener.py" "$CLIENT_B" 3389

    wait_tcp "$NS_OUTSIDE" "$SERVER" 80 || die "HTTP server did not start; see $RUN_DIR/http.log"
    wait_tcp "$NS_INSIDE" "$CLIENT_B" 22 || die "listener :22 did not start; see $RUN_DIR/ssh.log"
    wait_tcp "$NS_INSIDE" "$CLIENT_B" 3389 || die "listener :3389 did not start; see $RUN_DIR/rdp.log"
    kill -0 "$(cat "$RUN_DIR/dns.pid")" 2>/dev/null || die "dnsmasq exited; see $RUN_DIR/dns.log"
    say "servers up (logs in $RUN_DIR)"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    *) die "usage: $0 start|stop" ;;
esac

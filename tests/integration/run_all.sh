#!/usr/bin/env bash
# ============================================================================
# File Name:   run_all.sh
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: End-to-end tests for the firewall in the three-namespace test
#              topology (spec section 6). Needs root. Skips (exit 0) until
#              the tun I/O program and namespace script exist.
#
# Assumed interface with Giselle's pieces (change here if hers differs):
#   scripts/netns.sh up|down   creates/removes namespaces "inside" (10.0.1.2,
#                              10.0.1.3) and "outside" (10.0.2.2, 10.0.2.3)
#                              routed only through the firewall namespace
#   build/tunwall -r <rules>   runs in the "firewall" namespace; SIGUSR1
#                              prints counters; logs to stderr
# Override with TUNWALL=, NETNS_SCRIPT=, RULES=.
# ============================================================================
set -u
cd "$(dirname "$0")/../.."
TUNWALL=${TUNWALL:-build/tunwall}
NETNS_SCRIPT=${NETNS_SCRIPT:-scripts/netns.sh}
RULES=${RULES:-config/rules.example.conf}
LOGDIR=${LOGDIR:-build/integration}

if [ ! -x "$TUNWALL" ] || [ ! -x "$NETNS_SCRIPT" ]; then
    echo "SKIP: $TUNWALL or $NETNS_SCRIPT not present yet (tun I/O and namespace setup)"
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then echo "must run as root (sudo)"; exit 1; fi

mkdir -p "$LOGDIR"
pass=0; failn=0; FW_PID=""; BG_PIDS=""

ok()   { echo "ok   $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; failn=$((failn+1)); }
check(){ # check <name> <expected: pass|fail> <cmd...>
    local name=$1 want=$2; shift 2
    if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then ok "$name"; else bad "$name (wanted $want)"; fi
}
inside()  { ip netns exec inside  "$@"; }
outside() { ip netns exec outside "$@"; }
bg()      { "$@" >/dev/null 2>&1 & BG_PIDS="$BG_PIDS $!"; }

start_fw() {
    ip netns exec firewall "$TUNWALL" -r "$RULES" 2>"$LOGDIR/tunwall.log" &
    FW_PID=$!; sleep 1
    kill -0 "$FW_PID" 2>/dev/null
}
cleanup() {
    [ -n "$FW_PID" ] && kill "$FW_PID" 2>/dev/null
    for p in $BG_PIDS; do kill "$p" 2>/dev/null; done
    "$NETNS_SCRIPT" down >/dev/null 2>&1
}
trap cleanup EXIT

"$NETNS_SCRIPT" down >/dev/null 2>&1
"$NETNS_SCRIPT" up   || { echo "namespace setup failed"; exit 1; }
start_fw || { echo "tunwall did not start; see $LOGDIR/tunwall.log"; exit 1; }

# Servers: web + DNS-like UDP echo outside, SSH-like and blocked ports inside.
SRV=$LOGDIR/www; mkdir -p "$SRV"; head -c 200000 /dev/urandom > "$SRV/index.bin"
bg ip netns exec outside python3 -m http.server 80 --bind 10.0.2.2 --directory "$SRV"
# Echoes at once, except payloads "late<N>" which are echoed after N seconds
# (used by the flow-expiry test below).
bg ip netns exec outside python3 -c '
import socket,threading
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.0.2.2",53))
while True:
    d,a=s.recvfrom(512)
    if d.startswith(b"late"):
        threading.Timer(int(d[4:]),lambda d=d,a=a:s.sendto(d,a)).start()
    else:
        s.sendto(d,a)'
bg ip netns exec inside python3 -m http.server 22   --bind 10.0.1.3
bg ip netns exec inside python3 -m http.server 3389 --bind 10.0.1.3
sleep 1

# Flow expiry: an unanswered UDP flow times out after 30 s. Two flows send a
# datagram; the server answers one after 5 s (flow alive, must arrive) and one
# after 35 s (flow expired, must be dropped). Runs in the background (~40 s)
# and is checked at the end. Set SKIP_SLOW=1 to skip.
if [ -z "${SKIP_SLOW:-}" ]; then
    ip netns exec inside python3 -c '
import socket,sys,time
def mk(p):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.0.1.2",p)); s.settimeout(0.5); return s
a,b=mk(40005),mk(40035)
a.sendto(b"late5",("10.0.2.2",53)); b.sendto(b"late35",("10.0.2.2",53))
def got(s):
    try: s.recv(64); return True
    except socket.timeout: return False
ra=rb=False; end=time.time()+40
while time.time()<end:
    ra=ra or got(a); rb=rb or got(b)
sys.exit(0 if ra and not rb else 1)' >/dev/null 2>&1 &
    EXPIRY_PID=$!
fi

udp_echo() { # udp_echo <ns> <dst> <port> : send one datagram, expect it back
    ip netns exec "$1" python3 -c '
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b"hello",(sys.argv[1],int(sys.argv[2]))); assert s.recv(16)==b"hello"' "$2" "$3"
}
tcp_open() { ip netns exec "$1" timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3"; }

echo "== allowed traffic from inside"
check "inside curl downloads page"      pass inside curl -sf --max-time 5 -o "$LOGDIR/got.bin" http://10.0.2.2/index.bin
check "downloaded bytes match (sha256)" pass bash -c "[ \"\$(sha256sum < $SRV/index.bin)\" = \"\$(sha256sum < $LOGDIR/got.bin)\" ]"
check "inside ping outside"             pass inside ping -c 2 -W 2 10.0.2.2
check "inside DNS to trusted resolver"  pass udp_echo inside 10.0.2.2 53

echo "== blocked traffic"
check "outside ping inside fails"       fail outside ping -c 2 -W 2 10.0.1.2
check "outside to inside port 3389 dropped" fail tcp_open outside 10.0.1.3 3389
check "inside web to other port dropped"    fail tcp_open inside 10.0.2.2 8080
check "inside DNS to other resolver dropped" fail udp_echo inside 10.0.2.3 53

echo "== exposed service"
check "outside reaches ssh on client B" pass tcp_open outside 10.0.1.3 22
check "outside cannot reach ssh on client A" fail tcp_open outside 10.0.1.2 22

echo "== scans (nmap)"
if command -v nmap >/dev/null; then
    open=$(outside nmap -n -Pn -p 22,80,443,3389 10.0.1.3 2>/dev/null | grep -c ' open ')
    [ "$open" = 1 ] && ok "nmap finds only the allowed port" || bad "nmap open ports = $open, wanted 1"
    ack=$(outside nmap -n -Pn -sA -p 22,3389 10.0.1.3 2>/dev/null | grep -c ' unfiltered')
    [ "$ack" = 0 ] && ok "ACK scan finds nothing unfiltered" || bad "ACK scan sees $ack unfiltered ports"
else echo "skip nmap tests (nmap not installed)"; fi

echo "== logging and stats"
kill -USR1 "$FW_PID"; sleep 1
grep -qiE "drop|denied|no matching" "$LOGDIR/tunwall.log" && ok "drops are logged with a reason" || bad "no drop reasons in log"
grep -qiE "flow" "$LOGDIR/tunwall.log" && ok "flow open/close logged" || bad "no flow lines in log"

echo "== idle flows expire"
if [ -n "${EXPIRY_PID:-}" ]; then
    echo "   (waiting for the 40 s expiry test)"
    wait "$EXPIRY_PID" && ok "late reply on an expired UDP flow is dropped, timely reply allowed" \
                       || bad "flow expiry: late reply got through or timely reply was lost"
else echo "skip expiry test (SKIP_SLOW set)"; fi

echo "== killing the firewall stops all traffic"
kill "$FW_PID"; wait "$FW_PID" 2>/dev/null; FW_PID=""
check "no traffic once tunwall is gone" fail inside curl -sf --max-time 3 -o /dev/null http://10.0.2.2/index.bin

echo; echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]

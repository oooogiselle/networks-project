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
TUNWALL_ARGS=${TUNWALL_ARGS:--d}   # -d = debug logging (per-packet DROP lines)
NETNS_SCRIPT=${NETNS_SCRIPT:-scripts/netns.sh}
RULES=${RULES:-config/rules.example.conf}

if [ ! -x "$TUNWALL" ] || [ ! -x "$NETNS_SCRIPT" ]; then
    echo "$TUNWALL or $NETNS_SCRIPT not present yet (tun I/O and namespace setup)"
    # CI sets REQUIRE_INTEGRATION=1 so a missing piece is a failure, not a pass.
    if [ -n "${REQUIRE_INTEGRATION:-}" ]; then echo "FAIL: integration tests required but cannot run"; exit 1; fi
    echo "SKIP (set REQUIRE_INTEGRATION=1 to make this an error)"
    exit 0
fi
if [ "$(id -u)" -ne 0 ]; then echo "must run as root (sudo)"; exit 1; fi

# Private scratch dir (mode 0700) so root never writes through a planted path.
# Set LOGDIR to keep logs somewhere specific (it must not be a symlink).
if [ -z "${LOGDIR:-}" ]; then LOGDIR=$(mktemp -d /tmp/tunwall-it.XXXXXX) || exit 1
elif [ -L "$LOGDIR" ]; then echo "LOGDIR must not be a symlink"; exit 1
else mkdir -p "$LOGDIR" || exit 1; fi
chmod 700 "$LOGDIR"
echo "logs: $LOGDIR"
pass=0; failn=0; FW_PID=""; BG_PIDS=""

ok()   { echo "ok   $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; failn=$((failn+1)); }
check(){ # check <name> <expected: pass|fail> <cmd...>
    local name=$1 want=$2; shift 2
    if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then ok "$name"; else bad "$name (wanted $want)"; fi
}
expect(){ # expect <name> <wanted outcome> <command printing an outcome...>
    local name=$1 want=$2; shift 2
    local got; got=$("$@" 2>/dev/null | tail -1)
    if [ "$got" = "$want" ]; then ok "$name"; else bad "$name (wanted '$want', got '${got:-nothing}')"; fi
}
logged(){ # logged <name> <extended regex>: the firewall log must contain a matching line
    if grep -Eq "$2" "$LOGDIR/tunwall.log"; then ok "log: $1"; else bad "log: $1 (no line matching: $2)"; fi
}
not_logged(){ # not_logged <name> <regex>
    if grep -Eq "$2" "$LOGDIR/tunwall.log"; then bad "log: $1 (unexpected line matching: $2)"; else ok "log: $1"; fi
}
probe(){ ip netns exec "$1" python3 tests/integration/probe.py "$2" "$3" "$4"; }
icmp_probe(){ # reply | refused (ICMP unreachable) | timeout (silent drop)
    local out; out=$(ip netns exec "$1" ping -c 2 -W 2 "$2" 2>&1)
    if echo "$out" | grep -qiE "unreachable|prohibited"; then echo refused
    elif echo "$out" | grep -qE " 0% packet loss"; then echo reply
    elif echo "$out" | grep -qE "100% packet loss"; then echo timeout
    else echo "mixed"; fi
}
inside()  { ip netns exec inside  "$@"; }
outside() { ip netns exec outside "$@"; }
bg()      { "$@" >/dev/null 2>&1 & BG_PIDS="$BG_PIDS $!"; }

start_fw() {
    ip netns exec firewall "$TUNWALL" -r "$RULES" $TUNWALL_ARGS 2>"$LOGDIR/tunwall.log" &
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
EMPTY=$LOGDIR/empty; mkdir -p "$EMPTY"   # served directory: nothing sensitive
bg ip netns exec inside python3 -m http.server 22   --bind 10.0.1.3 --directory "$EMPTY"
bg ip netns exec inside python3 -m http.server 3389 --bind 10.0.1.3 --directory "$EMPTY"
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

# Note on the expectations below: "timeout" means the packet was silently
# dropped. "refused" or "unreachable" would mean the firewall answered with a
# RST or ICMP error, which the spec forbids (ports must look filtered).
same_sha256() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
need_tool() { # in CI (REQUIRE_INTEGRATION) a missing tool is a failure, not a skip
    command -v "$1" >/dev/null && return 0
    if [ -n "${REQUIRE_INTEGRATION:-}" ]; then bad "$1 is not installed"; else echo "skip: $1 not installed"; fi
    return 1
}

echo "== allowed traffic from inside"
check  "inside curl downloads page"      pass inside curl -sf --max-time 5 -o "$LOGDIR/got.bin" http://10.0.2.2/index.bin
check  "downloaded bytes match (sha256)" pass same_sha256 "$SRV/index.bin" "$LOGDIR/got.bin"
expect "inside ping outside gets replies" reply icmp_probe inside 10.0.2.2
expect "inside DNS to trusted resolver"   reply probe inside udp 10.0.2.2 53

echo "== blocked traffic is silently dropped (not refused)"
expect "outside ping to inside"            timeout icmp_probe outside 10.0.1.2
expect "outside to inside port 3389"       timeout probe outside tcp 10.0.1.3 3389
expect "inside web to non-allowed port"    timeout probe inside  tcp 10.0.2.2 8080
expect "inside DNS to untrusted resolver"  timeout probe inside  udp 10.0.2.3 53
expect "outside to ssh on client A (no rule)" timeout probe outside tcp 10.0.1.2 22

echo "== exposed service"
expect "outside reaches ssh on client B"   open probe outside tcp 10.0.1.3 22

echo "== scans (nmap)"
# Each scan must finish ("Nmap done") so empty output cannot pass, and the
# counts below are exact: every probed port is filtered / open|filtered
# (silent drop) and none is "closed" (which would mean a RST came back).
nmap_scan() { # nmap_scan <nmap flags...> -> output on stdout, fails if nmap did not finish
    local out; out=$(outside nmap -n -Pn "$@" 10.0.1.3 2>&1)
    echo "$out" | grep -q "Nmap done" || return 1
    echo "$out"
}
scan_expect() { # scan_expect <name> <state regex> <count wanted> <nmap flags...>
    local name=$1 state=$2 want=$3; shift 3
    local out; out=$(nmap_scan "$@") || { bad "$name (nmap did not finish)"; return; }
    local got; got=$(echo "$out" | grep -cE "$state")
    local closed; closed=$(echo "$out" | grep -cE '[0-9]+/(tcp|udp) +closed')
    if [ "$got" = "$want" ] && [ "$closed" = 0 ]; then ok "$name"
    else bad "$name (wanted $want x '$state', got $got; $closed closed)"; fi
}
if need_tool nmap; then
    scan_expect "SYN scan: only the allowed port is open" '[0-9]+/tcp +open +' 1 -sS -p 22,80,443,3389
    scan_expect "SYN scan: the other 3 ports are filtered" '[0-9]+/tcp +filtered' 3 -sS -p 22,80,443,3389
    scan_expect "ACK scan: both ports filtered, none unfiltered" '[0-9]+/tcp +filtered' 2 -sA -p 22,3389
    scan_expect "FIN scan: open|filtered, no RST" '[0-9]+/tcp +open\|filtered' 2 -sF -p 22,3389
    scan_expect "NULL scan: open|filtered, no RST" '[0-9]+/tcp +open\|filtered' 2 -sN -p 22,3389
    scan_expect "Xmas scan: open|filtered, no RST" '[0-9]+/tcp +open\|filtered' 2 -sX -p 22,3389
fi

echo "== logging and stats"
kill -USR1 "$FW_PID"; sleep 1

logged "flow opened for the allowed web request" 'FLOW NEW +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 '
logged "flow opened for the exposed ssh connection" 'FLOW NEW +tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:22 '
logged "inbound 3389 dropped for no matching rule" 'DROP tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:3389 .*why=no-rule\(default-deny\)'
logged "outbound port 8080 dropped for no matching rule" 'DROP tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:8080 .*why=no-rule\(default-deny\)'
logged "DNS to other resolver dropped by the deny rule" 'DROP udp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.3:53 .*why=rule-deny'
logged "inbound ping dropped for no matching rule" 'DROP icmp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.2:[0-9]+ .*why=no-rule\(default-deny\)'
not_logged "allowed web traffic is never dropped by a rule" 'DROP tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 .*why=(no-rule|rule-deny)'
not_logged "allowed ssh is never dropped by a rule" 'DROP tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:22 .*why=(no-rule|rule-deny)'
logged "stats: default-deny count printed" '^drop\[no-rule\(default-deny\)\]=[1-9][0-9]*'
logged "stats: rule-deny count printed" '^drop\[rule-deny\]=[1-9][0-9]*'
logged "stats: flows were created" '^flows: +created=[1-9][0-9]* '

echo "== idle flows expire"
if [ -n "${EXPIRY_PID:-}" ]; then
    echo "   (waiting for the 40 s expiry test)"
    wait "$EXPIRY_PID" && ok "late reply on an expired UDP flow is dropped, timely reply allowed" \
                       || bad "flow expiry: late reply got through or timely reply was lost"
    logged "the slow UDP flow was expired" 'FLOW EXPIRE +udp 10\.0\.1\.2:40035 -> 10\.0\.2\.2:53 '
    logged "the late reply was dropped" 'DROP udp 10\.0\.2\.2:53 -> 10\.0\.1\.2:40035 .*why=no-rule\(default-deny\)'
else echo "skip expiry test (SKIP_SLOW set)"; fi

echo "== killing the firewall stops all traffic"
kill "$FW_PID"; wait "$FW_PID" 2>/dev/null; FW_PID=""
expect "web connection times out once tunwall is gone" timeout probe inside tcp 10.0.2.2 80
expect "ping times out once tunwall is gone"           timeout icmp_probe inside 10.0.2.2

echo; echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]

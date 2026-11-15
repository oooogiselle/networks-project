#!/usr/bin/env bash
# ============================================================================
# File Name:   run_all.sh
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: End-to-end tests for the firewall in the three-namespace test
#              topology (spec section 6). Needs root. Skips locally (exit 0)
#              if build/tunwall or scripts/netns.sh is missing; with
#              REQUIRE_INTEGRATION=1 (CI) a missing piece is a failure.
#
# Uses:
#   scripts/netns.sh up|down   creates/removes namespaces "inside" (10.0.1.2,
#                              10.0.1.3), "firewall" and "outside" (10.0.2.2,
#                              10.0.2.3), routed only through the firewall
#   build/tunwall -r <rules>   runs in the "firewall" namespace; logs flows and
#                              drops to stderr; SIGUSR1 prints counters
# Override with TUNWALL=, NETNS_SCRIPT=, RULES=, TUNWALL_ARGS=, LOGDIR=.
# ============================================================================
set -u
cd "$(dirname "$0")/../.."
TUNWALL=${TUNWALL:-build/tunwall}
TUNWALL_ARGS=${TUNWALL_ARGS:-}   # logging of flows and drops is on by default
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

# ---- the command line (needs neither the topology nor a running firewall) ----
cli_says() { # cli_says <name> <wanted exit code> <regex for the output> <tunwall args...>
    local name=$1 rc=$2 re=$3; shift 3
    "$TUNWALL" "$@" > "$LOGDIR/cli.out" 2>&1; local got=$?
    if [ "$got" = "$rc" ] && grep -Eq "$re" "$LOGDIR/cli.out"; then ok "cli: $name"
    else bad "cli: $name (exit $got, wanted $rc; output: $(head -c 200 "$LOGDIR/cli.out" | tr '\n' ' '))"; fi
}
printf 'inside 10.0.1.0/24\nallow bogus\n' > "$LOGDIR/bad.conf"
printf 'allow out tcp any any 80\n' > "$LOGDIR/noinside.conf"
cli_says "no arguments prints usage and exits 2"          2 'usage: tunwall'
cli_says "-h prints usage and exits 0"                    0 'usage: tunwall' -h
cli_says "an unknown option exits 2"                      2 'usage: tunwall' -z
cli_says "an extra argument exits 2"                      2 'usage: tunwall' -r "$RULES" extra
cli_says "a missing rules file names the file, exit 1"    1 '/nonexistent/rules\.conf: cannot open file' -r /nonexistent/rules.conf
cli_says "a syntax error names the file and the line"     1 'bad\.conf: line 2: ' -r "$LOGDIR/bad.conf"
cli_says "no inside network is refused with the reason"   1 'noinside\.conf: declares no inside network' -r "$LOGDIR/noinside.conf"
cli_says "a missing tun device is refused with a hint"    1 'tw-missing0: no such device.*netns\.sh' -r "$RULES" -i tw-missing0

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
a,b,c=mk(40005),mk(40035),mk(40100)
a.sendto(b"late5",("10.0.2.2",53)); b.sendto(b"late35",("10.0.2.2",53)); c.sendto(b"early",("10.0.2.2",53))
def got(s):
    try: s.recv(64); return True
    except socket.timeout: return False
ra=rb=rc0=rc1=resent=False; start=time.time(); end=start+40
while time.time()<end:
    ra=ra or got(a); rb=rb or got(b)
    if not rc0: rc0=got(c)
    if rc0 and not resent and time.time()-start>=35: c.sendto(b"again",("10.0.2.2",53)); resent=True
    if resent: rc1=rc1 or got(c)
# a: timely reply allowed; b: reply after the 30 s timeout dropped;
# c: an ANSWERED flow lives on (120 s timeout), so a datagram at 35 s still works
sys.exit(0 if ra and not rb and rc0 and rc1 else 1)' >/dev/null 2>&1 &
    EXPIRY_PID=$!

    # Half-close: the client sends its request and shuts down its sending side;
    # the server answers only after 75 s (longer than the old 60 s FIN_WAIT).
    bg ip netns exec outside python3 -c '
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.2.3",80)); s.listen(1); s.settimeout(120)
c,_=s.accept(); buf=b""
while True:
    d=c.recv(4096)
    if not d: break
    buf+=d
time.sleep(75); c.sendall(b"answer:"+buf); c.close()'
    sleep 1
    ip netns exec inside python3 -c '
import socket,sys
s=socket.create_connection(("10.0.2.3",80),timeout=110)
s.sendall(b"request"*1000); s.shutdown(socket.SHUT_WR)
data=b""
while True:
    d=s.recv(4096)
    if not d: break
    data+=d
sys.exit(0 if data.startswith(b"answer:") and len(data)>7000 else 1)' >/dev/null 2>&1 &
    HALFCLOSE_PID=$!
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
    local out; out=$(outside nmap -n -Pn "$@" "${SCAN_TARGET:-10.0.1.3}" 2>&1)
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
    scan_expect "UDP scan: open|filtered, no ICMP unreachable" '[0-9]+/udp +open\|filtered' 2 -sU --max-retries 1 -p 53,161
fi

echo "== the firewall's own addresses are not a way around it"
bg ip netns exec firewall python3 -m http.server 8080 --bind 0.0.0.0 --directory "$EMPTY"
sleep 1
expect "outside cannot reach a service on the firewall (10.0.2.1)" timeout probe outside tcp 10.0.2.1 8080
expect "outside cannot reach a service on the firewall (10.0.1.1)" timeout probe outside tcp 10.0.1.1 8080
expect "inside cannot reach it either (10.0.1.1)"                  timeout probe inside  tcp 10.0.1.1 8080
if need_tool nmap; then
    # nmap folds an all-filtered result into one "Not shown" line, so check the
    # substance: the scan finished, ports were filtered, none open and none closed.
    for tgt in 10.0.2.1 10.0.1.1; do
        out=$(outside nmap -n -Pn --send-ip -sS -p 22,80,8080 $tgt 2>&1)
        if echo "$out" | grep -q "Nmap done" && echo "$out" | grep -q "filtered" &&
           ! echo "$out" | grep -qE '[0-9]+/tcp +(open|closed)'; then
            ok "nmap of the firewall's own address $tgt: every port filtered"
        else bad "nmap of the firewall's own address $tgt did not show all ports filtered"; fi
    done
fi

echo "== TTL and path MTU"
ttl_probe() { # ttl_probe <ttl>: reply | ttl-exceeded | timeout
    local out; out=$(ip netns exec inside ping -t "$1" -c 2 -W 2 10.0.2.2 2>&1)
    if echo "$out" | grep -qi "time to live exceeded"; then echo ttl-exceeded
    elif echo "$out" | grep -qE " 0% packet loss"; then echo reply
    else echo timeout; fi
}
mtu_probe() { # mtu_probe <payload size>: reply | frag-needed | timeout (DF set)
    local out; out=$(ip netns exec inside ping -M do -s "$1" -c 2 -W 2 10.0.2.2 2>&1)
    if echo "$out" | grep -qiE "frag needed|message too long"; then echo frag-needed
    elif echo "$out" | grep -qE " 0% packet loss"; then echo reply
    else echo timeout; fi
}
expect "TTL 1 expires at the firewall (hop 1)"                       ttl-exceeded ttl_probe 1
expect "TTL 2 gets through: the firewall counts as ONE hop, not two" reply ttl_probe 2
ip -n firewall link set veth-out mtu 1400
expect "a DF packet that fits the 1400-byte link passes"             reply mtu_probe 1372
expect "a larger DF packet is told 'fragmentation needed'"           frag-needed mtu_probe 1400
ip -n firewall link set veth-out mtu 1500

echo "== logging and stats"
kill -USR1 "$FW_PID"; sleep 1

logged "flow opened for the allowed web request" 'FLOW NEW +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 '
logged "flow opened for the exposed ssh connection" 'FLOW NEW +tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:22 '
logged "inbound 3389 dropped for no matching rule" 'DROP tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:3389 .*why=no-rule\(default-deny\)'
logged "outbound port 8080 dropped for no matching rule" 'DROP tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:8080 .*why=no-rule\(default-deny\)'
logged "DNS to other resolver dropped by the deny rule" 'DROP udp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.3:53 .*why=rule-deny'
logged "TCP close logged for the web download" 'FLOW CLOSE +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 state=(TIME_WAIT|CLOSED)'
logged "probes of the firewall's own addresses were dropped by tunwall" 'DROP tcp 10\.0\.[12]\.[0-9]+:[0-9]+ -> 10\.0\.[12]\.1:8080 .*why=(no-rule|wrong-destination)'
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
if [ -n "${HALFCLOSE_PID:-}" ]; then
    echo "   (waiting for the 75 s half-close test)"
    wait "$HALFCLOSE_PID" && ok "a half-closed connection survives a 75 s wait for the server's answer" \
                          || bad "half-close: the server's late answer did not arrive (flow expired?)"
fi

echo "== killing the firewall stops all traffic"
kill "$FW_PID"; wait "$FW_PID"; rc=$?; FW_PID=""
[ "$rc" = 0 ] && ok "tunwall exits 0 on SIGTERM" || bad "tunwall exited $rc on SIGTERM"
logged "counters are printed when it exits" '^io: +rx in=[0-9]+ out=[0-9]+ forwarded in=[0-9]+ out=[0-9]+ write-errors=0'
logged "log suppression is reported with the counters" '^log: +suppressed=[0-9]+'
expect "web connection times out once tunwall is gone" timeout probe inside tcp 10.0.2.2 80
expect "ping times out once tunwall is gone"           timeout icmp_probe inside 10.0.2.2

echo "== the topology stays closed if a tun device disappears"
leak_probe() { # does a datagram from inside reach the outside? arrived | none
    ip netns exec outside timeout 6 python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.0.2.2",9999)); s.settimeout(3)
try: s.recvfrom(64); print("arrived")
except socket.timeout: print("none")' > "$LOGDIR/leak.out" &
    local lp=$!; sleep 1
    ip netns exec inside timeout 3 python3 -c 'import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b"leak",("10.0.2.2",9999))'
    wait "$lp"; tail -1 "$LOGDIR/leak.out"
}
# Control: without the terminal blackhole rule a deleted tun device lets the
# kernel forward directly, and the probe sees it. Then the rule goes back.
ip -n firewall rule del iif veth-in blackhole pref 102
ip netns exec firewall ip tuntap del dev tun-in mode tun
expect "control: without the blackhole rule traffic leaks (the probe works)" arrived leak_probe
ip -n firewall rule add iif veth-in blackhole pref 102
expect "with the blackhole rule nothing gets through a deleted tun-in"       none leak_probe

echo; echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]

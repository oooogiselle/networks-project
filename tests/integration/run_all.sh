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
# INTERNET=1 also builds the NAT path ("netns.sh up nat") and tests the real
# Internet through the firewall; it needs the host to be online and changes the
# host's iptables while it runs (removed again afterwards). Off by default, so
# CI and offline runs are unaffected.
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
# Wait (up to 10 s) until a server is really listening, instead of hoping a fixed
# sleep was long enough. A server that never comes up is reported as such.
# Ask tunwall for its counters and wait until they are really in the log.
dump_stats() {
    local before i
    before=$(grep -c "^packets: total=" "$LOGDIR/tunwall.log")
    kill -USR1 "$FW_PID"
    for i in $(seq 1 50); do
        [ "$(grep -c "^packets: total=" "$LOGDIR/tunwall.log")" -gt "$before" ] && return 0
        sleep 0.1
    done
    bad "tunwall did not print its counters after SIGUSR1"
}

wait_listen() { # wait_listen <ns> tcp|udp <ip> <port> <what>
    local ns=$1 proto=$2 ip=$3 port=$4 what=$5 flag=-ltnH i
    [ "$proto" = udp ] && flag=-lunH
    for i in $(seq 1 100); do
        ip netns exec "$ns" ss $flag 2>/dev/null | awk '{print $4}' | grep -qx "$ip:$port" && return 0
        sleep 0.1
    done
    bad "$what never started listening on $ip:$port (namespace $ns)"
    return 1
}

# When a check has failed, print what is needed to see why, into the job log
# (a bare list of failed checks says what broke, not why).
diagnostics() {
    echo; echo "================ diagnostics: a check failed ================"
    echo "--- kernel and tools"
    uname -r; python3 --version 2>&1; ip -V 2>&1
    echo "present: $(command -v ethtool ss nstat openssl nmap curl 2>/dev/null | tr '\n' ' ')"
    echo "--- firewall log, last 60 lines ($LOGDIR/tunwall.log)"
    tail -n 60 "$LOGDIR/tunwall.log" 2>&1
    echo "--- tunwall still running? $(kill -0 "$FW_PID" 2>/dev/null && echo yes || echo no)"
    local ns
    for ns in inside firewall outside; do
        echo "--- $ns: addresses and listening sockets"
        ip -n "$ns" -br addr 2>&1
        ip netns exec "$ns" ss -ltunp 2>&1 | head -20
    done
    echo "--- firewall: policy rules, tun routes, neighbours"
    ip -n firewall rule 2>&1
    ip -n firewall route show table 100 2>&1; ip -n firewall route show table 200 2>&1
    ip -n firewall neigh 2>&1; ip -n inside neigh 2>&1; ip -n outside neigh 2>&1
    echo "--- firewall: link counters (look for dropped / errors on the tun devices)"
    ip netns exec firewall ip -s link show 2>&1 | grep -vE "^\s+(link/|altname)" | head -40
    echo "--- offloads on the firewall's veth-in"
    ip netns exec firewall ethtool -k veth-in 2>&1 | grep -E "^(tx|rx)-checksumming|segmentation-offload|receive-offload" | head -6
    echo "--- TCP counters seen by the inside and outside hosts"
    for ns in inside outside; do
        echo "($ns)"; ip netns exec "$ns" nstat -az TcpAttemptFails TcpOutRsts TcpRetransSegs TcpInCsumErrors IpInHdrErrors 2>&1 | head -8
    done
    echo "============================================================="
}

inside()  { ip netns exec inside  "$@"; }
outside() { ip netns exec outside "$@"; }
bg()      { "$@" >/dev/null 2>&1 & BG_PIDS="$BG_PIDS $!"; }

start_fw() {
    ip netns exec firewall "$TUNWALL" -r "$RULES" $TUNWALL_ARGS 2>"$LOGDIR/tunwall.log" &
    FW_PID=$!
    # wait until it says it is running (it has attached both tun devices), not a fixed second
    local i
    for i in $(seq 1 100); do
        kill -0 "$FW_PID" 2>/dev/null || return 1
        grep -q "^tunwall: running" "$LOGDIR/tunwall.log" 2>/dev/null && return 0
        sleep 0.1
    done
    kill -0 "$FW_PID" 2>/dev/null           # quiet (-q) runs never print the line
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
"$NETNS_SCRIPT" up ${INTERNET:+nat} || { echo "namespace setup failed"; exit 1; }
start_fw || { echo "tunwall did not start; see $LOGDIR/tunwall.log"; cat "$LOGDIR/tunwall.log"; exit 1; }

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
wait_listen outside tcp 10.0.2.2 80   "the outside web server"
wait_listen outside udp 10.0.2.2 53   "the outside DNS echo server"
wait_listen inside  tcp 10.0.1.3 22   "the inside ssh-like server"
wait_listen inside  tcp 10.0.1.3 3389 "the inside rdp-like server"

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
    wait_listen outside tcp 10.0.2.3 80 "the half-close server"
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

echo "== sanity: a TCP connection from inside reaches an outside server"
for _ in 1 2 3 4 5; do
    pre=$(probe inside tcp 10.0.2.2 80)
    [ "$pre" = open ] && break
    sleep 1
done
if [ "$pre" = open ]; then ok "inside can open a TCP connection to the outside web server"
else bad "inside could not open a TCP connection to the outside web server (got '$pre')"; diagnostics; fi

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
wait_listen firewall tcp 0.0.0.0 8080 "the test service on the firewall itself"
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

echo "== application identification (by payload, not by port)"
# Real traffic of each kind: HTTP on its port, a real TLS handshake on 443, HTTP
# on port 443 (the port says TLS, the payload says HTTP), and a real DNS query.
if need_tool openssl; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -keyout "$LOGDIR/tls.key" -out "$LOGDIR/tls.crt" -subj /CN=tunwall-test >/dev/null 2>&1
    bg ip netns exec outside python3 -c '
import functools, http.server, ssl, sys
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[3])
srv = http.server.HTTPServer(("10.0.2.2", 443), h)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()' "$LOGDIR/tls.crt" "$LOGDIR/tls.key" "$EMPTY"
    wait_listen outside tcp 10.0.2.2 443 "the TLS server"
    check "real TLS handshake and request through the firewall" pass inside curl -sk --max-time 5 -o /dev/null https://10.0.2.2:443/
fi
bg ip netns exec outside python3 -m http.server 443 --bind 10.0.2.3 --directory "$EMPTY"
wait_listen outside tcp 10.0.2.3 443 "the plain HTTP server on port 443"
check "plain HTTP on port 443 passes (the port is allowed)" pass inside curl -s --max-time 5 -o /dev/null http://10.0.2.3:443/
dns_query() { ip netns exec inside python3 -c '
import socket, struct
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(q, ("10.0.2.2", 53)); assert s.recv(512) == q'; }
check "a real DNS query is answered" pass dns_query

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
dump_stats

logged "flow opened for the allowed web request" 'FLOW NEW +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 '
logged "flow opened for the exposed ssh connection" 'FLOW NEW +tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:22 '
logged "inbound 3389 dropped for no matching rule" 'DROP tcp 10\.0\.2\.[0-9]+:[0-9]+ -> 10\.0\.1\.3:3389 .*why=no-rule\(default-deny\)'
logged "outbound port 8080 dropped for no matching rule" 'DROP tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:8080 .*why=no-rule\(default-deny\)'
logged "DNS to other resolver dropped by the deny rule" 'DROP udp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.3:53 .*why=rule-deny'
logged "the web download is labelled http" 'FLOW APP +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 .*app=http'
if command -v openssl >/dev/null; then
    logged "the TLS handshake is labelled tls" 'FLOW APP +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:443 .*app=tls dur'
fi
logged "the DNS query is labelled dns" 'FLOW APP +udp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:53 .*app=dns'
logged "HTTP on port 443 is flagged: payload disagrees with port" 'FLOW APP +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.3:443 .*app=http dur.* mismatch\(port suggests tls\)'
not_logged "HTTP on its own port is not flagged" 'FLOW APP +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:80 .*mismatch'
logged "stats: the labelled flows are counted" '^apps: +http=[1-9][0-9]* tls=[0-9]+ dns=[1-9][0-9]* other=[0-9]+ mismatched=[1-9][0-9]*'
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

if [ -n "${INTERNET:-}" ]; then
    echo "== the real Internet through the firewall"
    # example.com is static, so the page fetched through the firewall must be
    # byte for byte the one the host fetches directly. The address is resolved on
    # the host and pinned with --resolve, so this does not depend on DNS.
    EX_IP=$(getent ahostsv4 example.com | awk 'NR==1 {print $1}')
    if [ -z "$EX_IP" ] || ! curl -s -m 8 -o /dev/null "http://example.com"; then
        bad "the host itself cannot reach example.com, so INTERNET=1 cannot be tested"
    else
        expect "ping a real Internet address (1.1.1.1) through the firewall" reply icmp_probe inside 1.1.1.1
        for scheme in http https; do
            port=$([ $scheme = http ] && echo 80 || echo 443)
            via=$(ip netns exec inside curl -s -m 15 --resolve example.com:$port:$EX_IP $scheme://example.com/ | sha256sum)
            direct=$(curl -s -m 15 --resolve example.com:$port:$EX_IP $scheme://example.com/ | sha256sum)
            if [ "$via" = "$direct" ] && [ "$via" != "$(printf '' | sha256sum)" ]; then
                ok "$scheme://example.com through the firewall is byte for byte the direct page (SHA-256 ${via:0:16})"
            else bad "$scheme://example.com differs through the firewall (via $via, direct $direct)"; fi
        done
        expect "a non-web port on the Internet is silently dropped (not refused)" timeout probe inside tcp "$EX_IP" 8080
        expect "SSH to the Internet is silently dropped"                            timeout probe inside tcp "$EX_IP" 22
        expect "outside cannot start a connection to the inside via the NAT path"   timeout probe outside tcp 10.0.1.3 3389
        dump_stats
        logged "the real HTTP flow is labelled http" "FLOW APP +tcp 10\\.0\\.1\\.2:[0-9]+ -> $EX_IP:80 .*app=http"
        logged "the real HTTPS flow is labelled tls" "FLOW APP +tcp 10\\.0\\.1\\.2:[0-9]+ -> $EX_IP:443 .*app=tls"
        logged "the dropped SSH attempt is logged with its reason" "DROP tcp 10\\.0\\.1\\.2:[0-9]+ -> $EX_IP:22 .*why=no-rule"
    fi
fi

echo "== source NAT (tunwall -n 10.0.2.254)"
# Restart the firewall with source NAT on and its own rule file (the example
# rules plus TCP 8000, for a server that reports who connected to it). The
# outside loses its route back to the inside, so a reply can only come back
# through the NAT address: if translation failed, nothing would work.
NATIP=10.0.2.254
cp "$LOGDIR/tunwall.log" "$LOGDIR/tunwall-before-nat.log"
kill "$FW_PID"; wait "$FW_PID" 2>/dev/null; FW_PID=""
printf '%s\n' 'inside 10.0.1.0/24' \
    'allow out tcp  10.0.1.0/24 any 80,443,8000' \
    'allow out udp  10.0.1.0/24 10.0.2.2 53' \
    'allow out icmp 10.0.1.0/24 any echo' \
    'allow in  tcp  any 10.0.1.3 22' > "$LOGDIR/nat.conf"
SAVED_RULES=$RULES; SAVED_ARGS=$TUNWALL_ARGS
RULES=$LOGDIR/nat.conf; TUNWALL_ARGS="$TUNWALL_ARGS -n $NATIP"
if start_fw; then
    ok "tunwall starts with source NAT"
    logged "it says NAT is on" "^tunwall: running .*source NAT to $NATIP"
    ip -n outside route replace unreachable 10.0.1.0/24
    expect "control: the outside cannot reach the inside directly any more" unreachable probe outside tcp 10.0.1.3 22

    # A server that answers each connection with the address it came from.
    bg ip netns exec outside python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.2.2",8000)); s.listen(8)
while True:
    c,a=s.accept(); c.sendall(a[0].encode()); c.close()'
    wait_listen outside tcp 10.0.2.2 8000 "the who-am-i server"
    peer=$(inside python3 -c 'import socket; s=socket.create_connection(("10.0.2.2",8000),5); print(s.recv(64).decode())' 2>/dev/null)
    [ "$peer" = "$NATIP" ] && ok "the outside sees the connection come from $NATIP, not the inside host" \
                           || bad "the outside saw the connection come from '${peer:-nothing}', wanted $NATIP"
    check  "inside curl downloads the page through NAT"        pass inside curl -sf --max-time 5 -o "$LOGDIR/got-nat.bin" http://10.0.2.2/index.bin
    check  "the page is byte for byte the same (sha256)"       pass same_sha256 "$SRV/index.bin" "$LOGDIR/got-nat.bin"
    expect "ping through NAT gets replies"                      reply icmp_probe inside 10.0.2.2
    expect "DNS (UDP) through NAT gets an answer"               reply probe inside udp 10.0.2.2 53
    expect "an unsolicited connection to the NAT address is silently dropped" timeout probe outside tcp $NATIP 22
    expect "an unsolicited ping to the NAT address is silently dropped"       timeout icmp_probe outside $NATIP
    # Path MTU through NAT: the firewall's kernel reports "fragmentation
    # needed" to the translated source; tunwall must translate the ICMP error
    # (its embedded header included) back to the inside host.
    ip -n firewall link set veth-out mtu 1400
    expect "through NAT, a DF packet that fits the 1400-byte link passes"   reply mtu_probe 1372
    expect "through NAT, a larger DF packet is told 'fragmentation needed'" frag-needed mtu_probe 1400
    ip -n firewall link set veth-out mtu 1500
    ip -n outside route replace 10.0.1.0/24 via 10.0.2.1
    expect "the exposed service still works with NAT on (not translated)" open probe outside tcp 10.0.1.3 22

    dump_stats
    logged "flows are logged with the real inside address" 'FLOW NEW +tcp 10\.0\.1\.2:[0-9]+ -> 10\.0\.2\.2:8000 '
    logged "NAT counters are printed" "^nat: +addr=$NATIP mappings active=[0-9]+ created=[1-9][0-9]* .*translated out=[1-9][0-9]* in=[1-9][0-9]* icmp-errors=[1-9][0-9]* dropped no-mapping=[1-9][0-9]*"
else
    bad "tunwall did not start with -n $NATIP"; cat "$LOGDIR/tunwall.log"
fi
RULES=$SAVED_RULES; TUNWALL_ARGS=$SAVED_ARGS

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
    local lp=$!
    wait_listen outside udp 10.0.2.2 9999 "the leak-probe listener" || true
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

if [ -n "${INTERNET:-}" ]; then
    echo "== tearing down restores the host"
    "$NETNS_SCRIPT" down >/dev/null 2>&1
    [ "$(iptables -S FORWARD | grep -c tunwall-demo)$(iptables -t nat -S POSTROUTING | grep -c tunwall-demo)" = "00" ] \
        && ok "no tunwall-demo iptables rule is left on the host" || bad "tunwall-demo iptables rules are still there"
    ip link show veth-host >/dev/null 2>&1 && bad "veth-host is still there" || ok "the host-side veth is gone"
    [ ! -e /run/tunwall-netns ] && [ ! -e /etc/netns/inside/resolv.conf ] \
        && ok "the saved state and resolv.conf files are gone" || bad "state or resolv.conf files were left behind"
fi

[ "$failn" -eq 0 ] || diagnostics

echo; echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]

#!/usr/bin/env bash
# ============================================================================
# File Name:   demo_steps.sh
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: The narrated steps of the demo (started by scripts/demo.sh in the
#              lower tmux pane). Each step says what to watch for in the
#              firewall log above, runs the real command, and CHECKS the result
#              and the matching log line, printing a tick or a cross. It waits
#              for Enter before each step so the presenter controls the pace.
#              DEMO_AUTO=1 runs every step without waiting and exits non-zero
#              if any check failed; DEMO_LOG is the firewall's log file.
# ============================================================================
set -u
cd "$(dirname "$0")/.."
AUTO=${DEMO_AUTO:-}
LOG=${DEMO_LOG:-}
TOTAL=13

B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; C=$'\033[36m'; Z=$'\033[0m'
pass=0; failn=0; n=0

inside()  { sudo ip netns exec inside  "$@"; }
outside() { sudo ip netns exec outside "$@"; }

step() { # step "title" "line of narration" ...
    n=$((n + 1))
    echo; echo "${B}${C}== Step $n/$TOTAL: $1${Z}"
    shift
    for line in "$@"; do echo "   ${D}$line${Z}"; done
    if [ -z "$AUTO" ]; then read -rp $'\n   ▶ press Enter to run this step ' _; fi
    echo
}
cmd()   { echo "   ${B}\$ $*${Z}"; }
say()   { echo "   $*"; }
good()  { pass=$((pass + 1)); echo "   ${G}✔ $*${Z}"; }
bad()   { failn=$((failn + 1)); echo "   ${R}✘ $*${Z}"; }
check() { local label=$1; shift; if "$@"; then good "$label"; else bad "$label"; fi; }

# the firewall log is written by another process: give it a moment
log_has() {
    [ -n "$LOG" ] || return 0
    local i
    for i in 1 2 3 4 5 6 7 8; do grep -Eq -- "$1" "$LOG" && return 0; sleep 0.4; done
    return 1
}
contains() { case $1 in *"$2"*) return 0;; *) return 1;; esac; }
sha() { sha256sum | cut -c1-24; }

echo "${B}tunwall: a stateful firewall in userspace${Z}"
echo "${D}Every packet between the two networks passes through our program. Watch the log above.${Z}"

# ---------------------------------------------------------------------------
step "The setup and the policy" \
     "Three network namespaces. Every packet crossing between inside and outside is" \
     "routed into a tun device, read by our program, and written out only if allowed." \
     "Anything not matched by a rule is dropped."
cat <<'ART'
   inside                  firewall                         outside
   10.0.1.2, 10.0.1.3 --- veth-in   veth-out --- 10.0.2.2, 10.0.2.3 --- NAT --- Internet
                          tun-in <- tunwall -> tun-out
ART
echo
cmd "grep -vE '^(#|\$)' config/rules.example.conf"
grep -vE '^(#|$)' config/rules.example.conf | sed 's/^/     /'

# ---------------------------------------------------------------------------
step "A client inside can ping the real Internet" \
     "Allowed by 'allow out icmp ... echo'. The reply is allowed back because it" \
     "matches the flow the request created. Log: a green FLOW NEW for icmp."
cmd "ping -c 3 1.1.1.1      (from the inside namespace)"
out=$(inside ping -c 3 -W 3 1.1.1.1 2>&1); echo "$out" | tail -4 | sed 's/^/     /'
check "replies came back through the firewall" contains "$out" " 0% packet loss"
check "the flow was logged" log_has "FLOW NEW +icmp 10\\.0\\.1\\.2:[0-9]+ -> 1\\.1\\.1\\.1:"

# ---------------------------------------------------------------------------
step "A real web page, byte for byte" \
     "Download example.com from inside (through the firewall) and from the host" \
     "directly, and compare the SHA-256 of the two. Log: the flows are labelled by" \
     "what the payload IS: app=http on port 80, app=tls on port 443 (cyan lines)."
for scheme in http https; do
    cmd "curl -s $scheme://example.com | sha256sum      # through the firewall"
    a=$(inside curl -s -m 15 $scheme://example.com | sha); say "   $a"
    cmd "curl -s $scheme://example.com | sha256sum      # direct, no firewall"
    b=$(curl -s -m 15 $scheme://example.com | sha); say "   $b"
    check "$scheme: identical pages (SHA-256 $a)" test -n "$a" -a "$a" = "$b"
done
check "port 80 was identified as HTTP" log_has "FLOW APP +tcp 10\\.0\\.1\\.2:[0-9]+ -> [0-9.]+:80 .*app=http"
check "port 443 was identified as TLS"  log_has "FLOW APP +tcp 10\\.0\\.1\\.2:[0-9]+ -> [0-9.]+:443 .*app=tls"

# ---------------------------------------------------------------------------
step "DNS, but only through the trusted resolver" \
     "The rules allow DNS to exactly one resolver (10.0.2.2) and deny every other." \
     "Log: app=dns for the allowed query, and a red DROP with why=rule-deny for 8.8.8.8."
cmd "dig +short example.com @10.0.2.2"
out=$(inside dig +short +time=3 +tries=2 example.com @10.0.2.2 2>&1); echo "$out" | sed 's/^/     /'
check "the trusted resolver answers" test -n "$out"
check "the query was identified as DNS" log_has "FLOW APP +udp 10\\.0\\.1\\.2:[0-9]+ -> 10\\.0\\.2\\.2:53 .*app=dns"
cmd "dig +time=2 +tries=1 example.com @8.8.8.8      # any other resolver"
out=$(inside dig +time=2 +tries=1 example.com @8.8.8.8 2>&1); echo "$out" | grep -E "timed out|ANSWER" | head -1 | sed 's/^/     /'
check "another resolver gets no answer (timed out)" contains "$out" "timed out"
check "the drop was logged with its rule" log_has "DROP udp 10\\.0\\.1\\.2:[0-9]+ -> 8\\.8\\.8\\.8:53 .*why=rule-deny"

# ---------------------------------------------------------------------------
step "Application identification: the payload, not the port" \
     "We run a plain HTTP server on port 443. The rules allow port 443, so the" \
     "request goes through, but the firewall looks at the bytes: it is HTTP, not TLS." \
     "Log: a magenta line, app=http mismatch(port suggests tls)."
cmd "curl -s http://10.0.2.3:443/"
out=$(inside curl -s -m 5 http://10.0.2.3:443/); echo "$out" | sed 's/^/     /'
check "the request succeeded (the port is allowed)" contains "$out" "tunwall demo server"
check "the mismatch was flagged" log_has "-> 10\\.0\\.2\\.3:443 .*app=http.*mismatch\\(port suggests tls\\)"

# ---------------------------------------------------------------------------
step "Default deny: an outside host cannot reach the inside" \
     "From the outside, try client B's port 3389 (a service IS listening there) and ping." \
     "Nothing answers: the packets are dropped silently, no RST and no ICMP error," \
     "so the attacker cannot even tell the host is there. Log: red DROP lines."
cmd "probe tcp 10.0.1.3 3389     (from the outside namespace)"
out=$(outside python3 tests/integration/probe.py tcp 10.0.1.3 3389); say "   result: $out"
check "the connection attempt timed out: dropped, not refused" test "$out" = timeout
cmd "ping -c 2 -W 2 10.0.1.2     (from the outside namespace)"
out=$(outside ping -c 2 -W 2 10.0.1.2 2>&1); echo "$out" | grep -E "transmitted" | sed 's/^/     /'
check "inbound ping gets no reply" contains "$out" "100% packet loss"
check "the drops were logged with the reason" log_has "DROP tcp 10\\.0\\.2\\.[0-9]+:[0-9]+ -> 10\\.0\\.1\\.3:3389 .*why=no-rule"

# ---------------------------------------------------------------------------
step "nmap from the outside finds only the allowed port" \
     "Only port 22 on client B has a rule (allow in tcp any 10.0.1.3 22)." \
     "Everything else shows 'filtered': no response at all. An ACK scan, which" \
     "would reveal a plain packet filter, finds nothing either."
cmd "nmap -Pn -n -p 22,80,443,3389 10.0.1.3"
out=$(outside nmap -Pn -n -p 22,80,443,3389 10.0.1.3 2>&1); echo "$out" | grep -E "^PORT|/tcp" | sed 's/^/     /'
check "exactly one open port, and none reported closed" test "$(echo "$out" | grep -c '/tcp .*open ')" = 1 -a "$(echo "$out" | grep -c ' closed ')" = 0
cmd "nmap -Pn -n -sA -p 22,3389 10.0.1.3      # ACK scan"
out=$(outside nmap -Pn -n -sA -p 22,3389 10.0.1.3 2>&1); echo "$out" | grep -E "^PORT|/tcp" | sed 's/^/     /'
check "the ACK scan sees nothing (all filtered)" test "$(echo "$out" | grep -c ' unfiltered')" = 0

# ---------------------------------------------------------------------------
step "The one exposed service works" \
     "Port 22 on client B is allowed in. A real connection from the outside succeeds," \
     "and the firewall tracks it: Log: a green FLOW NEW for the inbound flow."
cmd "curl -s http://10.0.1.3:22/     (from the outside namespace)"
out=$(outside curl -s -m 5 http://10.0.1.3:22/); echo "$out" | sed 's/^/     /'
check "the exposed service answered" contains "$out" "tunwall demo server"
check "the inbound flow was logged" log_has "FLOW NEW +tcp 10\\.0\\.2\\.[0-9]+:[0-9]+ -> 10\\.0\\.1\\.3:22"

# ---------------------------------------------------------------------------
step "A port scanner gets cut off" \
     "Now 10.0.2.3 scans client B's ports 1-100, in order. After 20 dropped ports in" \
     "5 seconds the firewall decides it is a scan and drops EVERYTHING from that host" \
     "for 60 s, so port 22, open a moment ago, is never found. Log: a yellow SCAN line." \
     "Other outside hosts are not affected."
cmd "nmap -Pn -n -S 10.0.2.3 -T4 -r -p 1-100 10.0.1.3      (from the outside namespace)"
out=$(outside nmap -Pn -n --send-ip -S 10.0.2.3 -e veth-sout -T4 -r --max-retries 1 -p 1-100 10.0.1.3 2>&1)
echo "$out" | grep -E "^PORT|/tcp|Not shown|Nmap done" | sed 's/^/     /'
check "the scan was detected" log_has "SCAN +10\\.0\\.2\\.3 dropped on 20 ports"
check "nmap did not find port 22 (scanned after the cut-off)" test "$(echo "$out" | grep -cE '^22/tcp +open')" = 0
cmd "curl http://10.0.1.3:22/ from the scanner, then from 10.0.2.2"
outside curl -s -m 4 --interface 10.0.2.3 -o /dev/null http://10.0.1.3:22/; rc=$?
say "   from 10.0.2.3: curl exit $rc (28 = timed out)"
check "the scanner can no longer reach port 22" test "$rc" = 28
out=$(outside curl -s -m 5 --interface 10.0.2.2 http://10.0.1.3:22/)
check "10.0.2.2 still can" contains "$out" "tunwall demo server"

# ---------------------------------------------------------------------------
step "A SYN flood can't lock out the service" \
     "A flood of SYNs from thousands of forged addresses fills the firewall's" \
     "connection table with half-open connections, to shut real clients out. We flood" \
     "until the table is full (a yellow SYNFLOOD line), stop, and then a normal client" \
     "STILL connects: tunwall evicted the oldest half-open one, like the Linux SYN backlog."
# Backscatter guard: in the Internet-connected demo topology, drop client B's
# SYN-ACKs to the forged addresses so they never leave the machine; the real
# client at 10.0.2.2 (in 10.0.2.0/24) is still answered. Removed after the step.
GUARD="OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK ! -d 10.0.2.0/24 -j DROP"
sudo ip netns exec inside iptables -I $GUARD 2>/dev/null
cmd "hping3 -S --flood --rand-source -p 22 10.0.1.3      (forged SYNs from the outside)"
sudo ip netns exec outside timeout 15 hping3 -q -S --flood --rand-source -p 22 10.0.1.3 >/dev/null 2>&1 &
HPING=$!
say "   flooding until the table fills..."
check "the firewall reports the table under pressure" log_has "SYNFLOOD table under pressure"
# Stop the flood, then connect: the table is still full of half-open attack
# connections, so getting in requires an eviction.
sudo kill "$HPING" 2>/dev/null; sudo pkill -x hping3 2>/dev/null; wait "$HPING" 2>/dev/null; sleep 2
sudo ip netns exec inside iptables -D $GUARD 2>/dev/null
cmd "curl http://10.0.1.3:22/     (from 10.0.2.2, table still full of half-open connections)"
out=$(outside curl -s -m 6 --interface 10.0.2.2 http://10.0.1.3:22/)
check "a real client still reaches the service despite the full table" contains "$out" "tunwall demo server"
sudo pkill -USR1 -x tunwall; sleep 1
check "half-open connections were evicted to make room" log_has "^flows: .* evicted=[1-9]"

# ---------------------------------------------------------------------------
step "The counters" \
     "Sending SIGUSR1 prints the statistics: packets allowed and dropped, drops by" \
     "reason, flows, the identified applications, and any log lines suppressed."
cmd "kill -USR1 tunwall"
sudo pkill -USR1 -x tunwall; sleep 1
check "the counters were printed" log_has "^apps: +http=[1-9]"
check "drops are broken down by reason" log_has "^drop\\[no-rule\\(default-deny\\)\\]=[1-9]"
check "the scan is counted" log_has "^scan: +detected=1 "

# ---------------------------------------------------------------------------
step "Performance against the Linux kernel" \
     "Measured on this 2-CPU VM: iperf3 (5 runs of 10 s) and 5000 pings. The firewall adds" \
     "about 0.12 ms at the median. It is single-threaded, so one core is its ceiling; the" \
     "profile shows ~90% of the time is the kernel forwarding each packet twice."
cmd "sed -n '/^| Setup/,/^\$/p' README.md"
sed -n '/^| Setup/,/^$/p' README.md | sed 's/^/     /'

# ---------------------------------------------------------------------------
step "Kill the firewall: nothing gets through" \
     "The tun devices are persistent, so with no program reading them the kernel" \
     "simply drops every packet routed to them. No firewall means no traffic."
cmd "pkill tunwall"
sudo pkill -x tunwall; sleep 1
cmd "ping -c 2 -W 2 1.1.1.1"
out=$(inside ping -c 2 -W 2 1.1.1.1 2>&1); echo "$out" | grep -E "transmitted" | sed 's/^/     /'
check "ping no longer works" contains "$out" "100% packet loss"
cmd "curl -m 4 https://example.com"
inside curl -s -m 4 -o /dev/null https://example.com; rc=$?
check "the web request times out (curl exit $rc)" test "$rc" = 28

# ---------------------------------------------------------------------------
echo; echo "${B}Demo checks: ${G}$pass passed${Z}${B}, ${failn:+$R}$failn failed${Z}"
[ -n "$AUTO" ] && exit $((failn > 0))
read -rp $'\n   Press Enter to tear the demo down ' _
exit 0

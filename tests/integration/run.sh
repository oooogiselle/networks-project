#!/usr/bin/env bash
# run.sh - end-to-end tests of tunwall on the namespace network.
# Needs Linux and root.
#
#   sudo tests/integration/run.sh            # fast checks (~1 minute)
#   sudo SLOW=1 tests/integration/run.sh     # also wait for idle-flow expiry
#   sudo KEEP=1 tests/integration/run.sh     # leave network + servers up
#
# On any failure it prints diagnostics (scripts/ns_diag.sh) and the tunwall
# log, so the whole output can be pasted for debugging.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
. "$ROOT/scripts/common.sh"

need_root
check_deps ip ping curl dig nmap dnsmasq python3 sha256sum timeout make

RULES=$HERE/test.rules
PROBE=$HERE/probe.py
TW=$ROOT/tunwall
LOG=$RUN_DIR/tunwall.log
TW_PID=
PASSED=0
FAILED=0
FINISHED=0

mkdir -p "$RUN_DIR"

# ---- reporting -------------------------------------------------------------

section() { printf '\n===== %s =====\n' "$*"; }
pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; }
fail() {
    FAILED=$((FAILED + 1))
    printf 'FAIL  %s\n' "$1"
    [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/      /'
    return 0
}

# expect_ok NAME CMD... : CMD must succeed.
expect_ok() {
    local name=$1 out; shift
    if out=$("$@" 2>&1); then pass "$name"; else fail "$name" "\$ $*"$'\n'"$out"; fi
}
# expect_fail NAME CMD... : CMD must fail.
expect_fail() {
    local name=$1 out; shift
    if out=$("$@" 2>&1); then
        fail "$name" "\$ $*  (succeeded, expected failure)"$'\n'"$out"
    else
        pass "$name"
    fi
}

# step CMD... : setup step; on failure show its output and abort.
step() {
    local out
    out=$("$@" 2>&1) || { printf '%s\n' "$out"; fail "setup: $*"; finish; }
}

# ---- tunwall control -------------------------------------------------------

start_tunwall() {
    : >"$LOG"
    ip netns exec "$NS_FW" "$TW" -r "$RULES" -vv >>"$LOG" 2>&1 &
    TW_PID=$!
    local i
    for i in $(seq 50); do
        grep -q 'tunwall: ready' "$LOG" && return 0
        kill -0 "$TW_PID" 2>/dev/null || break
        sleep 0.1
    done
    cat "$LOG"
    return 1
}

stop_tunwall() {
    if [ -n "$TW_PID" ]; then
        kill "$TW_PID" 2>/dev/null
        wait "$TW_PID" 2>/dev/null
        TW_PID=
    fi
}

# flow_stat FIELD : ask tunwall for stats and print flows: FIELD=<n>.
flow_stat() {
    kill -USR1 "$TW_PID" 2>/dev/null
    sleep 0.5
    grep '^flows:' "$LOG" | tail -n 1 | sed -n "s/.*$1=\([0-9]*\).*/\1/p"
}

finish() {
    [ "$FINISHED" = 1 ] && return
    FINISHED=1
    if [ "$FAILED" -gt 0 ]; then
        section "diagnostics (scripts/ns_diag.sh)"
        "$ROOT/scripts/ns_diag.sh"
    fi
    stop_tunwall
    if [ "$FAILED" -gt 0 ] && [ -s "$LOG" ]; then
        section "tunwall log (last 80 lines of $LOG)"
        tail -n 80 "$LOG"
    fi
    if [ "${KEEP:-0}" = 1 ]; then
        say "KEEP=1: network and servers left running (sudo scripts/ns_teardown.sh to remove)"
    else
        "$ROOT/scripts/servers.sh" stop >/dev/null 2>&1
        "$ROOT/scripts/ns_teardown.sh" >/dev/null 2>&1
    fi
    section "summary"
    printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
    [ "$FAILED" -eq 0 ] && exit 0
    exit 1
}
trap finish EXIT
trap 'echo; fail "interrupted"; finish' INT TERM

# ---- individual checks -----------------------------------------------------

check_rules_error() {
    local bad=$RUN_DIR/bad.rules out rc
    printf 'allow out tcp from any to any port 80\nallow sideways tcp\n' >"$bad"
    out=$("$TW" -r "$bad" -i no-such-tun 2>&1); rc=$?
    echo "exit=$rc: $out"
    [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'line 2'
}

check_http() {
    in_ns "$NS_INSIDE" curl -sS -f --max-time 15 --interface "$CLIENT_A" \
        -o "$RUN_DIR/got.bin" "http://$SERVER/blob" || return 1
    local want got
    want=$(sha256sum <"$RUN_DIR/www/blob")
    got=$(sha256sum <"$RUN_DIR/got.bin")
    echo "want $want"
    echo "got  $got"
    [ "$want" = "$got" ]
}

check_dns() {
    local ans
    ans=$(in_ns "$NS_INSIDE" dig +short +time=2 +tries=2 -b "$CLIENT_A" \
        @"$SERVER" web.test) || return 1
    echo "answer: '$ans'"
    [ "$ans" = "$SERVER" ]
}

# filtered SRC_NS SRC DST PORT : connection must time out (dropped silently),
# not be refused (which would mean the SYN got through and was answered).
check_filtered() {
    local out
    if out=$(in_ns "$1" python3 "$PROBE" "$2" "$3" "$4" 3); then
        echo "connected: $out"
        return 1
    fi
    echo "$out"
    printf '%s' "$out" | grep -qi 'timeout\|timed out'
}

check_nmap_syn() {
    local out ports nopen
    out=$(in_ns "$NS_OUTSIDE" nmap -n -Pn -sS -S "$ATTACKER" -e eth0 -T4 \
        --max-retries 1 -p 20-25,80,3389 -oG - "$CLIENT_B" 2>&1) || { echo "$out"; return 1; }
    echo "$out"
    ports=$(printf '%s\n' "$out" | grep 'Ports:')
    nopen=$(printf '%s\n' "$ports" | grep -o '[0-9]*/open/' | wc -l)
    printf '%s' "$ports" | grep -q '22/open/' && [ "$nopen" -eq 1 ] &&
        ! printf '%s' "$out" | grep -qi 'closed'
}

check_nmap_ack() {
    local out
    out=$(in_ns "$NS_OUTSIDE" nmap -n -Pn -sA -S "$ATTACKER" -e eth0 -T4 \
        --max-retries 1 -p 20-25,80,3389 -oG - "$CLIENT_B" 2>&1) || { echo "$out"; return 1; }
    echo "$out"
    printf '%s' "$out" | grep -q 'Host:' && ! printf '%s' "$out" | grep -q 'unfiltered'
}

check_stats() {
    kill -USR1 "$TW_PID" || return 1
    sleep 0.5
    tail -n 20 "$LOG"
    grep -q -- '--- tunwall stats ---' "$LOG" && grep -q '^packets:' "$LOG" &&
        grep -q '^drop\[' "$LOG"
}

check_expiry() {
    in_ns "$NS_INSIDE" ping -c 1 -W 2 -I "$CLIENT_A" "$SERVER" >/dev/null || return 1
    local before after
    before=$(flow_stat expired)
    echo "expired before: $before; waiting 40 s (ICMP idle timeout is 30 s)"
    sleep 40
    after=$(flow_stat expired)
    echo "expired after:  $after"
    [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]
}

# ---- run -------------------------------------------------------------------

section "build"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    step sudo -u "$SUDO_USER" make -s -C "$ROOT" all
else
    step make -s -C "$ROOT" all
fi
[ -x "$TW" ] || { fail "build: $TW missing"; finish; }
pass "tunwall builds"
expect_ok "rule syntax error: exit 1 with line number" check_rules_error

section "setup"
step "$ROOT/scripts/ns_setup.sh"
step "$ROOT/scripts/servers.sh" start
pass "namespaces and servers up"

section "fail-closed before start"
expect_fail "no traffic while tunwall is not running" \
    in_ns "$NS_INSIDE" ping -c 2 -W 1 -I "$CLIENT_A" "$SERVER"

section "tunwall running"
if start_tunwall; then
    pass "tunwall starts and attaches to tun-in/tun-out"
else
    fail "tunwall starts and attaches to tun-in/tun-out"
    finish
fi

expect_ok "outbound ping (client A -> server)" \
    in_ns "$NS_INSIDE" ping -c 3 -W 2 -I "$CLIENT_A" "$SERVER"
expect_ok "HTTP download, SHA-256 matches" check_http
expect_ok "DNS lookup web.test via $SERVER" check_dns
expect_fail "inbound ping (server -> client A) blocked" \
    in_ns "$NS_OUTSIDE" ping -c 2 -W 1 -I "$SERVER" "$CLIENT_A"
expect_ok "inbound TCP to exposed $CLIENT_B:22 allowed" \
    in_ns "$NS_OUTSIDE" python3 "$PROBE" "$ATTACKER" "$CLIENT_B" 22 3
expect_ok "inbound TCP to $CLIENT_B:3389 silently dropped" \
    check_filtered "$NS_OUTSIDE" "$ATTACKER" "$CLIENT_B" 3389
expect_ok "outbound TCP to unlisted port $SERVER:8080 silently dropped" \
    check_filtered "$NS_INSIDE" "$CLIENT_A" "$SERVER" 8080
expect_ok "nmap SYN scan: only 22 open, rest filtered" check_nmap_syn
expect_ok "nmap ACK scan: everything filtered" check_nmap_ack
expect_ok "SIGUSR1 prints counters" check_stats

if [ "${SLOW:-0}" = 1 ]; then
    expect_ok "idle ICMP flow expires" check_expiry
else
    say "skipping idle-flow expiry (SLOW=1 to run it, +40 s)"
fi

section "fail-closed after kill -9"
kill -9 "$TW_PID" 2>/dev/null
wait "$TW_PID" 2>/dev/null
TW_PID=
expect_fail "no traffic after tunwall is killed" \
    in_ns "$NS_INSIDE" ping -c 2 -W 1 -I "$CLIENT_A" "$SERVER"

finish

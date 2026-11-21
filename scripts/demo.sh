#!/usr/bin/env bash
# ============================================================================
# File Name:   demo.sh
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: The recorded demo. Builds the three-namespace topology WITH a
#              path to the real Internet, starts the firewall, and opens a
#              tmux window split in two: the firewall's live log on top and the
#              narrated demo steps (scripts/demo_steps.sh) below, which wait
#              for Enter between steps so the presenter sets the pace.
#
#                scripts/demo.sh          set everything up and attach
#                scripts/demo.sh auto     run every step unattended with checks
#                                         (no tmux), then tear down; exit 0 = ok
#                scripts/demo.sh stop     tear everything down (safe any time)
#
#              It needs sudo (namespaces), tmux, nmap, hping3, dig, curl, and the host
#              must be online. It changes the HOST temporarily (a veth pair,
#              ip_forward and three iptables rules tagged "tunwall-demo"); stop
#              removes exactly those. Set DEMO_UPSTREAM_DNS to use another
#              resolver than 1.1.1.1.
# ============================================================================
set -u
cd "$(dirname "$0")/.."
SESSION=tunwall-demo
RULES=/tmp/tunwall-demo-rules.conf   # a copy of config/rules.example.conf: a step tightens it live
LOG=/tmp/tunwall-demo.log
WEBDIR=/tmp/tunwall-demo-web
UPSTREAM=${DEMO_UPSTREAM_DNS:-1.1.1.1}

need() { command -v "$1" >/dev/null || { echo "demo.sh: $1 is required ($2)" >&2; exit 1; }; }

in_ns() { local ns=$1; shift; sudo ip netns exec "$ns" "$@"; }

# Start a helper server in a namespace, detached: setsid -f puts it in its own
# session with no terminal, so it keeps running after this script exits (with
# DEMO_NO_ATTACH=1 that is right away) or the terminal closes. On a terminal,
# sudo runs its command on a pseudo-terminal that dies with this script, and a
# plain `&` would take the helper down with it. `stop` still finds and kills
# it, because it lives in the namespace.
in_ns_bg() { local ns=$1; shift; sudo setsid -f ip netns exec "$ns" "$@" </dev/null >/dev/null 2>&1; }

# Everything the demo started inside the namespaces, killed by namespace so
# nothing else on the machine is touched.
kill_in_namespaces() {
    local ns pids
    for ns in outside inside firewall; do
        pids=$(sudo ip netns pids "$ns" 2>/dev/null) || continue
        [ -n "$pids" ] && sudo kill $pids 2>/dev/null
    done
    sleep 0.5
}

stop() {
    kill_in_namespaces
    sudo scripts/netns.sh down >/dev/null 2>&1
    rm -rf "$WEBDIR" "$RULES"
    echo "demo stopped: namespaces, host rules and helper processes are gone."
    # The tmux session goes LAST: when the demo ends by itself, this very function
    # is running inside one of its panes, and killing the session first would kill
    # it before the host was restored.
    tmux kill-session -t "$SESSION" 2>/dev/null
}

# Topology + Internet path + the little servers the demo talks to.
setup() {
    need nmap "apt install nmap"; need hping3 "apt install hping3"; need dig "apt install dnsutils"; need curl curl
    need python3 python3; need sudo sudo
    sudo -n true 2>/dev/null || sudo -v || exit 1      # cache the password now, not mid-demo
    make -s tunwall || { echo "demo.sh: the build failed" >&2; exit 1; }
    if ! curl -s -m 8 -o /dev/null http://example.com; then
        echo "demo.sh: this machine cannot reach example.com, so there is no Internet to demo" >&2; exit 1
    fi
    sudo scripts/netns.sh down >/dev/null 2>&1
    sudo scripts/netns.sh up nat || exit 1

    mkdir -p "$WEBDIR"; echo "<h1>tunwall demo server</h1>" > "$WEBDIR/index.html"
    in_ns_bg outside python3 scripts/dns_forwarder.py 10.0.2.2 "$UPSTREAM"
    # HTTP spoken on port 443 (outside), and two services on the inside client B
    in_ns_bg outside python3 -m http.server 443 --bind 10.0.2.3 --directory "$WEBDIR"
    in_ns_bg inside  python3 -m http.server 22   --bind 10.0.1.3 --directory "$WEBDIR"
    in_ns_bg inside  python3 -m http.server 3389 --bind 10.0.1.3 --directory "$WEBDIR"
    # an echo server on an allowed web port, for the forged-RST and SSH-over-443 steps
    in_ns_bg outside python3 tests/integration/inject.py server 10.0.2.2 443
    cp config/rules.example.conf "$RULES"
    sleep 1
}

case "${1:-start}" in
stop) stop; exit 0 ;;

auto)
    trap stop EXIT
    setup
    : > "$LOG"
    in_ns firewall build/tunwall -r "$RULES" > "$LOG" 2>&1 &
    sleep 1
    DEMO_AUTO=1 DEMO_LOG="$LOG" DEMO_RULES="$RULES" scripts/demo_steps.sh
    exit $?
    ;;

start)
    need tmux "apt install tmux"
    [ -t 0 ] || [ -n "${DEMO_NO_ATTACH:-}" ] || { echo "demo.sh: run this in a terminal" >&2; exit 1; }
    stop >/dev/null 2>&1
    setup
    : > "$LOG"
    cols=${COLUMNS:-$(tput cols 2>/dev/null || echo 200)}; rows=${LINES:-$(tput lines 2>/dev/null || echo 50)}
    # top pane: the firewall's live log (colourised copy on screen, plain copy in $LOG)
    tmux new-session -d -s "$SESSION" -x "$cols" -y "$rows" \
        "sudo ip netns exec firewall build/tunwall -r $RULES 2>&1 | tee $LOG | awk -f scripts/demo_log.awk; read -rp 'firewall stopped - press Enter '"
    # bottom pane: the narrated steps
    tmux split-window -v -p 62 -t "$SESSION" "DEMO_LOG=$LOG DEMO_RULES=$RULES scripts/demo_steps.sh; scripts/demo.sh stop"
    tmux set-option -t "$SESSION" pane-border-status top
    tmux select-pane -t "$SESSION:0.0" -T " FIREWALL LOG (live) "
    tmux select-pane -t "$SESSION:0.1" -T " DEMO - Enter runs the next step "
    tmux select-pane -t "$SESSION:0.1"
    [ -n "${DEMO_NO_ATTACH:-}" ] && { echo "session $SESSION is running (detached)"; exit 0; }
    tmux attach -t "$SESSION"
    # leaving tmux early (detach or Ctrl-b d) must not leave the machine changed
    stop
    ;;

*) echo "usage: scripts/demo.sh [start|auto|stop]" >&2; exit 2 ;;
esac

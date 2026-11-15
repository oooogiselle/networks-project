#!/usr/bin/env bash
# ============================================================================
# File Name:   run_bench.sh
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: iperf3 throughput and ping latency from inside to outside in
#              the test topology. Run once per setup and label the run:
#                sudo scripts/netns.sh up kernel; sudo bench/run_bench.sh kernel
#                sudo scripts/netns.sh up; (tunwall -r bench/allow-all.conf -q &)
#                sudo bench/run_bench.sh allow-all  (tunwall, one allow rule)
#                sudo bench/run_bench.sh many-rules (tunwall, many rules)
#              Results go to bench/results/<label>.txt (git-ignored).
#              Set PERF=1 to also record a perf profile of tunwall.
# ============================================================================
set -eu
cd "$(dirname "$0")/.."
label=${1:?usage: run_bench.sh <label>}
secs=${SECS:-10}
out=bench/results; mkdir -p "$out"
for c in iperf3 ping; do command -v $c >/dev/null || { echo "need $c"; exit 1; }; done

# The label must match what is actually running, or the numbers are misleading.
case "$label" in
    kernel)
        pgrep -x tunwall >/dev/null && { echo "label 'kernel' but tunwall is running; stop it first"; exit 1; }
        ip -n firewall rule 2>/dev/null | grep -q "iif veth-in" &&
            { echo "label 'kernel' needs the baseline topology: sudo scripts/netns.sh up kernel"; exit 1; } ;;
    allow-all|many-rules)
        pgrep -x tunwall >/dev/null || { echo "label '$label' but tunwall is not running; start it with the matching rules"; exit 1; }
        ip -n firewall rule 2>/dev/null | grep -q "iif veth-in" ||
            { echo "label '$label' needs the firewall topology: sudo scripts/netns.sh up"; exit 1; }
        # Record which rules file the running firewall was started with.
        echo "tunwall command line: $(tr '\0' ' ' < /proc/"$(pgrep -x tunwall | head -1)"/cmdline)" ;;
    *) echo "label must be kernel, allow-all or many-rules"; exit 1 ;;
esac

ip netns exec outside iperf3 -s -1 -B 10.0.2.2 >/dev/null 2>&1 &
srv=$!; sleep 1
if [ "${PERF:-0}" = 1 ] && pgrep -x tunwall >/dev/null; then
    perf record -o "$out/$label.perf.data" -g -p "$(pgrep -x tunwall | head -1)" -- sleep $((secs+3)) >/dev/null 2>&1 &
fi
{
  echo "# $label  $(date -Is)"
  echo "## ping (200 packets)"
  ip netns exec inside ping -c 200 -i 0.01 -q 10.0.2.2 | tail -2
  echo "## iperf3 TCP, ${secs}s"
  ip netns exec inside iperf3 -c 10.0.2.2 -t "$secs" | tail -4
} | tee "$out/$label.txt"
wait $srv 2>/dev/null || true

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
#                sudo scripts/netns.sh up
#                sudo ip netns exec firewall build/tunwall -r bench/allow-all.conf -q &
#                sudo bench/run_bench.sh allow-all     (tunwall, one allow rule)
#                bench/gen_many_rules.sh 2000 > /tmp/many.conf
#                sudo ip netns exec firewall build/tunwall -r /tmp/many.conf -q &
#                sudo bench/run_bench.sh many-rules    (tunwall, many rules)
#              The label must match what is really running: the script refuses
#              to run if the topology, the firewall, or its rules file (by its
#              rule count) do not fit it.
#              RUNS=5 SECS=10 repeats the iperf3 run and reports the MEDIAN of
#              the runs (one run is too noisy to trust). The receiver rate is
#              the headline figure. Results go to bench/results/<label>.txt
#              (git-ignored). Set PERF=1 to also record a perf profile.
# ============================================================================
set -eu
cd "$(dirname "$0")/.."
label=${1:?usage: run_bench.sh <label>}
secs=${SECS:-10}
runs=${RUNS:-1}
out=bench/results
for c in iperf3 ping python3; do command -v $c >/dev/null || { echo "need $c"; exit 1; }; done

# ---- the label must match what is actually running -------------------------
nrules() { grep -cE '^[[:space:]]*(allow|deny)' "$1"; }
rules_file_of_tunwall() { # the -r argument of the running tunwall
    tr '\0' '\n' < /proc/"$(pgrep -x tunwall | head -1)"/cmdline | awk 'p {print; exit} $0 == "-r" {p = 1}'
}
case "$label" in
    kernel)
        pgrep -x tunwall >/dev/null && { echo "label 'kernel' but tunwall is running; stop it first"; exit 1; }
        ip -n firewall rule 2>/dev/null | grep -q "iif veth-in" &&
            { echo "label 'kernel' needs the baseline topology: sudo scripts/netns.sh up kernel"; exit 1; }
        info="kernel forwarding (no tunwall)" ;;
    allow-all|many-rules)
        pgrep -x tunwall >/dev/null || { echo "label '$label' but tunwall is not running; start it with the matching rules"; exit 1; }
        ip -n firewall rule 2>/dev/null | grep -q "iif veth-in" ||
            { echo "label '$label' needs the firewall topology: sudo scripts/netns.sh up"; exit 1; }
        rf=$(rules_file_of_tunwall); n=$(nrules "$rf")
        if [ "$label" = allow-all ] && [ "$n" -gt 10 ]; then
            echo "label 'allow-all' but $rf has $n rules (expected a handful)"; exit 1; fi
        if [ "$label" = many-rules ] && [ "$n" -lt 100 ]; then
            echo "label 'many-rules' but $rf has only $n rules (expected 100 or more)"; exit 1; fi
        info="tunwall with $rf ($n rules)" ;;
    *) echo "label must be kernel, allow-all or many-rules"; exit 1 ;;
esac

# Run as root inside a user-writable tree: never write through a symlink.
if [ -L "$out" ] || [ -L "$out/$label.txt" ]; then echo "refusing: $out or $out/$label.txt is a symlink"; exit 1; fi
mkdir -p "$out"
if [ "${PERF:-0}" = 1 ] && pgrep -x tunwall >/dev/null; then
    perf record -o "$out/$label.perf.data" -g -p "$(pgrep -x tunwall | head -1)" -- sleep $((secs * runs + 5)) >/dev/null 2>&1 &
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
{
  echo "# $label  $(date -Is)  --  $info"
  echo "## ping (200 packets)"
  ip netns exec inside ping -c 200 -i 0.01 -q 10.0.2.2 | tail -2
  echo "## iperf3 TCP, ${secs}s x ${runs} run(s)"
  for ((i = 1; i <= runs; i++)); do
      ip netns exec outside iperf3 -s -1 -B 10.0.2.2 >/dev/null 2>&1 &
      srv=$!; sleep 1
      ip netns exec inside iperf3 -c 10.0.2.2 -t "$secs" -J > "$tmp/run$i.json" || true
      wait $srv 2>/dev/null || true
  done
  python3 - "$tmp" "$runs" <<'PY'
import json, statistics, sys
d, n = sys.argv[1], int(sys.argv[2])
rx, tx = [], []
for i in range(1, n + 1):
    try:
        e = json.load(open("%s/run%d.json" % (d, i)))["end"]
        tx.append(e["sum_sent"]["bits_per_second"] / 1e9)
        rx.append(e["sum_received"]["bits_per_second"] / 1e9)
        print("  run %d: sent %.2f  received %.2f Gbit/s, %d retransmits" % (i, tx[-1], rx[-1], e["sum_sent"].get("retransmits", 0)))
    except Exception as ex:
        print("  run %d: failed (%s)" % (i, ex))
if rx:
    print("  median received %.2f Gbit/s (min %.2f, max %.2f), median sent %.2f Gbit/s" %
          (statistics.median(rx), min(rx), max(rx), statistics.median(tx)))
PY
} | tee "$out/$label.txt"
# leave the results owned by whoever ran sudo, not by root
[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$out" || true

#!/usr/bin/env python3
# ============================================================================
# File Name:   summary.py
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Reads the results run_bench.sh left in bench/results/ for the
#              three setups (kernel, allow-all, many-rules) and prints one
#              markdown table: throughput, latency percentiles, and the
#              ADDED latency of the firewall over plain kernel forwarding,
#              which is what the spec's "under 0.5 ms" goal is about.
# Usage:       bench/summary.py [results-dir=bench/results]
# ============================================================================
import json
import os
import sys

d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "results")
LABELS = [("kernel", "(a) kernel forwarding"), ("allow-all", "(b) tunwall, one rule"),
          ("many-rules", "(c) tunwall, 2000 rules")]


def load(label, kind):
    try:
        return json.load(open(os.path.join(d, "%s.%s.json" % (label, kind))))
    except (OSError, ValueError):
        return None


base = load("kernel", "latency")
print("| Setup | Throughput (median, range) | p50 | p95 | p99 | max | Added p50 | Added p99 |")
print("|---|---|---|---|---|---|---|---|")
for label, name in LABELS:
    t, l = load(label, "iperf"), load(label, "latency")
    tp = "%.2f Gbit/s (%.2f - %.2f)" % (t["median_rx_gbps"], t["min_rx_gbps"], t["max_rx_gbps"]) if t else "-"
    if l:
        add50 = "%+.3f ms" % (l["p50_ms"] - base["p50_ms"]) if base and label != "kernel" else "-"
        add99 = "%+.3f ms" % (l["p99_ms"] - base["p99_ms"]) if base and label != "kernel" else "-"
        print("| %s | %s | %.3f | %.3f | %.3f | %.3f | %s | %s |" %
              (name, tp, l["p50_ms"], l["p95_ms"], l["p99_ms"], l["max_ms"], add50, add99))
    else:
        print("| %s | %s | - | - | - | - | - | - |" % (name, tp))
print("\nLatencies are ping round-trip times in ms. 'Added' is the firewall's value minus the kernel baseline's.")

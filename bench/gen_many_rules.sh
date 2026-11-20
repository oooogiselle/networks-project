#!/usr/bin/env bash
# ============================================================================
# File Name:   gen_many_rules.sh
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Prints a benchmark policy (c) with N rules (default 1000) that
#              never match the benchmark traffic, followed by the allow-all
#              rules, so every NEW flow walks the whole list. Once a flow
#              exists the rules are not consulted, which is what the benchmark
#              demonstrates: throughput should not depend on N.
# Usage: bench/gen_many_rules.sh [N] > /tmp/many.conf
# ============================================================================
set -eu
n=${1:-1000}
echo "inside 10.0.1.0/24"
for ((i = 0; i < n; i++)); do
    echo "deny out tcp 10.0.1.0/24 192.168.$((i / 250)).$((i % 250 + 1)) $((1024 + i % 60000))"
done
echo "allow out any any any"
echo "allow in  any any any"

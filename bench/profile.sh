#!/usr/bin/env bash
# ============================================================================
# File Name:   profile.sh
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Explains the throughput gap between tunwall and kernel
#              forwarding with measurements. Builds the topology, starts the
#              firewall with the allow-all policy, pushes iperf3 TCP traffic
#              through it, and records, over a steady-state window:
#                - a CPU profile of tunwall (perf, software clock, so it works
#                  on a VM without hardware counters), grouped into where the
#                  time goes: copying packets to and from the kernel, the
#                  syscall and tun layer, the kernel network stack that
#                  forwards the packet again, and tunwall's own code;
#                - how much of ONE core tunwall uses (it is single-threaded);
#                - packets per second and the average packet size;
#                - syscalls per packet (strace -c, counts only: strace slows
#                  everything, so it is never run during the profile);
#              and prints the cost per packet. Needs root, perf, iperf3, strace.
# Usage:       sudo bench/profile.sh          (SECS=15 sets the window length)
#              Results: bench/results/profile.txt and profile.perf.data
# ============================================================================
set -eu
cd "$(dirname "$0")/.."
secs=${SECS:-15}
out=bench/results
for c in perf iperf3 strace python3 ip; do command -v $c >/dev/null || { echo "need $c"; exit 1; }; done
[ -x build/tunwall ] || { echo "build it first: make tunwall"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }
if [ -L "$out" ] || [ -L "$out/profile.txt" ]; then echo "refusing: $out or profile.txt is a symlink"; exit 1; fi
mkdir -p "$out"

FW=""; IPERF=""
cleanup() {
    [ -n "$IPERF" ] && kill "$IPERF" 2>/dev/null
    [ -n "$FW" ] && kill "$FW" 2>/dev/null
    ip netns exec outside true 2>/dev/null && for p in $(ip netns pids outside 2>/dev/null); do kill "$p" 2>/dev/null; done
    scripts/netns.sh down >/dev/null 2>&1
    [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$out" 2>/dev/null
    return 0
}
trap cleanup EXIT

scripts/netns.sh up >/dev/null
ip netns exec firewall build/tunwall -r bench/allow-all.conf -q 2>/dev/null &
FW=$!
for _ in $(seq 1 100); do                       # wait until it has attached the tun devices
    [ "$(ip -n firewall -br link show tun-in | awk '{print $2}')" = UP ] && break; sleep 0.1
done
kill -0 "$FW" 2>/dev/null || { echo "tunwall did not start"; exit 1; }

ip netns exec outside iperf3 -s -1 -B 10.0.2.2 >/dev/null 2>&1 &
sleep 1
# long enough to cover: warm-up, the profile window, then the strace count
ip netns exec inside iperf3 -c 10.0.2.2 -t $((secs + 40)) -J > /tmp/profile-iperf.json 2>/dev/null &
IPERF=$!
sleep 2                                         # let the connection reach steady state

# kernel-side counters of the two tun devices: tx = packets tunwall READS,
# rx = packets tunwall WRITES (from the kernel's point of view)
tunstat() { ip netns exec firewall cat /sys/class/net/$1/statistics/$2; }
snapshot() {
    echo "$(date +%s.%N) $(awk '{print $14+$15}' /proc/$FW/stat) $(tunstat tun-in tx_packets) $(tunstat tun-out tx_packets) $(tunstat tun-in tx_bytes) $(tunstat tun-out tx_bytes) $(tunstat tun-in rx_packets) $(tunstat tun-out rx_packets)"
}
# 1) load numbers over a clean window (nothing else attached to tunwall)
A=$(snapshot); sleep $((secs / 2)); B=$(snapshot)
# 2) the CPU profile, in its own window
perf record -F 999 -e cpu-clock -p "$FW" -o "$out/profile.perf.data" -- sleep $((secs - 4)) >/dev/null 2>&1

# syscall counts, on their own (strace slows the process down a lot)
timeout 3 strace -c -f -p "$FW" -o /tmp/profile-strace.txt >/dev/null 2>&1 || true
kill "$IPERF" 2>/dev/null; wait "$IPERF" 2>/dev/null || true; IPERF=""

{
echo "# tunwall profile  $(date -Is)  (window ${secs}s, allow-all policy, iperf3 TCP inside -> outside)"
python3 - "$A" "$B" "$(getconf CLK_TCK)" <<'PY'
import sys
a, b, hz = sys.argv[1].split(), sys.argv[2].split(), int(sys.argv[3])
dt = float(b[0]) - float(a[0])
cpu = (int(b[1]) - int(a[1])) / hz
d = [int(y) - int(x) for x, y in zip(a[2:], b[2:])]
reads, written = d[0] + d[1], d[4] + d[5]
bytes_read = d[2] + d[3]
print("\n## load")
print("window %.1f s (no profiler attached);  tunwall used %.1f%% of one core (%.2f s of CPU)" % (dt, 100 * cpu / dt, cpu))
print("packets read   %9d  = %8.0f packets/s, average %.0f bytes" % (reads, reads / dt, bytes_read / max(reads, 1)))
print("packets written%9d  = %8.0f packets/s" % (written, written / dt))
print("throughput through the firewall (both directions' payload read): %.2f Gbit/s" % (bytes_read * 8 / dt / 1e9))
print("cost per packet read: %.2f microseconds of CPU" % (1e6 * cpu / max(reads, 1)))
print("if one core were 100%% busy: at most %.0f packets/s" % (reads / cpu if cpu else 0))
PY
echo; echo "## syscalls (strace -c, 3 s)"
grep -E "^ *[0-9.]+ +[0-9.]+ +[0-9]+ +[0-9]+ +[a-z_0-9]+|calls|total" /tmp/profile-strace.txt 2>/dev/null | head -8
python3 - "$A" "$B" <<'PY' 2>/dev/null || true
import re, sys
rows = {}
for l in open("/tmp/profile-strace.txt"):
    m = re.match(r"\s*[0-9.]+\s+[0-9.]+\s+\d+\s+(\d+)\s+(?:\d+\s+)?(\w+)\s*$", l)
    if m: rows[m.group(2)] = int(m.group(1))
r, w = rows.get("read", 0), rows.get("write", 0)
if r:
    p = rows.get("ppoll", 0) + rows.get("poll", 0)
    print("reads %d, writes %d, polls %d  =>  %.2f read + %.2f write + %.3f poll syscalls per packet read"
          % (r, w, p, 1.0, w / r, p / r))
PY
} > "$out/profile.txt.part"

echo; echo "## where the CPU time goes (perf, $((secs - 4)) s of samples)" >> "$out/profile.txt.part"
perf report -i "$out/profile.perf.data" --stdio --no-children --sort dso,symbol -F overhead,dso,sym 2>/dev/null \
  | grep -vE "^#|^$" > /tmp/profile-report.txt || true
python3 - /tmp/profile-report.txt >> "$out/profile.txt.part" <<'PY'
import re, sys, collections
rows = []
for l in open(sys.argv[1]):
    m = re.match(r"\s*([0-9.]+)%\s+(\S+)\s+\[(.)\]\s+(\S+)", l)
    if m: rows.append((float(m.group(1)), m.group(2), m.group(3), m.group(4)))
rows.sort(key=lambda r: -r[0])
tot = sum(r[0] for r in rows) or 1.0
def cat(dso, kind, sym):
    if kind == "k":
        if re.search(r"copy_(to|from)_user|_copy_(to|from)_iter|copy_page|raw_copy|__arch_copy|memcpy|csum_partial_copy", sym): return "kernel: copying packets between kernel and tunwall"
        if re.search(r"^tun_|tun_", sym): return "kernel: tun driver"
        if re.search(r"el0_svc|do_el0|invoke_syscall|__arm64_sys|ksys_|vfs_|fdget|fput|__fget|new_sync|do_iter|poll|schedule|finish_task|ret_to_user|exit_to_user|enter_from_user|rw_verify|security_|el0t|el0_sync", sym): return "kernel: syscall entry/exit, file layer, poll, scheduling"
        if re.search(r"skb|slab|kmem_cache|kfree|kmalloc|__alloc|free_page|page_pool|build_skb", sym): return "kernel: allocating and freeing packet buffers"
        if re.search(r"ip_|fib_|neigh|rt_|inet_|__ip|nf_|conntrack|__fib|ipv4", sym): return "kernel: IP forwarding, routing and neighbour lookup"
        if re.search(r"netif|dev_|veth|qdisc|sch_|fq_|napi|net_rx|process_backlog|softirq|local_bh|irq|gic|rcu|__dev|enqueue|dequeue", sym): return "kernel: device queues, veth and softirq"
        return "kernel: other"
    if "tunwall" in dso:
        if re.search(r"parse|csum|check_ip_options", sym): return "tunwall: parsing and checksums"
        if re.search(r"siphash|hash|bucket|find_exact|ft_|src_|release", sym): return "tunwall: flow table (hash and lookup)"
        if re.search(r"engine|decide|tcp_|rules|appid|identify|is_http|is_tls|dns_", sym): return "tunwall: decision logic"
        if re.search(r"fwd_|handle_packet|drain|give_back|main", sym): return "tunwall: packet loop and TTL fix-up"
        return "tunwall: other"
    return "libc and other libraries (syscall wrappers)"
by = collections.OrderedDict()
for pct, dso, kind, sym in rows:
    by.setdefault(cat(dso, kind, sym), []).append((pct, sym))
print("%-72s %6s" % ("group", "share"))
for c, items in sorted(by.items(), key=lambda kv: -sum(p for p, _ in kv[1])):
    print("%-72s %5.1f%%" % (c, 100 * sum(p for p, _ in items) / tot))
kern = sum(sum(p for p, _ in v) for c, v in by.items() if c.startswith("kernel"))
user = sum(sum(p for p, _ in v) for c, v in by.items() if c.startswith("tunwall"))
print("\nkernel %.1f%%   tunwall's own code %.1f%%   libc/other %.1f%%" % (100 * kern / tot, 100 * user / tot, 100 * (tot - kern - user) / tot))
print("\n## top 25 symbols")
for pct, dso, kind, sym in rows[:25]:
    print("%5.1f%%  %-18s [%s] %s" % (100 * pct / tot, dso[:18], kind, sym[:60]))
PY
mv "$out/profile.txt.part" "$out/profile.txt"
cat "$out/profile.txt"

# Userspace Stateful Firewall

A stateful firewall in C that sits between two tun interfaces (`tun-in` =
trusted network, `tun-out` = untrusted network), parses raw IPv4 packets, and
allows or drops them using rules and connection tracking. Default policy: deny.
CS 60 final project (Giselle Wu, Eva Tate). See `requirements-spec.pdf`.

## Layout

| Path | Module | Owner |
|---|---|---|
| `include/engine.h` | Shared interface: `pkt_t`, `engine_decide()` | shared |
| `include/parser.h`, `src/parser.c` | Packet parse + checksums → `pkt_t` | Giselle |
| `src/flowtable.c` | 5-tuple hash table, expiry | Eva |
| `src/tcpstate.c` | TCP state machine, per-state timeouts | Eva |
| `src/rules.c` | Rule file parser + first-match evaluation | Eva |
| `src/engine.c` | Fast path / slow path decision logic | Eva |
| `src/log.c` | Per-flow logs, counters | Eva |
| `src/forwarder.c`, `include/forwarder.h` | Packet loop: read, parse, decide, write to the other side, 1 s expiry sweep (works on any pair of fds, so it is unit-tested with socket pairs) | Giselle |
| `src/tun_io.c`, `src/main.c` | Opens the tun devices; `tunwall` program: arguments, signals, stats | Giselle |
| `scripts/netns.sh` | Three-namespace test topology with policy routing into the tun devices | Giselle |
| `bench/` | iperf3/ping benchmark script and its rule files | Giselle |
| `tests/` | Unit tests (`tests/pktbuild.c` builds real wire packets) | shared |

## Build and test

```
make          # builds build/libfwengine.a (parser, engine, forwarder)
make test     # unit tests (run on macOS or Linux, no root needed)
make asan     # same tests under AddressSanitizer + UBSan
make tunwall  # builds build/tunwall, the firewall program (Linux only)
```

## Running the firewall

```
sudo scripts/netns.sh up                       # inside / firewall / outside namespaces
sudo ip netns exec firewall build/tunwall -r config/rules.example.conf
sudo ip netns exec inside curl http://10.0.2.2/   # in another terminal
sudo scripts/netns.sh down
```

`tunwall -r <rules> [-i tun-in] [-o tun-out] [-f | -q]`. By default every flow
open/close and every dropped packet (with its reason) is logged to stderr. The
logging is rate-limited to 1000 lines per second (bursts of 1000, shared by all
kinds of line) so a flood or a scan cannot turn into a flood of log writes; when
lines had to be dropped a `N log lines suppressed` line says how many, and the
counters are never limited. `-f` logs flows only, `-q` logs only errors, `-d` is
accepted for old scripts. SIGUSR1 prints the counters; SIGINT/SIGTERM stop it
and print them (exit status 0). It refuses to start, naming the file, on a rules
syntax error (with the line number), on a missing `inside` network, or if a tun
device does not exist. Restarting `tunwall` forgets all flow state, so
connections that were established before the restart stall (their packets are
dropped as "no flow" and no RST is sent, as the spec requires).

How the topology works: `scripts/netns.sh` creates two **persistent** tun
devices in the firewall namespace and uses `ip rule` so that every packet
arriving from the inside veth goes into `tun-in` and every packet from the
outside veth goes into `tun-out`. The kernel never forwards between the two
sides itself; `tunwall` reads a packet from one tun device and, if allowed,
writes it to the other, and the kernel then routes it out the right veth.
Because the tun devices are persistent, if `tunwall` is not running the kernel
simply drops what it routes to them: no traffic gets through.
`scripts/netns.sh up kernel` builds the same topology without the policy
routing (plain kernel forwarding) as the benchmark baseline.

## Tests

Line coverage of the library (everything in `src/` except `main.c` and
`tun_io.c`'s successful-attach line, which need root and real tun devices and
are covered by the integration tests instead) is 100%, measured with
`gcc --coverage`. `tests/test_alloc_fail.c` covers the out-of-memory paths
by making each startup allocation fail in turn (`src/fwalloc.c` is the thin
wrapper that allows this); run it under `make asan` on Linux to also catch
leaks. `tests/test_fuzz.c` throws random and corrupted packets at the parser and
engine and checks that nothing crashes and the counters stay consistent. It is
deterministic; replay or lengthen a run with
`FUZZ_SEED=<n> FUZZ_ITERS=<n> ./build/test_fuzz`.

`make tunwall && sudo tests/integration/run_all.sh` runs the end-to-end tests in
the namespace topology against the real `tunwall` (curl with a SHA-256 match,
DNS, ping, blocked inbound traffic that must be silently dropped rather than
refused, nmap SYN/ACK/FIN/NULL/Xmas scans, exact log lines, flow expiry,
kill-the-firewall). They need root, `nmap` and `python3`. CI sets
`REQUIRE_INTEGRATION=1` so a missing piece fails instead of skipping. Set
`SKIP_SLOW=1` to skip the 40 s expiry and 75 s half-close tests. The suite fails when the firewall
is wrong: with the slow tests skipped, an allow-nothing policy fails 18 checks and an
allow-everything policy fails 16.

### Benchmarks

```
sudo scripts/netns.sh up kernel && sudo bench/run_bench.sh kernel       # (a) kernel forwarding
sudo scripts/netns.sh up                                                # (b) tunwall, one allow-all rule
sudo ip netns exec firewall build/tunwall -r bench/allow-all.conf -q &
sudo bench/run_bench.sh allow-all
bench/gen_many_rules.sh 2000 > /tmp/many.conf                           # (c) tunwall, 2000 rules
sudo ip netns exec firewall build/tunwall -r /tmp/many.conf -q &
sudo bench/run_bench.sh many-rules
```

The script refuses to run if the topology, the running firewall or its rules
file (by rule count) does not match its label. `RUNS=5 SECS=10` repeats the
iperf3 run and reports the median.

Measured on the 2-CPU / 4 GB course VM (5 runs of 10 s each, median of the
receiver rate; the VM is shared by iperf3's client and server and `tunwall`,
so the spread is large):

| Setup | Median | Range over 5 runs | Avg ping (200) |
|---|---|---|---|
| (a) kernel forwarding | 8.94 Gbit/s | 8.32 - 9.06 | 0.04 ms |
| (b) `tunwall`, one allow-all rule | 1.74 Gbit/s | 0.52 - 1.77 | 0.11 ms |
| (c) `tunwall`, 2000 rules | 1.08 Gbit/s | 0.77 - 1.45 | 0.77 ms (outliers to 20 ms) |

`tunwall` is far above the 200 Mbit/s goal but about 5 to 8 times slower than
kernel forwarding (it does a read and a write per packet, no GSO/GRO batching).
The ranges of (b) and (c) overlap, so these runs do not show whether the rule
count matters (rules are only consulted for a new flow, so it should not). The
latency goal (under 0.5 ms added) is not demonstrated on this VM because of the
outliers. A `perf` profile to explain the gap is still to do (`PERF=1` records
one).

On macOS use `make CC=clang asan`: Homebrew gcc has no ASan runtime.

## How a packet is decided

1. `parse_packet(buf, len, &pkt)` validates the raw packet: IPv4 only, lengths
   consistent, IP/TCP/UDP/ICMP checksums good, no fragments, TTL not 0, no
   martian addresses (0/8, loopback, 169.254/16, multicast/class E), and a
   well-formed IP option list with no source-route options (LSRR/SSRR). On failure it returns a `parse_result_t` (malformed, fragment,
   unsupported, bad checksum) and the packet is dropped without reaching the
   engine. On success it fills a `pkt_t` (contract in `engine.h`).
   A rejected packet is reported with `engine_parse_failed(e, result, dir,
   len, now_ns)`, so it is counted (per `parse_result_t`) and logged next to
   the engine's own drop reasons.
2. `engine_decide(e, &pkt, dir, now_ns, &reason)`:
   - **Anti-spoofing** (always on; the rules file must declare at least one
     `inside` network or the firewall refuses to start): outside
     packets may not carry an inside source address, and inside packets must
     (`DROP_BAD_SRC`).
   - **ICMP errors** (unreachable, time exceeded, parameter problem) are
     allowed only if all of these hold: the packet they embed belongs to a
     tracked flow; the error travels back toward that packet's sender and is
     addressed to it; a TCP flow is still active (not TIME_WAIT/CLOSED); and
     the flow has used fewer than 8 errors in the current second
     (`DROP_ICMP_RATE`). The error's own source is not checked, since it is a
     router on the path. Errors never change the flow or refresh its timer.
   - **Flow exists** (fast path): update TCP state / timers, no rules evaluated.
     Packets travelling the wrong way for the flow (spoofing) are dropped. On
     an ICMP echo flow the originator may only send echo requests and its
     peer only echo replies (`DROP_ICMP_TYPE`), and a rejected packet never
     refreshes the flow's timer.
   - **No flow** (slow path): only a pure TCP SYN (ECN bits allowed; PSH/URG
     or any other flag is not a SYN), a UDP datagram, or an ICMP echo request
     may start a flow. A SYN may carry data (TCP Fast Open). A flow must run
     between an inside and an outside host: inside-to-inside,
     outside-to-outside, or anything aimed at an inside network's broadcast
     address is dropped as `wrong-destination` whatever the rules say. Then the
     rule list is evaluated in order (first match wins). No match means drop.
     On allow, a flow is created.
   The flow table holds 65,536 flows by default (`FW_DEFAULT_MAX_FLOWS`). All
   slots are allocated once at startup, so no memory is allocated per
   connection or per packet. Two caps stop one party starving the rest:
   a single source address may hold at most 1/16 of the table (4096 flows,
   `per-source-limit`), and flows started from the outside at most 3/4 of it
   (`outside-quota`), so inside users keep a reserve even against a flood from
   many spoofed sources, which a per-source cap alone cannot stop. When the
   table is full, flows that already timed out are
   swept out first (at most once per second, so a flood cannot make every
   packet pay for a scan); if it is still full, new connections are refused and
   existing ones keep working. A finished TCP connection (TIME_WAIT or CLOSED)
   is not kept alive by traffic and cannot carry data.
   A packet that was allowed but could not be written to the other side does
   not leave a flow behind (`write-failed`). Because the kernel takes 1 off
   the TTL when it routes a packet into the tun device and again when it routes
   it out, the forwarder adds 1 (with an incremental checksum update) so the
   firewall counts as one hop, as traceroute expects. The flow hash is SipHash-2-4 with a random
   per-run key, so an attacker cannot craft flows that all share one bucket.
   Every flow close is logged once (`CLOSE` when TCP closes, `EXPIRE` when an
   idle flow times out, including one found expired by a lookup). Idle timeouts: half-open TCP 30 s, established
   TCP 1 hour, half-closed (one FIN seen) 1 hour, TIME_WAIT 30 s, after a RST
   5 s, UDP 30 s (120 s once answered), ICMP echo 30 s.
3. Caller forwards on `VERDICT_ALLOW`, discards on `VERDICT_DROP`, and calls
   `engine_expire()` about once a second.

For ICMP errors, `pkt.payload` is the embedded original packet;
`parse_icmp_inner()` extracts its 5-tuple, which the engine matches against
the flow table.

## Rules

See `config/rules.example.conf` and the syntax comment in `include/rules.h`.
Rules can be written in the compact form from the spec
(`allow out tcp 10.0.1.0/24 any 80,443`, `allow out icmp 10.0.1.0/24 any echo`,
`allow in tcp any 10.0.1.3 22`) or the longer `from ... to ... port ...` form;
both can be mixed. Only tcp and udp rules may name ports (a port on an `icmp`
or `any` rule is a syntax error, because it would silently widen the rule).
Ports may be a list of numbers and ranges (`80,443`, `22,8000-8100`; up to 8
items). `inside <cidr>` declares the trusted network(s) and is required: it drives
the address anti-spoofing check, and without it the firewall refuses to start.
`out` = connection initiated from the inside (the default); `in` = initiated
from the outside (exposed services).

## Not done yet / ideas

- TCP sequence-number validation (blind RST/injection protection)
- Full SYN-flood protection: a per-source cap and an outside-flow quota keep
  inside users working, but there are no SYN cookies and no half-open limit
- Application identification (HTTP/DNS by payload) or source NAT
- NAT from the outside namespace to the real Internet (the tests use a local web
  server in the outside namespace, which the spec allows)
- `perf` profile of `tunwall` and a written explanation of the throughput gap

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
| `include/appid.h`, `src/appid.c` | Application identification: recognizes HTTP, TLS and DNS from the payload (pure functions) | shared |
| `src/flowtable.c` | 5-tuple hash table, expiry | Eva |
| `src/tcpstate.c` | TCP state machine, per-state timeouts | Eva |
| `src/rules.c` | Rule file parser + first-match evaluation | Eva |
| `src/engine.c` | Fast path / slow path decision logic | Eva |
| `src/log.c` | Per-flow logs, counters | Eva |
| `include/nat.h`, `src/nat.c` | Source NAT with port translation: mapping table, RFC 1624 incremental checksums, ICMP error translation (`tunwall -n`) | Giselle |
| `src/forwarder.c`, `include/forwarder.h` | Packet loop: read, parse, decide, write to the other side, 1 s expiry sweep (works on any pair of fds, so it is unit-tested with socket pairs) | Giselle |
| `src/tun_io.c`, `src/main.c` | Opens the tun devices; `tunwall` program: arguments, signals, stats | Giselle |
| `scripts/netns.sh` | Three-namespace test topology with policy routing into the tun devices | Giselle |
| `bench/` | iperf3 and latency-percentile benchmark (`run_bench.sh`, `summary.py`), the CPU profile (`profile.sh`), and the rule files | Giselle |
| `scripts/demo.sh`, `scripts/demo_steps.sh`, `scripts/demo_log.awk`, `scripts/dns_forwarder.py` | The recorded demo: a tmux window with the live firewall log above and narrated, self-checking steps below, using the real Internet (see `DEMO.md`) | shared |
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
routing (plain kernel forwarding) as the benchmark baseline. `scripts/netns.sh
up nat` adds a path to the real Internet for the demo: the outside namespace
becomes a NAT gateway to the host. That changes the host while it is up (a veth
pair, `ip_forward`, three iptables rules tagged `tunwall-demo`) and `down`
removes exactly those and restores `ip_forward`. That host NAT is plumbing for
the demo; `tunwall`'s own source NAT is the `-n` option below.

### Source NAT (`-n`)

```
sudo ip netns exec firewall build/tunwall -r config/rules.example.conf -n 10.0.2.254
```

With `-n ADDR`, connections started from the inside leave with the outside
address `ADDR` and a port from 20000-59999 (for a ping, the echo identifier is
translated instead), so the outside never sees inside addresses, as on a home
router. This is the first optional feature from the spec (section 7).

- **Where it happens.** NAT sits around the engine, not inside it. A packet
  from the outside to `ADDR` is translated back to its inside host *before*
  `engine_decide()`, and an allowed packet from the inside is translated
  *after*. Rules, flow tracking, anti-spoofing and the logs therefore only ever
  see real inside addresses, and none of them needed to change.
- **Mappings.** There is one mapping per connection (5-tuple), and only the
  remote endpoint the connection was opened to may answer it (endpoint-dependent
  filtering, "symmetric" NAT). An unsolicited packet to `ADDR` is dropped
  silently and counted as `no-mapping`. A mapping lives exactly as long as its
  engine flow: the once-a-second sweep frees mappings whose flow has expired or
  closed. All 65,536 mapping slots are allocated at start-up. The inside lookup
  is a keyed (SipHash) hash, and the outside lookup is an array indexed by port,
  so both directions take constant time and nothing is allocated per packet.
  Connections the *outside* started, to an exposed service, are not translated.
- **Checksums.** Changing an address or port updates the IP header checksum
  and the TCP/UDP checksum (whose pseudo-header covers the addresses)
  incrementally with RFC 1624 (`HC' = ~(~HC + ~m + m')`) rather than
  recomputing them over the whole packet. A UDP checksum of 0 ("none") stays 0.
- **ICMP errors.** An error about a translated connection is translated too.
  That covers the outer address and the embedded original header (its address,
  port and checksums), and then the ICMP checksum is recomputed. Path-MTU
  discovery and traceroute therefore work through the NAT. This goes both ways:
  an error from the outside is turned back towards the inside host, and an
  inside host's error about a translated reply leaves from `ADDR`.
- **The test address.** `scripts/netns.sh` sets aside 10.0.2.254: the outside
  reaches it through the firewall's veth (a permanent neighbour entry, since no
  interface owns it). ICMP errors the firewall's own kernel sends to it are
  routed into `tun-out`, so `tunwall` translates them too.
- **Counters.** SIGUSR1 and exit add a line:
  `nat: addr= mappings active= created= freed= translated out= in= icmp-errors= dropped no-mapping= full=`.

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
source NAT, kill-the-firewall). The NAT section restarts `tunwall` with
`-n 10.0.2.254` and removes the outside's route back to the inside, so replies
can only come back through the NAT. It then checks that the outside sees
connections from 10.0.2.254, that curl (SHA-256), ping and DNS work, that
unsolicited packets to the NAT address are silently dropped, and that path MTU
discovery works, which needs ICMP error translation.

`tests/test_nat.c` checks every translated packet byte for byte against the
same packet built from scratch with the translated addresses. The builder,
`tests/pktbuild.c`, computes every checksum in full, so the incremental
updates are proven exact for TCP, UDP (with and without a checksum), ICMP echo,
and ICMP errors embedding truncated or whole TCP, UDP and echo packets. They need root, `nmap` and `python3`. CI sets
`REQUIRE_INTEGRATION=1` so a missing piece fails instead of skipping. Set
`SKIP_SLOW=1` to skip the 40 s expiry and 75 s half-close tests. `INTERNET=1`
also builds the NAT path and tests the real Internet through the firewall (the
same page, byte for byte, as the host fetches directly; non-web ports dropped;
flows labelled; and that tearing down restores the host). It needs the host to
be online, so it is off by default and CI does not run it. The suite fails when the firewall
is wrong: with the slow tests skipped, an allow-nothing policy fails 26 checks and an
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

Measured on the 2-CPU / 4 GB course VM with the machine otherwise idle: 5
iperf3 runs of 10 s (median of the receiver rate, with the range) and 5,000 pings
10 ms apart (percentiles of the pooled round-trip times). `bench/summary.py`
prints this table from the saved results; "added" is the firewall's value minus
the kernel baseline's, which is what the spec's "under 0.5 ms" goal is about.

| Setup | Throughput (median, range) | p50 | p95 | p99 | max | Added p50 | Added p99 |
|---|---|---|---|---|---|---|---|
| (a) kernel forwarding | 5.15 Gbit/s (2.31 - 5.34) | 0.036 | 0.076 | 0.145 | 6.860 | - | - |
| (b) `tunwall`, one rule | 1.28 Gbit/s (1.24 - 1.35) | 0.153 | 0.276 | 0.588 | 8.780 | +0.117 ms | +0.443 ms |
| (c) `tunwall`, 2000 rules | 1.34 Gbit/s (1.20 - 1.35) | 0.154 | 0.273 | 0.660 | 9.040 | +0.118 ms | +0.515 ms |

Latencies are ping round-trip times in ms. What this shows:
- **Throughput** is about 6 times the 200 Mbit/s goal, and about a quarter of the
  kernel's.
- **Latency:** the firewall adds about **0.12 ms at the median** and **0.44 to
  0.52 ms at the 99th percentile**, so the goal (under 0.5 ms) is met at the
  median and right at the limit in the tail. The 6 to 9 ms maxima appear for the
  kernel too, so they are the VM, not the firewall.
- **Rule count does not matter**: 2,000 rules give the same throughput range and
  the same latency as one rule, as expected (rules are only consulted for the
  first packet of a flow).
- The VM's absolute speed drifts a lot between sessions (the kernel baseline has
  measured 2.4, 5.2 and 8.9 Gbit/s on different days), so only comparisons made
  in the same session are meaningful.

### Where the time goes (`bench/profile.sh`)

`sudo bench/profile.sh` builds the topology, pushes iperf3 through the firewall
and records, over a steady-state window: a `perf` CPU profile (software clock, as
this VM has no hardware counters), how much of one core `tunwall` uses, packets
per second, and syscalls per packet. The measured explanation of the gap:

- **`tunwall` is limited by a single core.** It is single-threaded and runs at
  98 to 100% of one core, so its throughput is exactly (packets per second it can
  handle) x (packet size): about 142,000 packets/s of about 1,140 bytes, or 6.9
  microseconds of CPU per packet.
- **Two syscalls per packet, no more.** Measured with `strace -c`: 1.00 `read`,
  1.00 `write` and 0.01 `ppoll` per packet. The `poll` is already amortized over
  bursts of up to 64 packets.
- **About 90% of that time is the kernel, not our code.** Each packet is
  forwarded by the kernel twice (into the tun device, and out again after we write
  it back), plus a `read` and a `write` that copy it across the user/kernel
  boundary. The kernel baseline does one pass and no copies, and it can also use
  checksum and segmentation offload, which a userspace loop reading single
  packets cannot. That is the design's cost; the profile groups it as buffer
  allocation, IP forwarding and routing, device queues and softirq, syscall entry,
  and the two copies.
- **What was ours to fix: the checksum.** The first profile put `csum_partial`
  at 18% of all CPU time, the largest item in our own code: the parser validates
  the IP, TCP and UDP checksums (a spec requirement) and did it one 16-bit word at
  a time with a branch per word. It now adds 8 bytes per step with no branch
  (valid because the one's-complement sum does not depend on byte order, RFC
  1071). An equivalence test against the original covers every length 0 to 300 at
  every alignment, large and all-ones inputs and odd starting sums, and deliberately
  broken variants of the new code are all caught.

| | Before | After |
|---|---|---|
| `tunwall`'s own code, share of CPU time | 19.8% | 5.5% |
| of which parsing and checksums | 18.2% | 3.5% |
| CPU per packet | 8.96 us | 6.89 us |
| Packets per second (one core) | 111,000 | 142,000 |
| Throughput in the profile run | 1.02 Gbit/s | 1.29 Gbit/s |

An interleaved A/B (old and new `tunwall` alternating on the same topology, 8 runs
each) gives a median of 0.914 Gbit/s before and 1.235 Gbit/s after, **+35%**; the
worst new run (1.15) beats the best old run (0.98), so it is not noise.

What would be needed to go much faster is a different architecture, not tuning:
several threads on a multi-queue tun device, or larger packets through tun's
offload support. Those are future work. With our own code now about 5% of the
time, no more micro-optimizing of it would matter.

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
3. **Application identification** (optional feature from the spec, section 7).
   The first few data-carrying packets of a flow are examined (either
   direction, at most 3 before giving up) and the flow is labelled by what the
   payload *is*, not by its port: `http` (a request line such as
   `GET /x HTTP/1.1`, a response line, or the HTTP/2 preface), `tls` (a
   handshake record carrying a ClientHello or ServerHello), `dns` (a
   well-formed header plus one valid question, over UDP or over TCP with its
   length prefix), or `other`. The checks are deliberately strict: a wrong label
   is worse than none, so near-misses (`GETX / HTTP/1.1`, a TLS record with an
   impossible length, a DNS name with a 64-byte label) are not recognized. The
   label appears in the flow log lines (`app=tls`), a `FLOW APP` line is logged
   when it is decided, and the counters show `apps: http= tls= dns= other=
   mismatched=`. When the port suggests a different protocol than the payload
   (53 dns, 80 http, 443 tls) the `FLOW APP` line adds
   `mismatch(port suggests tls)` and the mismatch counter goes up, so HTTP on
   443, TLS on 80, or junk on 53 stands out. **It only labels: it runs after the
   verdict and never changes it** (it does not allow or drop anything), and a
   packet with no payload, or ICMP, is never labelled. Rules cannot match on the
   application, so, for example, TLS on 8080 is allowed or refused by the port
   rules exactly as before.
4. Caller forwards on `VERDICT_ALLOW`, discards on `VERDICT_DROP`, and calls
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
- Application identification only labels flows: rules cannot match on
  the application, and a flow is never dropped for what it carries
- Port forwarding (destination NAT) and endpoint-independent NAT mappings
  (full-cone, for peer-to-peer). Source NAT is symmetric: one mapping per connection
- Multi-threaded or offload-aware packet handling (the profile shows the remaining
  cost is in the kernel, so it would take a different architecture)

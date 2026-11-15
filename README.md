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
sudo ip netns exec firewall build/tunwall -r config/rules.example.conf -d
sudo ip netns exec inside curl http://10.0.2.2/   # in another terminal
sudo scripts/netns.sh down
```

`tunwall -r <rules> [-i tun-in] [-o tun-out] [-d | -q]`: `-d` also logs every
dropped packet with its reason, `-q` logs only errors. SIGUSR1 prints the
counters; SIGINT/SIGTERM stop it and print them. It refuses to start on a rules
syntax error (printing the line number), on a missing `inside` network, or if a
tun device does not exist.

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
`SKIP_SLOW=1` to skip the 40 s expiry test. The suite fails when the firewall
is wrong: against an allow-nothing policy 14 checks fail and against an
allow-everything policy 13 do.

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

The script refuses to run if the topology or the running firewall does not match
its label. First measurements (one 10 s iperf3 TCP run each, 2-CPU / 4 GB VM, so
treat as rough): kernel forwarding 8.75 Gbit/s, `tunwall` with one rule
1.11 Gbit/s, `tunwall` with 2000 rules 1.61 Gbit/s (not slower: rules are only
consulted for a new flow). Average ping RTT (200 pings): kernel 0.04 ms,
`tunwall` with 2000 rules 0.14 ms, `tunwall` with one rule 1.03 ms (a few
outliers up to 16.7 ms dominate that average; the spec's goal is under 0.5 ms
added). More and longer runs are needed before trusting these, and profiling
with `perf` to explain the gap is still to do (`PERF=1` records it).

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
   - **No flow** (slow path): only a pure TCP SYN, a UDP datagram, or an ICMP
     echo request may start a flow; the rule list is evaluated in order
     (first match wins). No match means drop. On allow, a flow is created.
   The flow table holds 65,536 flows by default (`FW_DEFAULT_MAX_FLOWS`). All
   slots are allocated once at startup, so no memory is allocated per
   connection or per packet. When it is full, flows that already timed out are
   swept out first (at most once per second, so a flood cannot make every
   packet pay for a scan); if it is still full, new connections are refused and
   existing ones keep working. The flow hash is SipHash-2-4 with a random
   per-run key, so an attacker cannot craft flows that all share one bucket.
   Every flow close is logged once (`CLOSE` when TCP closes, `EXPIRE` when an
   idle flow times out, including one found expired by a lookup). Idle timeouts: half-open TCP 30 s, established
   TCP 1 hour, UDP 30 s (120 s once answered), ICMP echo 30 s.
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
- SYN-flood protection (SYN cookies / half-open limits)
- Application identification (HTTP/DNS by payload) or source NAT
- NAT from the outside namespace to the real Internet (the tests use a local web
  server in the outside namespace, which the spec allows)
- `perf` profile of `tunwall` and a written explanation of the throughput gap

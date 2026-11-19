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
| `include/pipeline.h`, `src/pipeline.c` | Raw bytes → parse → engine; parse-drop counters | Giselle |
| `src/tun_io.c`, `src/main.c` | TUN devices, poll() I/O loop, signals (Linux) | Giselle |
| `scripts/` | Namespace harness, test servers, diagnostics | Giselle |
| `tests/` | Unit tests (`tests/pktbuild.c` builds real wire packets) | shared |
| `tests/integration/` | End-to-end tests on the namespace network | shared |

## Build and test

```
make          # builds build/libfwengine.a, plus ./tunwall on Linux
make test     # unit tests (run on macOS or Linux, no root needed)
make asan     # same tests under AddressSanitizer + UBSan
```

On macOS use `make CC=clang asan`: Homebrew gcc has no ASan runtime.

## Running on the VM (Linux, root)

One-time tools: `sudo apt-get install -y iproute2 iputils-ping curl dnsutils
nmap dnsmasq-base ethtool python3` (the scripts tell you if anything is missing).

```
make
sudo tests/integration/run.sh          # full end-to-end test (~1 min)
sudo SLOW=1 tests/integration/run.sh   # also checks idle-flow expiry (+40 s)
```

If something fails, the run prints `scripts/ns_diag.sh` output and the
tunwall log: paste the whole thing when asking for help.

By hand:

```
sudo scripts/ns_setup.sh               # inside / fw / outside namespaces
sudo scripts/servers.sh start          # HTTP + DNS on 10.0.2.2, listeners on 10.0.1.3:22/3389
sudo ip netns exec fw ./tunwall -r config/rules.example.conf -v

# in another terminal
sudo ip netns exec inside curl http://10.0.2.2/
sudo ip netns exec inside ping -I 10.0.1.2 10.0.2.2
sudo ip netns exec outside nmap -Pn -S 10.0.2.3 -e eth0 -p 20-25,3389 10.0.1.3
sudo ip netns exec fw pkill -USR1 tunwall   # print counters
sudo scripts/ns_diag.sh                # dump routing state
sudo scripts/ns_teardown.sh            # remove everything
```

Until tunwall is running (or after it dies), nothing crosses between inside
and outside: `fw` routes all inside/outside traffic into the TUN devices and
has blackhole rules behind them.

## How a packet is decided

1. `parse_packet(buf, len, &pkt)` validates the raw packet: IPv4 only, lengths
   consistent, IP/TCP/UDP/ICMP checksums good, no fragments, no martian
   addresses. On failure it returns a `parse_result_t` (malformed, fragment,
   unsupported, bad checksum) and the packet is dropped without reaching the
   engine. On success it fills a `pkt_t` (contract in `engine.h`).
2. `engine_decide(e, &pkt, dir, now_ns, &reason)`:
   - **Flow exists** (fast path): update TCP state / timers, no rules evaluated.
     Packets travelling the wrong way for the flow (spoofing) are dropped.
   - **No flow** (slow path): only a pure TCP SYN, a UDP datagram, or an ICMP
     echo request may start a flow; the rule list is evaluated in order
     (first match wins). No match means drop. On allow, a flow is created.
3. Caller forwards on `VERDICT_ALLOW`, discards on `VERDICT_DROP`, and calls
   `engine_expire()` about once a second.

For ICMP errors (unreachable, time exceeded, parameter problem), `pkt.payload`
is the embedded original packet; `parse_icmp_inner()` extracts its 5-tuple so
it can be matched against an existing flow.

## Rules

See `config/rules.example.conf` and the syntax comment in `include/rules.h`.
`out` = connection initiated from the inside (the default); `in` = initiated
from the outside (exposed services).

## Not done yet / ideas

- ICMP error messages matched against existing flows (spec item 6; parser
  side done via `parse_icmp_inner()`, engine side TODO)
- Address-based anti-spoofing: outside packets claiming an inside source, and
  inside packets with a non-inside source (spec item 7)
- Comma-separated port lists in rules (`80,443`, as in the spec example)
- Established TCP idle timeout is 300 s; the spec says 1 hour (item 5)
- Benchmarks (iperf3/ping vs kernel forwarding) and perf profiling
- TCP sequence-number validation (blind RST/injection protection)
- SYN-flood protection (SYN cookies / half-open limits)
- Application identification (HTTP/DNS by payload) or source NAT

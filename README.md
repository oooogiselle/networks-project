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
| `src/tun_io.c`, `src/main.c` | tun devices, I/O loop | Giselle (TODO) |
| `scripts/` | Namespace harness, benchmarks | Giselle (TODO) |
| `tests/` | Unit tests (`tests/pktbuild.c` builds real wire packets) | shared |

## Build and test

```
make          # builds build/libfwengine.a (parser + engine)
make test     # unit tests (run on macOS or Linux, no root needed)
make asan     # same tests under AddressSanitizer + UBSan
```

`tests/test_fuzz.c` throws random and corrupted packets at the parser and
engine and checks that nothing crashes and the counters stay consistent. It is
deterministic; replay or lengthen a run with
`FUZZ_SEED=<n> FUZZ_ITERS=<n> ./build/test_fuzz`.

On macOS use `make CC=clang asan`: Homebrew gcc has no ASan runtime.

## How a packet is decided

1. `parse_packet(buf, len, &pkt)` validates the raw packet: IPv4 only, lengths
   consistent, IP/TCP/UDP/ICMP checksums good, no fragments, no martian
   addresses. On failure it returns a `parse_result_t` (malformed, fragment,
   unsupported, bad checksum) and the packet is dropped without reaching the
   engine. On success it fills a `pkt_t` (contract in `engine.h`).
   A rejected packet is reported with `engine_parse_failed(e, result, dir,
   len, now_ns)`, so it is counted (per `parse_result_t`) and logged next to
   the engine's own drop reasons.
2. `engine_decide(e, &pkt, dir, now_ns, &reason)`:
   - **Anti-spoofing** (when the rules declare `inside` networks): outside
     packets may not carry an inside source address, and inside packets must
     (`DROP_BAD_SRC`).
   - **ICMP errors** (unreachable, time exceeded, parameter problem) are
     allowed only if the packet they embed belongs to a tracked flow and the
     error travels back toward that packet's sender. They never change the
     flow or refresh its timer.
   - **Flow exists** (fast path): update TCP state / timers, no rules evaluated.
     Packets travelling the wrong way for the flow (spoofing) are dropped.
   - **No flow** (slow path): only a pure TCP SYN, a UDP datagram, or an ICMP
     echo request may start a flow; the rule list is evaluated in order
     (first match wins). No match means drop. On allow, a flow is created.
   The flow table holds 65,536 flows by default (`FW_DEFAULT_MAX_FLOWS`). All
   slots are allocated once at startup, so no memory is allocated per
   connection or per packet. When it is full, new connections are refused and
   existing ones keep working. Idle timeouts: half-open TCP 30 s, established
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
both can be mixed. Ports may be a list of numbers and ranges (`80,443`, `22,8000-8100`; up to 8
items). `inside <cidr>` declares the trusted network(s) and turns on
address anti-spoofing; without it that check is off.
`out` = connection initiated from the inside (the default); `in` = initiated
from the outside (exposed services).

## Not done yet / ideas

- TCP sequence-number validation (blind RST/injection protection)
- SYN-flood protection (SYN cookies / half-open limits)
- Rate limiting of related ICMP errors
- Application identification (HTTP/DNS by payload) or source NAT

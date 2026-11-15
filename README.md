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

On macOS use `make CC=clang asan`: Homebrew gcc has no ASan runtime.

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
- Parse failures counted/logged alongside engine drop reasons (spec item 8)
- Comma-separated port lists in rules (`80,443`, as in the spec example)
- TCP sequence-number validation (blind RST/injection protection)
- SYN-flood protection (SYN cookies / half-open limits)
- Application identification (HTTP/DNS by payload) or source NAT

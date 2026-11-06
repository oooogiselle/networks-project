# Userspace Stateful Firewall

A stateful firewall in C that sits between two tun interfaces (`tun-in` =
trusted network, `tun-out` = untrusted network), parses raw IPv4 packets, and
allows or drops them using rules and connection tracking. Default policy: deny.

## Layout

| Path | Module | Owner |
|---|---|---|
| `include/engine.h` | Shared interface: `pkt_t`, `engine_decide()` | shared |
| `src/flowtable.c` | 5-tuple hash table, expiry | Eva |
| `src/tcpstate.c` | TCP state machine, per-state timeouts | Eva |
| `src/rules.c` | Rule file parser + first-match evaluation | Eva |
| `src/engine.c` | Fast path / slow path decision logic | Eva |
| `src/log.c` | Per-flow logs, counters | Eva |
| `src/parser.c`, `src/tun_io.c`, `src/main.c` | Packet parse + checksums, tun, I/O loop | Giselle (TODO) |
| `scripts/` | Namespace harness, benchmarks | Giselle (TODO) |
| `tests/` | Unit tests | shared |

## Build and test

```
make          # builds build/libfwengine.a
make test     # unit tests (run on macOS or Linux, no root needed)
make asan     # same tests under AddressSanitizer + UBSan
```

## How a packet is decided

1. Parser validates the packet and fills a `pkt_t` (contract in `engine.h`).
2. `engine_decide(e, &pkt, dir, now_ns, &reason)`:
   - **Flow exists** (fast path): update TCP state / timers, no rules evaluated.
     Packets travelling the wrong way for the flow (spoofing) are dropped.
   - **No flow** (slow path): only a pure TCP SYN, a UDP datagram, or an ICMP
     echo request may start a flow; the rule list is evaluated in order
     (first match wins). No match means drop. On allow, a flow is created.
3. Caller forwards on `VERDICT_ALLOW`, discards on `VERDICT_DROP`, and calls
   `engine_expire()` about once a second.

## Rules

See `config/rules.example.conf` and the syntax comment in `include/rules.h`.

## Not done yet / ideas

- TCP sequence-number validation (blind RST/injection protection)
- SYN-flood protection (SYN cookies / half-open limits)
- Application identification (HTTP/DNS by payload) or source NAT

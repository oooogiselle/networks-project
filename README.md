# Userspace Stateful Firewall

A stateful firewall in C that sits between two tun interfaces (`tun-in` =
trusted network, `tun-out` = untrusted network), parses raw IPv4 packets, and
allows or drops them using rules and connection tracking. Default policy: deny.
CS 60 final project (Giselle Wu, Eva Tate). See `requirements-spec.pdf`.

## Layout

| Path | Module | Written by |
|---|---|---|
| `include/engine.h` | Shared interface: `pkt_t`, `engine_decide()` | shared |
| `include/parser.h`, `src/parser.c` | Packet parse + checksums → `pkt_t` (including TCP sequence numbers and window scale) | Giselle |
| `include/reject.h`, `src/reject.c` | Builds the answer to a `reject` rule: a TCP RST or an ICMP unreachable, with checksums (pure function) | Giselle |
| `include/nat.h`, `src/nat.c` | Source NAT with port translation and port forwarding: mapping table, RFC 1624 incremental checksums, ICMP error translation (`tunwall -n`, `forward` rules) | Giselle |
| `include/appid.h`, `src/appid.c` | Application identification: recognizes HTTP, TLS and DNS from the payload (pure functions) | Eva |
| `src/flowtable.c` | 5-tuple hash table, expiry | Eva; half-open eviction queue for SYN-flood relief: Giselle |
| `src/tcpstate.c` | TCP state machine, per-state timeouts | Eva |
| `src/rules.c` | Rule file parser + first-match evaluation | Eva; `forward` lines, `limit` and `app`: Giselle |
| `src/engine.c` | Fast path / slow path decision logic | Eva; swapping the rules on reload, the scan-detection, SYN-flood, rate-limit, TCP sequence-check and app-rule hooks: Giselle |
| `src/log.c` | Per-flow logs, counters | Eva |
| `include/scandetect.h`, `src/scandetect.c` | Port-scan detection: distinct ports per outside host in a sliding window, temporary blocking (`tunwall -s`) | Giselle |
| `include/ratelimit.h`, `src/ratelimit.c` | Per-rule connection rate limits (`limit 5/min` on an allow rule): a token bucket (GCRA) per rule and source address in a fixed table | Giselle |
| `include/tcpseq.h`, `src/tcpseq.c` | TCP sequence-number checks: each direction's sequence window, so forged RSTs and injected data are dropped (`tunwall -L` turns them off) | Giselle |
| `src/forwarder.c`, `include/forwarder.h` | Packet loop: read, parse, decide, write to the other side, 1 s expiry sweep (works on any pair of fds, so it is unit-tested with socket pairs) | Eva; NAT, port forwarding and reject hooks: Giselle |
| `src/tun_io.c`, `src/main.c` | Opens the tun devices; `tunwall` program: arguments, signals, stats | Eva; `-n`, `-s` and SIGHUP reload: Giselle |
| `scripts/netns.sh` | Three-namespace test topology with policy routing into the tun devices | Eva; the NAT test address: Giselle |
| `bench/` | iperf3 and latency-percentile benchmark (`run_bench.sh`, `summary.py`), the CPU profile (`profile.sh`), and the rule files | Eva |
| `scripts/demo.sh`, `scripts/demo_steps.sh`, `scripts/demo_log.awk`, `scripts/dns_forwarder.py` | The recorded demo: a tmux window with the live firewall log above and narrated, self-checking steps below, using the real Internet (see `DEMO.md`) | Eva |
| `tests/` | Unit tests (`tests/pktbuild.c`, by Giselle, builds real wire packets); each module's tests are by its author | shared |
| `tests/integration/run_all.sh` | End-to-end tests in the namespace topology | Eva; NAT, port forwarding, reload and port-scan sections: Giselle |

The first plan gave the tun I/O, the namespace topology and the benchmarks to
Giselle. Eva's versions of those were merged first (#6), so Giselle's own
harness was kept as a record in draft PR #11 rather than merged. Giselle then
took the parser, reject rules, source NAT, port forwarding and rule reload.

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

`tunwall -r <rules> [-i tun-in] [-o tun-out] [-n ADDR] [-s P,W,B] [-L] [-f | -q]`
(`-n` turns on source NAT, `-s` tunes port-scan detection, `-L` turns off the
TCP sequence-number checks, all below). By default every flow
open/close and every dropped packet (with its reason) is logged to stderr. The
logging is rate-limited to 1000 lines per second (bursts of 1000, shared by all
kinds of line) so a flood or a scan cannot turn into a flood of log writes; when
lines had to be dropped a `N log lines suppressed` line says how many, and the
counters are never limited. `-f` logs flows only, `-q` logs only errors, `-d` is
accepted for old scripts. SIGUSR1 prints the counters; SIGINT/SIGTERM stop it
and print them (exit status 0). SIGHUP reloads the rules file without a restart
(`sudo ip netns exec firewall pkill -HUP tunwall`): the new rules govern
connections that start from then on, existing flows keep going (as Linux
conntrack keeps ESTABLISHED connections when iptables rules change), and a
file with an error (reported with its line number), with no `inside` network,
or that cannot be read is refused while the running rules stay exactly as
they were. It refuses to start, naming the file, on a rules
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
  `nat: addr= mappings active= created= freed= translated out= in= icmp-errors= dropped no-mapping= full= forwarded=`.

### Port forwarding (`forward`)

With source NAT on, the outside can't reach an inside server at all: its
address is hidden. A `forward` line in the rules file publishes one port of the
NAT address, like a home router's port forwarding:

```
inside  10.0.1.0/24
forward tcp 8080 10.0.1.3 80        # 10.0.2.254:8080 from outside -> 10.0.1.3:80
allow in tcp any 10.0.1.3 80        # the filter still has to allow it
```

- **What happens.** A new connection from the outside to `ADDR:8080` (a TCP
  SYN, or a UDP datagram) gets a mapping, and its destination is rewritten to
  `10.0.1.3:80` before `engine_decide()`. The server's replies are found by
  that mapping and leave from `ADDR:8080`, so the client sees one consistent
  peer. The client's own address is kept, so the server and the log show who
  connected (`FLOW NEW tcp 10.0.2.3:51000 -> 10.0.1.3:80`).
- **The filter still decides.** A forward only translates. The engine then
  decides the connection like any other inbound one, so it needs an `allow in`
  rule (in iptables terms, DNAT in the nat table plus ACCEPT in FORWARD). If the
  engine refuses the first packet (no rule, a `deny`, a `reject`, or a full flow
  table), or the write fails, the new mapping is removed at once, so refused
  SYNs leave nothing behind. A `reject` here drops silently, since its answer
  would leak the hidden inside address.
- **Same table as source NAT.** Forward mappings live in the same preallocated
  table. A forwarded port is shared by every client, so it has no slot in the
  by-port array; instead forward mappings are also kept in a second keyed hash
  by their outside side (protocol, port, client address and port), so inbound
  packets are found in constant time, even after a reload changed the forward.
  The external port must be outside the source-NAT range
  (20000-59999), so the two never compete for a port. ICMP errors about a
  forwarded connection are translated both ways, as for source NAT, and a
  mapping is freed with its flow.
- **Checks.** A forward needs `-n`, a single target address inside an `inside`
  network, tcp or udp, and an external port no other forward uses (up to 16).
  Any mistake is refused at start-up and on SIGHUP, naming the line, and a bad
  reload keeps the old rules *and* forwards. Forwards changed by a reload apply
  to new connections; open ones keep going to the server they started with.
- **Limits.** No hairpinning (an inside host can't use `ADDR:8080` itself), no
  forwarding of port ranges or ICMP, and forwards only work with `-n`.

### Port-scan detection (`-s`)

An outside host that gets dropped on **20 different ports within 5 seconds** is
treated as a port scanner: tunwall logs it and drops **everything** it sends
for **60 seconds**, existing connections included. Other hosts are not
affected.

```
[  12.345678] SCAN    10.0.2.3 dropped on 20 ports in 0.84s, blocking for 60s
[  72.401234] UNBLOCK 10.0.2.3 (dropped 1874 packets while blocked)
```

- **What counts.** An outside TCP or UDP packet refused by the policy (no
  rule, `deny`, `reject`) or a TCP packet with no connection that is not a SYN,
  so SYN, ACK, FIN, NULL, Xmas and UDP scans all count. The port is the
  destination (protocol, port), on any inside host. With `-n`, unsolicited
  packets to the NAT address count too (they never reach the rules), so a scan
  of the public address is caught. Allowed packets, ICMP, inside hosts, drops
  on existing flows, spoofed sources and wrong destinations never count.
- **Sliding window.** Each port remembers when it was last hit, and hits older
  than 5 s are forgotten, so a scan split across a window boundary is still
  caught.
- **Bounded.** 4096 sources are tracked in a fixed table (about 1.5 MB, allocated
  at start-up; nothing per packet), chosen by a keyed SipHash so forged
  addresses cannot be aimed at one slot. When a slot is needed the least
  recently seen unblocked source gives way. While nobody is blocked, the check
  costs nothing on the fast path.
- **Settings.** `-s PORTS[,WINDOW_S[,BLOCK_S]]` changes them (default
  `-s 20,5,60`); `-s 0` turns detection off. The counters show
  `scan: detected= blocked-now=` and `drop[scan-blocked]=`.
- **What nmap shows.** nmap tries common ports such as 22 first, so a plain
  `nmap -p 1-1000` usually finds 22 open before the 20th drop; after that it
  gets no answers and slows to a crawl (about 6 s without detection, 100 s or
  more with it). With `-r` (ports in order) 22 comes after the cut-off and is
  never found. The demo uses that.
- **Limitation.** A source address can be forged, so someone can get a
  legitimate outside host blocked for 60 s by faking a scan from its address.
  An allowlist of never-blocked hosts would fix this.

### SYN-flood relief

A SYN flood from many forged source addresses would fill the table with
**half-open** connections (a SYN with no completed handshake), each living
30 s, and shut real clients out of the exposed services. The per-source cap
does not help when every source is different, and the connections have not
timed out yet, so sweeping them does not free room either.

When a new connection is refused because the table is full or the outside
share is used up, tunwall **evicts the oldest outside connection that never
finished its handshake** and admits the new one, exactly as the Linux kernel
drops the oldest entry from a full SYN backlog. Established connections and
connections started from the inside are never evicted; nor is anything evicted
to make room for a source that is already over its own per-source cap. It is
always on, costs nothing on the fast path, and only ever turns a refusal into
an admission. The outside-started connections are kept in a FIFO queue
(`ft_evict_halfopen` in `src/flowtable.c`); entries that completed their
handshake are dropped from the queue as they are passed over, so each eviction
is O(1) amortized.

Under a flood the counters show `flows: ... evicted=N`, and once a second (not
per packet, which at flood rates would just trip the log limiter) a summary
line is written: `SYNFLOOD table under pressure: evicted N half-open
connections in the last 1.0s to admit new ones`.

Not done, and why: **SYN cookies** would need the firewall to answer the SYN
itself (a SYN proxy), since it is a middlebox, not the connection's endpoint.
A real handshake must still complete within roughly `3/4 of the table / flood
rate` (about 0.3 s at ~170k SYN/s) before its own half-open entry is evicted —
the Linux SYN backlog has the same property. A **UDP** flood to an allowed port
is not covered: UDP has no handshake that tells a real datagram from a forged
one.

### Per-rule connection rate limits (`limit`)

An `allow` rule can cap how many **new connections** each source address may
open through it, which slows down password guessing against an exposed
service:

```
allow in tcp any 10.0.1.3 22 limit 5/min
```

Each outside host may open 5 SSH connections straight away, then one more
every 12 s. A connection over the limit is dropped silently, so the client
just times out, as it would for a firewalled port. Other hosts are not
affected, and connections that are already open never are.

```
[  31.204518] LIMIT   10.0.2.3 over 5/min on rule line 2, dropping its new connections
```

- **Syntax.** `limit N/sec`, `N/min` or `N/hour` (N from 1 to 10000), as the
  last two words of an `allow` rule, in either rule form, with or without
  ports. On `deny` or `reject` it is a syntax error (naming the line).
- **Token bucket.** The limit is a bucket of N tokens, refilled at N per
  period, kept separately for each (rule, source address) pair, as with
  iptables' `hashlimit` in `srcip` mode. It is implemented as GCRA (the
  generic cell rate algorithm), which keeps one number per pair: the time at
  which the bucket would be full again. With `T = period/N`, a connection is
  admitted if `now >= tat - (period - T)`, and then `tat = max(tat, now) + T`.
  All the arithmetic is in integer nanoseconds.
- **What counts.** Only connections the rule actually admits. A refused SYN
  costs nothing, so a client that keeps retrying is not locked out for longer.
  A retransmitted SYN of an admitted connection belongs to its flow and is not
  counted again. A connection that is admitted but then never set up (flow
  table full, or its first packet could not be written) is given back.
  Rate-limited drops do not count toward port-scan detection.
- **Log and counters.** One `LIMIT` line when a source first goes over the
  limit, and another only after it has been admitted again (not one per
  packet). Each refused packet is counted as `drop[rate-limited]=` and logged
  at debug level with `why=rate-limited`.
- **Bounded.** The table tracks 4096 (rule, source) pairs (1024 sets x 4,
  about 96 KB, allocated at start-up; nothing per packet). Sets are chosen
  with a keyed SipHash. When a set is full, the pair whose bucket is fullest
  gives way. A pair whose bucket is already full again loses nothing by this.
- **Reload.** SIGHUP resets all counts (rule numbers may have changed).
- **Limitations.** It limits connections, not password attempts inside one
  connection (sshd's `MaxAuthTries`, 6 by default, still applies). Someone
  sending from very many forged addresses can push a real attacker's pair out
  of a full set, which resets that attacker's bucket.

By hand (`sudo scripts/netns.sh up` first):

```
sudo ip netns exec inside python3 -m http.server 22 --bind 10.0.1.3 &   # an ssh-like listener
printf 'inside 10.0.1.0/24\nallow in tcp any 10.0.1.3 22 limit 5/min\n' > /tmp/limit.conf
sudo ip netns exec firewall build/tunwall -r /tmp/limit.conf &
for i in 1 2 3 4 5 6; do
    sudo ip netns exec outside python3 tests/integration/probe.py tcp 10.0.1.3 22
done                          # open x5, then timeout; the log shows LIMIT 10.0.2.2
sleep 12; sudo ip netns exec outside python3 tests/integration/probe.py tcp 10.0.1.3 22   # open
```

### TCP sequence-number checks (`-L` turns them off)

Following a connection by its flags alone leaves a hole. Anyone who knows a
connection's addresses and ports (a web server's, say, which are public) can
end it with **one forged RST**, or slip data into it, without ever seeing a
packet of it: the firewall would believe the RST, mark the flow closed and
drop everything after. So tunwall also tracks each direction's **sequence
window**, as Linux conntrack (`tcp_in_window`) and pf do, after van Rooij's
"Real Stateful TCP Packet Filtering". A segment outside it is dropped as
`tcp-out-of-window` before it can change anything.

- **What is remembered.** For each direction: the highest sequence number it
  has sent (`end`), the highest its peer has allowed it (`maxend` = the peer's
  ack + window), and the largest window it has advertised (`maxwin`).
- **The checks.** A segment from sender `s` to receiver `r`, with
  `end = seq + length` (SYN and FIN count one each), must pass all four
  (comparisons modulo 2^32, so sequence numbers may wrap):

  | | Rule | Refuses |
  |---|---|---|
  | A | `seq <= s.maxend` | data beyond what the receiver allowed |
  | B | `end >= s.end - r.maxwin` | segments more than a window old |
  | C | `ack <= r.end` (if ACK) | acknowledging data never sent |
  | D | `ack >= r.end - max(s.maxwin, 66000)` (if ACK) | stale acknowledgments |

  A forged RST must therefore land inside the receiver's window: a blind
  guess succeeds with probability about window / 2^32 instead of always.
- **The handshake.** The SYN that creates the flow sets up the originator's
  window. The SYN-ACK must acknowledge that SYN (ack between ISN + 1 and the
  end of the SYN, since a TCP Fast Open server may ack only the SYN and not
  its data) and sets up the responder's. A repeated SYN must carry the same
  ISN, except that the originator may start over with a new one before any
  answer. Window scaling (RFC 7323) is applied only if both SYNs offered it,
  and windows in SYNs are never scaled. An RST refusing a connection must
  acknowledge the SYN (RFC 793). Simultaneous open works.
- **What is not checked.** SACK blocks and timestamps (PAWS), as in Linux by
  default. Retransmissions, zero-window probes and keepalives fall inside the
  window and pass.
- **Cost.** A few comparisons per TCP packet on the fast path, and the parser
  reads TCP options only on a SYN. The windows add 2 x 20 bytes to each
  preallocated flow slot.
- **On and off.** `tunwall` turns the checks on; `-L` ("liberal", like Linux's
  `nf_conntrack_tcp_be_liberal`) turns them off. The library's
  `engine_create*` leave them off (`engine_set_tcp_window()`), because most
  unit tests drive the engine with flag-only packets. A dropped segment is
  logged (`why=tcp-out-of-window`) and counted (`drop[tcp-out-of-window]=`),
  never refreshes the flow's timer, and does not count toward scan detection.

The end-to-end test attacks a live connection, from the outside namespace,
with segments forged as the server (`tests/integration/inject.py`):

```
blind RST  (seq half the space away)   -> dropped, connection keeps working
blind data (seq a quarter away)        -> dropped, never reaches the client
RST at the exact next seq (on-path)    -> passes, connection reset
blind RST again, with tunwall -L       -> passes, firewall cuts the connection
```

The last line is the hole this closes. The client's own TCP ignores the
out-of-window RST (RFC 5961), but a firewall that believed it would mark the
flow closed and drop everything after it.

### App-aware rules (`app`)

A port rule says nothing about what runs on the port: `allow out tcp ... 80`
lets an SSH tunnel, TLS or any covert channel out, as long as it uses port 80.
An `allow` rule can therefore also name the applications it allows, using the
labels from application identification (see "How a packet is decided"):

```
allow out tcp 10.0.1.0/24 any 80,443 app http      # only HTTP, on either port
allow out udp 10.0.1.0/24 10.0.2.2 53 app dns      # only real DNS to the resolver
```

- **Syntax.** `app NAME[,NAME...]` with NAME `http`, `tls`, `dns` or `other`,
  at the end of an `allow` rule for `tcp` or `udp` (ICMP is never labelled, so
  `app` on an `icmp` or `any` rule is a syntax error). It may be combined with
  `limit`, in either order.
- **When a flow is cut.** The rule is chosen on the first packet as always.
  The flow's payload is then identified as usual: the first recognized
  protocol, or `other` after three data packets that are none of them. If
  that label is not in the rule's list, the flow is **blocked**:
  - the packet that decided it is dropped, and so is every later packet in
    either direction (`why=app-not-allowed`);
  - ICMP errors about the flow are refused;
  - one line is logged:
    `FLOW BLOCK  tcp 10.0.1.2:41000 -> 10.0.2.2:443 state=ESTABLISHED rule=2 app=tls ...`;
  - its slot is freed 10 s later, instead of after the usual idle timeout.

  A TLS connection is cut at its ClientHello and never completes its
  handshake. Something unrecognized, such as an SSH banner, gets at most two
  data packets through before it is called `other`, which is inherent to
  identifying by payload. Data carried in a SYN (TCP Fast Open) or a UDP
  flow's first datagram is checked as it creates the flow.
- **A condition on the rule, not a new match.** A blocked flow does not fall
  through to a later rule: rules are matched once, on the first packet, as in
  the rest of the firewall. A reload (SIGHUP) leaves open connections under
  the rule that admitted them.
- **Counters.** `drop[app-not-allowed]=` counts the packets and
  `apps: ... blocked=` the flows. These drops never count toward scan
  detection. Rules without `app` only label, exactly as before.

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
refused, reject rules, nmap SYN/ACK/FIN/NULL/Xmas scans, application
identification, exact log lines, flow expiry, TTL and path MTU, source NAT,
port forwarding, SYN-flood relief, connection rate limits, forged TCP
RSTs and data, app-aware rules, SIGHUP reload,
kill-the-firewall). They
need root, `nmap`, `hping3` and `python3`.
- **Source NAT.** The section restarts `tunwall` with `-n 10.0.2.254` and removes
  the outside's route back to the inside, so replies can only come back through
  the NAT. It checks that the outside sees connections from 10.0.2.254, that curl
  (SHA-256), ping and DNS work, that unsolicited packets to the NAT address are
  silently dropped, and that path MTU discovery works, which needs ICMP error
  translation.
- **Port forwarding.** The outside reaches an inside server through
  `10.0.2.254:8080`, the server sees the real client address, and a port nobody
  forwards stays silently dropped.
- **Reload.** Appending a rule and sending SIGHUP opens a port that was dropped.
  A broken file is refused, `tunwall` keeps running, and the old rules still
  apply.
- **Port-scan detection.** Its own run at the end with `-s 20,5,10` (a 10 s
  block, to keep it short). An nmap scan of client B from 10.0.2.3 is
  detected, nmap never finds port 22, 10.0.2.3 is cut off while 10.0.2.2 still
  connects, and 10.0.2.3 gets back in after the block. Then a scan of the NAT
  address is detected and closes the port forward to the scanner only.
- **Rate limits.** With `allow in tcp any 10.0.1.3 22 limit 5/min`, 10.0.2.3
  opens 5 connections and the 6th times out. The `LIMIT` line and the
  `drop[rate-limited]` counter appear, 10.0.2.2 still connects, and no scan
  is reported. Unless `SKIP_SLOW` is set, 12 s later exactly one more
  connection gets in.
- **TCP sequence checks.** A forged RST and forged data with wrong sequence
  numbers are dropped (`why=tcp-out-of-window`) and the connection keeps
  echoing. An RST with the right sequence number still resets it. With `-L`
  the same blind RST cuts the connection at the firewall.
- **App-aware rules.** With `app http` on ports 80 and 443:
  - curl over HTTP on port 80 works, and the SHA-256 matches;
  - HTTP on port 443 works too;
  - a real TLS handshake on 443 is cut, with a `FLOW BLOCK ... app=tls` line;
  - an SSH-like session through an `app http` port is cut after its third
    packet.

  Real DNS passes `app dns`, and the counters show the blocked packets and
  flows.

CI sets `REQUIRE_INTEGRATION=1` so a missing piece fails instead of skipping. Set
`SKIP_SLOW=1` to skip the 40 s expiry and 75 s half-close tests (and the 12 s
rate-limit refill). `INTERNET=1`
also builds the NAT path and tests the real Internet through the firewall (the
same page, byte for byte, as the host fetches directly; non-web ports dropped;
flows labelled; and that tearing down restores the host). It needs the host to
be online, so it is off by default and CI does not run it. The suite fails when the firewall
is wrong: with the slow tests skipped, an allow-nothing policy fails 26 checks and an
allow-everything policy fails 16.

`tests/test_nat.c` checks every translated packet byte for byte against the
same packet built from scratch with the translated addresses. The builder,
`tests/pktbuild.c`, computes every checksum in full, so the incremental
updates are proven exact for TCP, UDP (with and without a checksum), ICMP echo,
and ICMP errors embedding truncated or whole TCP, UDP and echo packets, both
for source NAT and for port forwarding. `tests/test_reload.c` checks that
swapped rules govern new connections while existing flows keep going, and that
a bad file (syntax error, no `inside` network, missing) changes nothing.
`tests/test_reject.c` checks each reject answer (RST, port unreachable,
administratively prohibited), and that RSTs and ICMP errors are
never answered.

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
   - **Scan block**: an outside host blocked for port scanning has every
     packet dropped (`scan-blocked`), on existing flows too. See
     [Port-scan detection](#port-scan-detection--s).
   - **ICMP errors** (unreachable, time exceeded, parameter problem) are
     allowed only if all of these hold: the packet they embed belongs to a
     tracked flow; the error travels back toward that packet's sender and is
     addressed to it; a TCP flow is still active (not TIME_WAIT/CLOSED); and
     the flow has used fewer than 8 errors in the current second
     (`DROP_ICMP_RATE`). The error's own source is not checked, since it is a
     router on the path. Errors never change the flow or refresh its timer.
   - **Flow exists** (fast path): update TCP state / timers, no rules evaluated.
     A TCP segment must fall inside the connection's sequence window
     (`tcp-out-of-window`, see
     [TCP sequence-number checks](#tcp-sequence-number-checks--l-turns-them-off)).
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
     On allow, a flow is created, unless the rule has a `limit` and this
     source has used it up (`rate-limited`, see
     [Per-rule connection rate limits](#per-rule-connection-rate-limits-limit)).
   The flow table holds 65,536 flows by default (`FW_DEFAULT_MAX_FLOWS`). All
   slots are allocated once at startup, so no memory is allocated per
   connection or per packet. Two caps stop one party starving the rest:
   a single source address may hold at most 1/16 of the table (4096 flows,
   `per-source-limit`), and flows started from the outside at most 3/4 of it
   (`outside-quota`), so inside users keep a reserve even against a flood from
   many spoofed sources, which a per-source cap alone cannot stop. When the
   table is full, flows that already timed out are
   swept out first (at most once per second, so a flood cannot make every
   packet pay for a scan); failing that, under a SYN flood the oldest outside
   connection that never finished its handshake is evicted so real clients
   still get in (see [SYN-flood relief](#syn-flood-relief)); if it is still
   full, new connections are refused and existing ones keep working. A finished
   TCP connection (TIME_WAIT or CLOSED) is not kept alive by traffic and cannot
   carry data.
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
   443, TLS on 80, or junk on 53 stands out. A packet with no payload, or ICMP,
   is never labelled. **For a rule without `app`, it only labels**: it runs
   after the verdict and never changes it, so TLS on 8080 is allowed or refused
   by the port rules exactly as before. For a rule with an `app` list, a flow
   whose label is not on the list is cut from that packet on
   (`app-not-allowed`, see [App-aware rules](#app-aware-rules-app)).
4. Caller forwards on `VERDICT_ALLOW`, discards on `VERDICT_DROP`, answers on
   `VERDICT_REJECT` (see [Reject rules](#reject-rules)), and calls
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
from the outside (exposed services). With source NAT on, `forward tcp|udp <port> <ip> <port>`
publishes an inside service on the NAT address (see Port forwarding above).
An `allow` rule may end in `limit N/sec|min|hour` to cap the new connections
each source opens through it (see Per-rule connection rate limits above), and
in `app http|tls|dns|other[,...]` to allow only those applications (see
App-aware rules above).

### Reject rules

`reject` (an optional feature from spec section 7) refuses a new connection
like `deny`, but tells the sender at once instead of letting it time out:

| First packet | Answer |
|---|---|
| TCP SYN | RST (with ACK, acknowledging the SYN, per RFC 793) |
| UDP datagram | ICMP port unreachable (3/3) quoting the datagram |
| ICMP echo request | ICMP administratively prohibited (3/13) |

The answer poses as the host the packet was sent to and goes back out the
interface the packet came in on, the same path a real reply takes, so the
client's kernel matches it to the socket: `curl` fails with "Connection
refused" in milliseconds instead of hanging. The shipped config rejects telnet
(23) and TFTP (69) from the inside. Safeguards:
- the default policy is still a **silent** drop, so `nmap` from outside still
  sees only `filtered` ports. Use `reject` for your own users' outbound traffic.
- a RST, an ICMP error or an echo reply is never answered, so two firewalls
  can't answer each other forever.
- at most `REJECTS_PER_SEC` (100) answers are sent per second. Past that,
  rejected packets are dropped silently and counted
  (`reject: over-the-rate-limit(dropped-silently)=N`), so forged floods can't
  aim RSTs at someone else.
- with source NAT on, a packet the NAT translated back to an inside address is
  never answered (it is dropped silently): the answer would carry that hidden
  inside address as its source.
- the log says `why=rule-reject`, and the `io:` counter line says `rejects=N`.

## Not done yet / ideas

- App-aware rules only know the four labels application identification
  gives (`http`, `tls`, `dns`, `other`); there is no SSH, QUIC or TLS-SNI
  matching
- Endpoint-independent NAT mappings (full-cone, for peer-to-peer). Source NAT
  is symmetric: one mapping per connection. Port forwarding has no hairpinning
- Multi-threaded or offload-aware packet handling (the profile shows the remaining
  cost is in the kernel, so it would take a different architecture)

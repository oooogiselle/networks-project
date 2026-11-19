# The demo: how to run it and what to say

One command runs the whole recorded demo against the **real Internet**:

```
scripts/demo.sh        # builds, sets up, opens the split-pane window
```

You get a tmux window split in two. The **top pane** is the firewall's live log
(colour-coded). The **bottom pane** walks through 12 steps and waits for
**Enter** before each one, so the presenter sets the pace. Every step runs the
real command and *checks* the result and the matching log line, printing a tick
or a cross. After the last step, press Enter once more and everything is torn
down.

Other commands: `scripts/demo.sh auto` runs all 12 steps unattended (no tmux)
and exits 0 only if every check passed, which is the quickest way to find out
the demo is healthy before recording. `scripts/demo.sh stop` cleans up from any
state, for example after closing the terminal in the middle.

## Before you record

- Use a **wide, full-screen terminal** (160 columns or more) and a large font.
  The log lines are about 100 characters.
- Run `scripts/demo.sh auto` once. It should end with `Demo checks: 28 passed, 0 failed`.
- The VM must be online (it fetches example.com and talks to 1.1.1.1).
- Needs `sudo`, `tmux`, `nmap`, `dig`, `curl`. Nothing else.
- **What it changes on the machine, temporarily:** a veth pair, `ip_forward`
  (restored), and three iptables rules tagged `tunwall-demo`. `scripts/demo.sh
  stop` removes exactly those and nothing else.

## The log colours (top pane)

| Colour | Meaning |
|---|---|
| green | a flow was opened (`FLOW NEW`) |
| cyan | the application was identified (`FLOW APP ... app=tls`) |
| **magenta** | the port disagrees with the payload (`mismatch(port suggests tls)`) |
| red | a packet was dropped, with the reason (`why=no-rule(default-deny)`) |
| grey | a flow closed or expired |
| **yellow** | a port scanner was blocked (`SCAN`) or let go (`UNBLOCK`) |

## The steps, with a line to say for each

| # | Step | What to point at | Say something like |
|---|---|---|---|
| 1 | Setup and policy | the diagram and the rules file | "Every packet between the two networks goes through our program. Default deny: if no rule matches, it is dropped." |
| 2 | Ping the Internet | a green `FLOW NEW icmp` line | "Ping is allowed out, and the reply is allowed back because it matches the flow the request created." |
| 3 | A real web page | two identical SHA-256 values, cyan `app=http` and `app=tls` | "The same bytes arrive through the firewall as directly. Notice it labelled the flows by what the traffic is, not by its port." |
| 4 | DNS | `app=dns`, then a red `rule-deny` for 8.8.8.8 | "Only our trusted resolver is allowed. Any other resolver is dropped by an explicit deny rule." |
| 5 | Application identification | the **magenta** mismatch line | "This is plain HTTP on port 443. The port is allowed, so it goes through, but the firewall sees the payload is HTTP, not TLS, and flags it." |
| 6 | Default deny | red `no-rule` drops, `result: timeout` | "The attacker gets no answer at all: no reset, no ICMP error. It can't even tell the host exists." |
| 7 | nmap | one open port, the rest `filtered` | "Only the port with a rule shows as open. An ACK scan finds nothing either." |
| 8 | Exposed service | green inbound `FLOW NEW` | "Port 22 has a rule allowing it in, so that one works and is tracked." |
| 9 | Port scanner cut off | the **yellow** `SCAN` line, `Not shown: 100 filtered`, then `curl exit 28` | "Now 10.0.2.3 scans ports 1 to 100. After 20 dropped ports in 5 seconds the firewall calls it a scan and drops everything from that host for a minute. So port 22, open a moment ago, is never found, while 10.0.2.2 can still use it." |
| 10 | Counters | the stats block in the top pane, including `scan: detected=1` | "SIGUSR1 prints packets, drops by reason, the applications seen, scans detected, and any log lines suppressed." |
| 11 | Performance | the benchmark table | "About 1.3 Gbit/s versus 5 for the kernel on this VM, adding about 0.12 ms at the median. We are single-threaded, and the profile shows most of the time is the kernel forwarding each packet twice. Well above our 200 Mbit/s goal." |
| 12 | Kill the firewall | ping fails, curl times out | "The tun devices are persistent, so with no program reading them the kernel drops everything. No firewall, no traffic." |

## Suggested split of the ~10 minutes

| Time | Part | Presenter |
|---|---|---|
| 0:00 to 1:30 | The problem, the design, the diagram | Eva |
| 1:30 to 3:30 | How a packet is decided: parse, anti-spoofing, fast and slow path, TCP state machine, caps | Eva |
| 3:30 to 6:30 | The live demo, steps 1 to 9 | Giselle |
| 6:30 to 8:00 | The tun loop, persistent devices that fail closed, application identification | Giselle |
| 8:00 to 9:15 | Testing and performance, steps 10 and 11 | Giselle |
| 9:15 to 10:00 | Changes from the plan and what is not done, step 12 to close | Both |

Swap the roles if you like: each of you is graded on your own portion.

## Changes from the original plan (the rubric asks for these)

- `inside` became **required**, so anti-spoofing is always on.
- Flows are **capped**: one source may hold 1/16 of the table, and flows started from the outside at most 3/4.
- The flow hash is **keyed** (SipHash), so flows cannot be crafted to collide.
- ICMP errors are **rate-limited** and only accepted for the right flow.
- **Application identification** was added (HTTP, TLS, DNS by payload).
- **Port-scan detection** was added: 20 dropped ports in 5 s blocks the host for 60 s.
- The tun devices are **persistent** and the routing **fails closed**.
- Two review rounds, fuzzing, mutation testing and sanitizers found and fixed about 40 issues.

Not done: source NAT inside the firewall, TCP sequence validation, full SYN-flood protection (no SYN cookies), and a larger-scale architecture such as multi-threading.

## If something goes wrong

- **A cross in a step:** run `scripts/demo.sh stop`, then `scripts/demo.sh auto` to see which check fails and why.
- **No Internet:** `demo.sh` refuses to start and says so. Reconnect, or record against the local-only tests instead.
- **Terminal closed mid-demo:** run `scripts/demo.sh stop`.
- **The window looks cramped:** make the terminal bigger before starting; the two panes are sized from it.

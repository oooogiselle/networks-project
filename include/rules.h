/*=============================================================================
 * File Name:   rules.h
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Rule file format and matching interface: verbose and compact
 *              rule syntax, port lists, and the inside-network declaration used
 *              for anti-spoofing.
 =============================================================================*/

/*
 * rules.h - rule file parsing and first-match evaluation.
 *
 * File syntax (one rule per line, '#' starts a comment):
 *
 *   (allow|deny|reject) [in|out] (tcp|udp|icmp|any)
 *       from <addr> [port <ports>] to <addr> [port <ports>]
 *
 * or the compact form used in the requirements spec:
 *
 *   (allow|deny|reject) [in|out] (tcp|udp|icmp|any) <addr> <addr> [<ports>|echo]
 *       e.g.  allow out tcp 10.0.1.0/24 any 80,443
 *             allow out icmp 10.0.1.0/24 any echo
 *             allow in  tcp any 10.0.1.3 22
 *   Ports in the compact form match the DESTINATION port (omitted = any).
 *   `echo` is only for icmp (echo requests are the only ICMP that starts a
 *   flow, so it documents intent). Both forms may be mixed in one file.
 *
 *   <addr>  := any | a.b.c.d | a.b.c.d/len
 *   <ports> := <item>[,<item>...]   with <item> := N | N-M
 *              Only tcp and udp rules may name ports; a port on an icmp or
 *              any rule is a syntax error (it would silently widen the rule).
 *              e.g. 80   443   1024-65535   80,443   80,8000-8100,8443
 *              (no spaces around commas; at most 8 items)
 *   out|in  := direction of the connection, as in the spec (default: out).
 *              "out" = initiated from the inside (first packet arrives on
 *              tun-in, rule->dir == DIR_IN);
 *              "in"  = initiated from the outside, for deliberately exposed
 *              services (first packet arrives on tun-out, DIR_OUT).
 *
 * Besides rules, the file may declare which networks are the trusted side:
 *
 *   inside <a.b.c.d/len>      (repeatable, up to 8; "any" is not allowed)
 *
 * At least one `inside` network is REQUIRED. The engine enforces address
 * anti-spoofing with it: packets arriving from the outside must NOT have an
 * inside source address, and packets arriving from the inside MUST have one.
 * A rules file with no `inside` line parses, but the engine refuses to start
 * with it (engine_create* fail): without it there is no way to tell a spoofed
 * source from a real one.
 *
 * Port forwarding (destination NAT; needs source NAT, `tunwall -n ADDR`):
 *
 *   forward (tcp|udp) <ext-port> <a.b.c.d> <port>      (up to 16)
 *       e.g.  forward tcp 8080 10.0.1.3 80
 *
 * A connection from the outside to ADDR:<ext-port> is sent to the inside
 * host <a.b.c.d>:<port>, and its replies leave from ADDR:<ext-port>. The
 * target must be in an `inside` network and the external port must not be in
 * the source-NAT port range. A forward only translates: the connection is
 * then decided like any other, so it also needs a rule such as
 *   allow in tcp any 10.0.1.3 80
 *
 * Rate limits (allow rules only), as the last two tokens of the rule:
 *
 *   ... limit N/(sec|min|hour)          N = 1..10000
 *       e.g.  allow in tcp any 10.0.1.3 22 limit 5/min
 *
 * Each source address may open N new connections through the rule at once,
 * then one more every PERIOD/N (a token bucket, see ratelimit.h); new
 * connections over that are dropped silently. Connections already open are
 * never affected.
 *
 * `reject` refuses a new connection like `deny`, but also tells the sender
 * at once instead of letting it time out: a TCP RST for TCP, ICMP port
 * unreachable for UDP, ICMP administratively prohibited for an echo request
 * (see reject.h). Use it for traffic from your own users that should fail
 * fast. The default policy stays a SILENT drop, so a scanner learns nothing.
 *
 * Rules are evaluated in file order, first match wins, and if nothing
 * matches the policy is DENY. Rules are only consulted for the first packet
 * of a flow; later packets use the flow table.
 */
#ifndef FW_RULES_H
#define FW_RULES_H

#include "engine.h"

/* ACT_REJECT drops like deny and also answers (TCP RST / ICMP unreachable). */
typedef enum { ACT_DENY = 0, ACT_ALLOW = 1, ACT_REJECT = 2 } action_t;

typedef struct { bool any; uint32_t net, mask; } addr_match_t;
typedef struct { uint16_t lo, hi; } port_range_t;

/* A rule's port list: matches if the port falls in ANY of the ranges. */
#define MAX_PORT_RANGES 8
typedef struct {
    port_range_t r[MAX_PORT_RANGES];
    uint8_t      n;                 /* always >= 1 (omitted = 0-65535) */
} port_set_t;

/* Max `inside` networks a rules file may declare. */
#define MAX_INSIDE_NETS 8

/* Max `forward` lines a rules file may declare. */
#define MAX_FORWARDS 16

/* A `forward` line: outside -> NAT address:ext_port goes to ip:port. */
typedef struct forward {
    uint8_t  proto;              /* FW_PROTO_TCP or FW_PROTO_UDP */
    uint16_t ext_port;
    uint32_t ip;
    uint16_t port;
    int      line;
} forward_t;

typedef struct rule {
    action_t     action;
    dir_t        dir;
    uint8_t      proto;          /* 0 = any */
    addr_match_t src, dst;
    port_set_t   sport, dport;
    uint32_t     limit_n;        /* `limit N/...`: connections per period; 0 = no limit */
    uint64_t     limit_period_ns;
    int          line;           /* source line number, for logs */
} rule_t;

struct rules {
    rule_t *v;
    size_t  n, cap;
    addr_match_t inside[MAX_INSIDE_NETS];   /* `inside` directives */
    size_t       ninside;
    forward_t    fwd[MAX_FORWARDS];         /* `forward` directives */
    size_t       nfwd;
};

rules_t *rules_load_file(const char *path, char *err, size_t errlen);
rules_t *rules_parse_string(const char *text, char *err, size_t errlen);
void     rules_free(rules_t *r);

/* True if ip is in one of the declared inside networks. */
bool rules_is_inside(const rules_t *r, uint32_t ip);
/* True if ip is the directed-broadcast address of a declared inside network
 * (e.g. 10.0.1.255 for 10.0.1.0/24). A /32 network has none. */
bool rules_is_inside_broadcast(const rules_t *r, uint32_t ip);

/* First matching rule for a new-flow packet, or NULL (=> default deny). */
const rule_t *rules_match(const rules_t *r, const pkt_t *p, dir_t dir);

#endif

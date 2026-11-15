/*=============================================================================
 * File Name:   rules.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
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
 *   (allow|deny) [in|out] (tcp|udp|icmp|any)
 *       from <addr> [port <ports>] to <addr> [port <ports>]
 *
 * or the compact form used in the requirements spec:
 *
 *   (allow|deny) [in|out] (tcp|udp|icmp|any) <addr> <addr> [<ports>|echo]
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
 * Rules are evaluated in file order, first match wins, and if nothing
 * matches the policy is DENY. Rules are only consulted for the first packet
 * of a flow; later packets use the flow table.
 */
#ifndef FW_RULES_H
#define FW_RULES_H

#include "engine.h"

typedef enum { ACT_DENY = 0, ACT_ALLOW = 1 } action_t;

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

typedef struct rule {
    action_t     action;
    dir_t        dir;
    uint8_t      proto;          /* 0 = any */
    addr_match_t src, dst;
    port_set_t   sport, dport;
    int          line;           /* source line number, for logs */
} rule_t;

struct rules {
    rule_t *v;
    size_t  n, cap;
    addr_match_t inside[MAX_INSIDE_NETS];   /* `inside` directives */
    size_t       ninside;
};

rules_t *rules_load_file(const char *path, char *err, size_t errlen);
rules_t *rules_parse_string(const char *text, char *err, size_t errlen);
void     rules_free(rules_t *r);

/* True if ip is in one of the declared inside networks. */
bool rules_is_inside(const rules_t *r, uint32_t ip);

/* First matching rule for a new-flow packet, or NULL (=> default deny). */
const rule_t *rules_match(const rules_t *r, const pkt_t *p, dir_t dir);

#endif

/*
 * rules.h - rule file parsing and first-match evaluation.
 *
 * File syntax (one rule per line, '#' starts a comment):
 *
 *   (allow|deny) [in|out] (tcp|udp|icmp|any)
 *       from <addr> [port <ports>] to <addr> [port <ports>]
 *
 *   <addr>  := any | a.b.c.d | a.b.c.d/len
 *   <ports> := N | N-M
 *   in|out  := interface the FIRST packet of a flow arrives on (default: in).
 *              "in" rules govern connections initiated from the inside;
 *              "out" rules are for deliberately exposed services.
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

typedef struct rule {
    action_t     action;
    dir_t        dir;
    uint8_t      proto;          /* 0 = any */
    addr_match_t src, dst;
    port_range_t sport, dport;
    int          line;           /* source line number, for logs */
} rule_t;

struct rules {
    rule_t *v;
    size_t  n, cap;
};

rules_t *rules_load_file(const char *path, char *err, size_t errlen);
rules_t *rules_parse_string(const char *text, char *err, size_t errlen);
void     rules_free(rules_t *r);

/* First matching rule for a new-flow packet, or NULL (=> default deny). */
const rule_t *rules_match(const rules_t *r, const pkt_t *p, dir_t dir);

#endif

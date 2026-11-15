/*=============================================================================
 * File Name:   rules.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Rule file parser (reports the line number of any syntax error)
 *              and first-match rule evaluation with a default-deny policy.
 =============================================================================*/

#include "rules.h"

#include "fwalloc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOKENS 16

static void set_err(char *err, size_t n, int line, const char *msg)
{
    if (err && n) snprintf(err, n, "line %d: %s", line, msg);
}

static bool parse_addr(const char *s, addr_match_t *out)
{
    if (strcmp(s, "any") == 0) { out->any = true; out->net = out->mask = 0; return true; }

    char buf[32];
    if (strlen(s) >= sizeof buf) return false;
    strcpy(buf, s);

    int len = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end;
        long v = strtol(slash + 1, &end, 10);
        if (*end || end == slash + 1 || v < 0 || v > 32) return false;
        len = (int)v;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return false;
    out->any = false;
    out->mask = len ? ~0u << (32 - len) : 0;
    out->net = ntohl(a.s_addr) & out->mask;
    return true;
}

static bool parse_port(const char *s, uint16_t *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end || end == s || v < 0 || v > 65535) return false;
    *out = (uint16_t)v;
    return true;
}

/* One list item: "N" or "N-M". */
static bool parse_port_range(char *s, port_range_t *out)
{
    char *dash = strchr(s, '-');
    if (dash) {
        *dash = '\0';
        return parse_port(s, &out->lo) && parse_port(dash + 1, &out->hi) &&
               out->lo <= out->hi;
    }
    if (!parse_port(s, &out->lo)) return false;
    out->hi = out->lo;
    return true;
}

/* "80", "1024-65535", "80,443", "80,8000-8100". Empty items are errors. */
static bool parse_ports(const char *s, port_set_t *out)
{
    char buf[96];
    if (strlen(s) >= sizeof buf) return false;
    strcpy(buf, s);
    out->n = 0;
    /* strtok_r would skip empty items ("80,,443"), so split by hand. */
    char *item = buf;
    for (;;) {
        char *comma = strchr(item, ',');
        if (comma) *comma = '\0';
        if (out->n == MAX_PORT_RANGES) return false;
        if (!parse_port_range(item, &out->r[out->n])) return false;
        out->n++;
        if (!comma) break;
        item = comma + 1;
    }
    return true;
}

/*
 * Compact rule tail, starting at tok[i] (after action, direction, protocol):
 *   <src> <dst> [<ports>]    ports apply to the destination port
 *   <src> <dst> echo         icmp only; echo requests are the only ICMP
 *                            that can start a flow anyway, so it is a marker
 * Omitted ports (or `any`) mean every port.
 */
static bool parse_compact(char **tok, int n, int i, rule_t *r, int lineno,
                          char *err, size_t errlen)
{
    if (i >= n || !parse_addr(tok[i], &r->src)) {
        set_err(err, errlen, lineno, "bad source address");
        return false;
    }
    i++;
    if (i >= n || !parse_addr(tok[i], &r->dst)) {
        set_err(err, errlen, lineno, "expected destination address");
        return false;
    }
    i++;
    if (i < n) {
        if (strcmp(tok[i], "echo") == 0) {
            if (r->proto != FW_PROTO_ICMP) {
                set_err(err, errlen, lineno, "'echo' is only valid for icmp");
                return false;
            }
        } else if (strcmp(tok[i], "any") != 0) {
            if (r->proto == FW_PROTO_ICMP) {
                set_err(err, errlen, lineno, "icmp rules take 'echo', not ports");
                return false;
            }
            if (!parse_ports(tok[i], &r->dport)) {
                set_err(err, errlen, lineno, "bad port list");
                return false;
            }
        }
        i++;
    }
    if (i != n) {
        set_err(err, errlen, lineno, "unexpected trailing tokens");
        return false;
    }
    return true;
}

/* Returns 0 = rule parsed, 1 = blank/comment, 2 = `inside` directive (the
 * network is returned in r->src), -1 = error (err filled). */
static int parse_line(char *line, int lineno, rule_t *r, char *err, size_t errlen)
{
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';

    char *tok[MAX_TOKENS];
    int n = 0;
    char *save = NULL;
    for (char *t = strtok_r(line, " \t\r\n", &save); t;
         t = strtok_r(NULL, " \t\r\n", &save)) {
        if (n == MAX_TOKENS) { set_err(err, errlen, lineno, "too many tokens"); return -1; }
        tok[n++] = t;
    }
    if (n == 0) return 1;

    memset(r, 0, sizeof *r);
    r->line = lineno;

    if (strcmp(tok[0], "inside") == 0) {
        if (n != 2 || strcmp(tok[1], "any") == 0 || !parse_addr(tok[1], &r->src)) {
            set_err(err, errlen, lineno, "expected 'inside <a.b.c.d/len>'");
            return -1;
        }
        return 2;
    }

    r->sport.n = r->dport.n = 1;
    r->sport.r[0] = r->dport.r[0] = (port_range_t){0, 65535};
    int i = 0;

    if (strcmp(tok[i], "allow") == 0) r->action = ACT_ALLOW;
    else if (strcmp(tok[i], "deny") == 0) r->action = ACT_DENY;
    else { set_err(err, errlen, lineno, "expected 'allow' or 'deny'"); return -1; }
    i++;

    /* Keywords name the traffic direction, as in the spec: "out" = outbound
     * (first packet arrives on tun-in), "in" = inbound (arrives on tun-out).
     * Default when omitted: outbound. */
    r->dir = DIR_IN;
    if (i < n && strcmp(tok[i], "out") == 0) { r->dir = DIR_IN; i++; }
    else if (i < n && strcmp(tok[i], "in") == 0) { r->dir = DIR_OUT; i++; }

    if (i >= n) { set_err(err, errlen, lineno, "missing protocol"); return -1; }
    if (strcmp(tok[i], "tcp") == 0) r->proto = FW_PROTO_TCP;
    else if (strcmp(tok[i], "udp") == 0) r->proto = FW_PROTO_UDP;
    else if (strcmp(tok[i], "icmp") == 0) r->proto = FW_PROTO_ICMP;
    else if (strcmp(tok[i], "any") == 0) r->proto = 0;
    else { set_err(err, errlen, lineno, "unknown protocol"); return -1; }
    i++;

    /* Anything other than `from` after the protocol is the compact form:
     *   <src> <dst> [<ports> | echo]      (as in the requirements spec) */
    if (i < n && strcmp(tok[i], "from") != 0)
        return parse_compact(tok, n, i, r, lineno, err, errlen) ? 0 : -1;

    for (int side = 0; side < 2; side++) {
        const char *kw = side ? "to" : "from";
        addr_match_t *a = side ? &r->dst : &r->src;
        port_set_t *p = side ? &r->dport : &r->sport;
        if (i >= n || strcmp(tok[i], kw) != 0) {
            set_err(err, errlen, lineno, side ? "expected 'to'" : "expected 'from'");
            return -1;
        }
        i++;
        if (i >= n || !parse_addr(tok[i], a)) {
            set_err(err, errlen, lineno, "bad address");
            return -1;
        }
        i++;
        if (i < n && strcmp(tok[i], "port") == 0) {
            i++;
            if (i >= n || !parse_ports(tok[i], p)) {
                set_err(err, errlen, lineno, "bad port or port range");
                return -1;
            }
            i++;
        }
    }
    if (i != n) { set_err(err, errlen, lineno, "unexpected trailing tokens"); return -1; }
    return 0;
}

static bool rules_push(rules_t *rs, const rule_t *r)
{
    if (rs->n == rs->cap) {
        size_t nc = rs->cap ? rs->cap * 2 : 16;
        rule_t *nv = fw_realloc(rs->v, nc * sizeof *nv);
        if (!nv) return false;
        rs->v = nv;
        rs->cap = nc;
    }
    rs->v[rs->n++] = *r;
    return true;
}

rules_t *rules_parse_string(const char *text, char *err, size_t errlen)
{
    rules_t *rs = fw_calloc(1, sizeof *rs);
    if (!rs) return NULL;

    char *copy = fw_strdup(text);
    if (!copy) { free(rs); return NULL; }

    /* Split on '\n' by hand: strtok would skip blank lines and corrupt the
     * line numbers we report in errors and logs. */
    int lineno = 0;
    char *next = copy;
    while (next) {
        char *line = next;
        char *nl = strchr(line, '\n');
        if (nl) { *nl = '\0'; next = nl + 1; } else { next = NULL; }
        lineno++;
        rule_t r;
        int rc = parse_line(line, lineno, &r, err, errlen);
        if (rc == 2 && rs->ninside == MAX_INSIDE_NETS) {
            set_err(err, errlen, lineno, "too many 'inside' networks");
            rc = -1;
        } else if (rc == 2) {
            rs->inside[rs->ninside++] = r.src;
        }
        if (rc < 0 || (rc == 0 && !rules_push(rs, &r))) {
            if (rc == 0) set_err(err, errlen, lineno, "out of memory");
            free(copy);
            rules_free(rs);
            return NULL;
        }
    }
    free(copy);
    return rs;
}

rules_t *rules_load_file(const char *path, char *err, size_t errlen)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (err && errlen) snprintf(err, errlen, "cannot open %s", path);
        return NULL;
    }
    char *text = NULL;
    size_t len = 0, cap = 0;
    char chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, fp)) > 0) {
        if (len + got + 1 > cap) {
            cap = (len + got + 1) * 2;
            char *nt = fw_realloc(text, cap);
            if (!nt) { free(text); fclose(fp); return NULL; }
            text = nt;
        }
        memcpy(text + len, chunk, got);
        len += got;
    }
    fclose(fp);
    if (!text) {                       /* empty file */
        text = fw_calloc(1, 1);
        if (!text) return NULL;
    } else {
        text[len] = '\0';
    }
    rules_t *rs = rules_parse_string(text, err, errlen);
    free(text);
    return rs;
}

void rules_free(rules_t *r)
{
    if (!r) return;
    free(r->v);
    free(r);
}

static bool addr_ok(const addr_match_t *m, uint32_t ip)
{
    return m->any || (ip & m->mask) == m->net;
}

static bool ports_ok(const port_set_t *s, uint16_t p)
{
    for (uint8_t i = 0; i < s->n; i++)
        if (p >= s->r[i].lo && p <= s->r[i].hi) return true;
    return false;
}

bool rules_is_inside(const rules_t *rs, uint32_t ip)
{
    for (size_t i = 0; i < rs->ninside; i++)
        if (addr_ok(&rs->inside[i], ip)) return true;
    return false;
}

const rule_t *rules_match(const rules_t *rs, const pkt_t *p, dir_t dir)
{
    for (size_t i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->v[i];
        if (r->dir != dir) continue;
        if (r->proto && r->proto != p->proto) continue;
        if (!addr_ok(&r->src, p->src_ip) || !addr_ok(&r->dst, p->dst_ip)) continue;
        if (p->proto == FW_PROTO_TCP || p->proto == FW_PROTO_UDP) {
            if (!ports_ok(&r->sport, p->src_port) ||
                !ports_ok(&r->dport, p->dst_port)) continue;
        }
        return r;
    }
    return NULL;
}

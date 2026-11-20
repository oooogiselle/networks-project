/*=============================================================================
 * File Name:   rules.c
 * Author:      Eva Tate and Giselle Wu
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

/* Ports mean nothing to ICMP, and on an `any` rule they would apply to TCP and
 * UDP while silently leaving ICMP open, so such rules are refused outright. */
#define NOT_PORT_PROTO "ports are only valid for tcp and udp rules"

/* A message that is not about a particular line. */
static void set_msg(char *err, size_t n, const char *msg)
{
    if (err && n) snprintf(err, n, "%s", msg);
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
            if (r->proto != FW_PROTO_TCP && r->proto != FW_PROTO_UDP) {
                set_err(err, errlen, lineno, NOT_PORT_PROTO);
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

/* A single port 1-65535. */
static bool parse_port1(const char *s, uint16_t *out)
{
    char *end;
    if (!isdigit((unsigned char)*s)) return false;
    long v = strtol(s, &end, 10);
    if (*end || v < 1 || v > 65535) return false;
    *out = (uint16_t)v;
    return true;
}

#define LIMIT_MAX_N 10000
#define LIMIT_SYNTAX "expected 'limit N/sec|min|hour' (N = 1-10000) at the end of the rule"

/* `N/sec`, `N/min` or `N/hour` (the value after `limit`). */
static bool parse_limit(const char *s, rule_t *r)
{
    char *end;
    if (!isdigit((unsigned char)*s)) return false;
    long v = strtol(s, &end, 10);
    if (*end != '/' || v < 1 || v > LIMIT_MAX_N) return false;
    const char *unit = end + 1;
    uint64_t secs;
    if (strcmp(unit, "sec") == 0) secs = 1;
    else if (strcmp(unit, "min") == 0) secs = 60;
    else if (strcmp(unit, "hour") == 0) secs = 3600;
    else return false;
    r->limit_n = (uint32_t)v;
    r->limit_period_ns = secs * 1000000000ull;
    return true;
}

#define APP_SYNTAX "expected 'app NAME[,NAME...]' (http, tls, dns, other) at the end of the rule"

/* `http,tls,...` (the value after `app`) as a bitmask of 1u << app_t. Split
 * by hand, as in parse_ports, so an empty item ("http,,tls") is an error. */
static bool parse_apps(const char *s, uint8_t *out)
{
    static const struct { const char *name; app_t app; } names[] = {
        { "http", APP_HTTP }, { "tls", APP_TLS }, { "dns", APP_DNS }, { "other", APP_OTHER },
    };
    uint8_t mask = 0;
    const char *item = s;
    for (;;) {
        const char *comma = strchr(item, ',');
        const size_t len = comma ? (size_t)(comma - item) : strlen(item);
        size_t k = 0;
        while (k < sizeof names / sizeof *names &&
               (strlen(names[k].name) != len || strncmp(item, names[k].name, len) != 0))
            k++;
        if (k == sizeof names / sizeof *names) return false;
        mask |= (uint8_t)(1u << names[k].app);
        if (!comma) break;
        item = comma + 1;
    }
    *out = mask;
    return true;
}

/* `forward (tcp|udp) <ext-port> <a.b.c.d> <port>` (tok[0] is "forward"). */
static bool parse_forward(char **tok, int n, int lineno, forward_t *f,
                          char *err, size_t errlen)
{
    memset(f, 0, sizeof *f);
    f->line = lineno;
    if (n != 5) {
        set_err(err, errlen, lineno, "expected 'forward (tcp|udp) <port> <a.b.c.d> <port>'");
        return false;
    }
    if (strcmp(tok[1], "tcp") == 0) f->proto = FW_PROTO_TCP;
    else if (strcmp(tok[1], "udp") == 0) f->proto = FW_PROTO_UDP;
    else { set_err(err, errlen, lineno, "forward: protocol must be tcp or udp"); return false; }
    addr_match_t a;
    if (!parse_port1(tok[2], &f->ext_port) || !parse_port1(tok[4], &f->port)) {
        set_err(err, errlen, lineno, "forward: ports must be 1-65535");
        return false;
    }
    if (strchr(tok[3], '/') || !parse_addr(tok[3], &a) || a.any) {
        set_err(err, errlen, lineno, "forward: the target must be one address (a.b.c.d)");
        return false;
    }
    f->ip = a.net;
    return true;
}

/* Returns 0 = rule parsed, 1 = blank/comment, 2 = `inside` directive (the
 * network is returned in r->src), 3 = `forward` directive (returned in *fw),
 * -1 = error (err filled). */
static int parse_line(char *line, int lineno, rule_t *r, forward_t *fw,
                      char *err, size_t errlen)
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
    if (strcmp(tok[0], "forward") == 0)
        return parse_forward(tok, n, lineno, fw, err, errlen) ? 3 : -1;

    r->sport.n = r->dport.n = 1;
    r->sport.r[0] = r->dport.r[0] = (port_range_t){0, 65535};
    int i = 0;

    if (strcmp(tok[i], "allow") == 0) r->action = ACT_ALLOW;
    else if (strcmp(tok[i], "deny") == 0) r->action = ACT_DENY;
    else if (strcmp(tok[i], "reject") == 0) r->action = ACT_REJECT;
    else { set_err(err, errlen, lineno, "expected 'allow', 'deny' or 'reject'"); return -1; }
    i++;

    /* Optional `limit N/PERIOD` and `app NAME,...` clauses are always the
     * last tokens, in either order. Take them off here, so the compact and
     * the from/to forms below never see them. */
    bool have_limit = false, have_app = false;
    while (n - i >= 2) {
        const char *kw = tok[n - 2];
        if (strcmp(kw, "limit") == 0) {
            if (have_limit || !parse_limit(tok[n - 1], r)) {
                set_err(err, errlen, lineno, LIMIT_SYNTAX);
                return -1;
            }
            have_limit = true;
        } else if (strcmp(kw, "app") == 0) {
            if (have_app || !parse_apps(tok[n - 1], &r->apps)) {
                set_err(err, errlen, lineno, APP_SYNTAX);
                return -1;
            }
            have_app = true;
        } else {
            break;
        }
        n -= 2;
    }
    for (int k = i; k < n; k++) {         /* one left anywhere else is misplaced */
        if (strcmp(tok[k], "limit") == 0) { set_err(err, errlen, lineno, LIMIT_SYNTAX); return -1; }
        if (strcmp(tok[k], "app") == 0)   { set_err(err, errlen, lineno, APP_SYNTAX);   return -1; }
    }
    if ((have_limit || have_app) && r->action != ACT_ALLOW) {
        set_err(err, errlen, lineno, have_limit ? "'limit' only works on allow rules"
                                                : "'app' only works on allow rules");
        return -1;
    }

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
    /* Only TCP and UDP payloads are identified: an ICMP flow would never get
     * a label, so `app` on it would silently mean nothing. */
    if (have_app && r->proto != FW_PROTO_TCP && r->proto != FW_PROTO_UDP) {
        set_err(err, errlen, lineno, "'app' needs a tcp or udp rule");
        return -1;
    }

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
            if (r->proto != FW_PROTO_TCP && r->proto != FW_PROTO_UDP) {
                set_err(err, errlen, lineno, NOT_PORT_PROTO);
                return -1;
            }
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

static bool add_forward(rules_t *rs, const forward_t *f, char *err, size_t errlen)
{
    for (size_t i = 0; i < rs->nfwd; i++) {
        if (rs->fwd[i].proto == f->proto && rs->fwd[i].ext_port == f->ext_port) {
            char msg[96];
            snprintf(msg, sizeof msg, "forward: port %u is already forwarded on line %d",
                     f->ext_port, rs->fwd[i].line);
            set_err(err, errlen, f->line, msg);
            return false;
        }
    }
    if (rs->nfwd == MAX_FORWARDS) {
        set_err(err, errlen, f->line, "too many 'forward' lines");
        return false;
    }
    rs->fwd[rs->nfwd++] = *f;
    return true;
}

rules_t *rules_parse_string(const char *text, char *err, size_t errlen)
{
    rules_t *rs = fw_calloc(1, sizeof *rs);
    if (!rs) { set_msg(err, errlen, "out of memory"); return NULL; }

    char *copy = fw_strdup(text);
    if (!copy) { free(rs); set_msg(err, errlen, "out of memory"); return NULL; }

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
        forward_t fw;
        int rc = parse_line(line, lineno, &r, &fw, err, errlen);
        if (rc == 2 && rs->ninside == MAX_INSIDE_NETS) {
            set_err(err, errlen, lineno, "too many 'inside' networks");
            rc = -1;
        } else if (rc == 2) {
            rs->inside[rs->ninside++] = r.src;
        } else if (rc == 3) {
            rc = add_forward(rs, &fw, err, errlen) ? 3 : -1;
        }
        if (rc < 0 || (rc == 0 && !rules_push(rs, &r))) {
            if (rc == 0) set_err(err, errlen, lineno, "out of memory");
            free(copy);
            rules_free(rs);
            return NULL;
        }
    }
    free(copy);
    /* Checked at the end: `inside` may come after the forward that needs it. */
    for (size_t i = 0; i < rs->nfwd; i++) {
        if (!rules_is_inside(rs, rs->fwd[i].ip)) {
            set_err(err, errlen, rs->fwd[i].line,
                    "forward: the target is not in an 'inside' network");
            rules_free(rs);
            return NULL;
        }
    }
    return rs;
}

rules_t *rules_load_file(const char *path, char *err, size_t errlen)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (err && errlen) snprintf(err, errlen, "%s: cannot open file", path);
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
            if (!nt) {
                free(text); fclose(fp);
                set_msg(err, errlen, "out of memory");
                return NULL;
            }
            text = nt;
        }
        memcpy(text + len, chunk, got);
        len += got;
    }
    /* fread() returns 0 both at end of file and on a read error (a directory,
     * a failing disk). An error must not look like a short or empty file: the
     * lines lost might include `inside` or a deny rule. */
    const bool read_failed = ferror(fp) != 0;
    fclose(fp);
    if (read_failed) {
        free(text);
        if (err && errlen) snprintf(err, errlen, "%s: error reading file", path);
        return NULL;
    }
    /* The parser works on a C string, so a NUL would silently end the file
     * there and drop every later rule. */
    if (text && memchr(text, '\0', len)) {
        free(text);
        if (err && errlen) snprintf(err, errlen, "%s: contains a NUL byte", path);
        return NULL;
    }
    if (!text) {                       /* empty file */
        text = fw_calloc(1, 1);
        if (!text) { set_msg(err, errlen, "out of memory"); return NULL; }
    } else {
        text[len] = '\0';
    }
    rules_t *rs = rules_parse_string(text, err, errlen);
    free(text);
    if (!rs && err && errlen) {                 /* "line N: ..." -> "path: line N: ..." */
        char msg[256];
        snprintf(msg, sizeof msg, "%s: %s", path, err);
        snprintf(err, errlen, "%s", msg);
    }
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

bool rules_is_inside_broadcast(const rules_t *rs, uint32_t ip)
{
    for (size_t i = 0; i < rs->ninside; i++) {
        const addr_match_t *m = &rs->inside[i];
        if (m->mask != 0xffffffffu && ip == (m->net | ~m->mask)) return true;
    }
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

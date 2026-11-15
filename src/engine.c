/*=============================================================================
 * File Name:   engine.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Decision engine. Ties the flow table, TCP state machine and
 *              rules together (fast path for known flows, slow path for new
 *              ones), and handles ICMP error matching and address anti-
 *              spoofing.
 =============================================================================*/

/*
 * engine.c - ties the flow table, TCP state machine and rules together.
 *
 *   existing flow  -> FAST PATH: hash lookup + state update, no rules
 *   no flow        -> SLOW PATH: sanity-check, evaluate rules, maybe create
 */
#include "engine.h"

#include <stdlib.h>
#include <string.h>

#include "flowtable.h"
#include "log.h"
#include "parser.h"
#include "rules.h"
#include "tcpstate.h"


_Static_assert(PARSE_RESULT_COUNT <= ENGINE_PARSE_KINDS,
               "grow ENGINE_PARSE_KINDS in engine.h");

struct engine {
    rules_t     *rules;
    flowtable_t *ft;
    engine_stats_t st;
};

engine_t *engine_create_with_rules_sized(rules_t *rules, size_t max_flows)
{
    if (!rules) return NULL;
    engine_t *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->rules = rules;
    /* about one bucket per flow slot keeps chains short at capacity */
    e->ft = ft_create(max_flows, max_flows);
    if (!e->ft) { free(e); return NULL; }
    return e;
}

engine_t *engine_create_with_rules(rules_t *rules)
{
    return engine_create_with_rules_sized(rules, FW_DEFAULT_MAX_FLOWS);
}

engine_t *engine_create(const char *rules_path, char *err, size_t errlen)
{
    rules_t *r = rules_load_file(rules_path, err, errlen);
    if (!r) return NULL;
    engine_t *e = engine_create_with_rules(r);
    if (!e) rules_free(r);
    return e;
}

void engine_destroy(engine_t *e)
{
    if (!e) return;
    ft_destroy(e->ft);
    rules_free(e->rules);
    free(e);
}

static verdict_t do_drop(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now,
                         drop_reason_t why, drop_reason_t *out)
{
    e->st.pkts_dropped++;
    e->st.drops[why]++;
    log_drop(p, dir, why, now);
    if (out) *out = why;
    return VERDICT_DROP;
}

static verdict_t do_allow(engine_t *e, drop_reason_t *out)
{
    e->st.pkts_allowed++;
    if (out) *out = DROP_NONE;
    return VERDICT_ALLOW;
}

void engine_parse_failed(engine_t *e, unsigned result, dir_t dir, size_t len,
                         uint64_t now_ns)
{
    if (result == PARSE_OK || result >= PARSE_RESULT_COUNT) return;
    e->st.pkts_total++;
    e->st.pkts_dropped++;
    e->st.parse_fail[result]++;
    log_parse_fail(result, dir, len, now_ns);
}

/*
 * ICMP error (unreachable, time exceeded, ...): allowed only if the packet it
 * embeds belongs to a tracked flow AND the error is travelling back toward
 * that packet's sender. The flow itself is not touched (no state change, no
 * counters, no timer refresh), so errors cannot keep a flow alive.
 */
static verdict_t decide_icmp_error(engine_t *e, const pkt_t *p, dir_t dir,
                                   uint64_t now, drop_reason_t *reason)
{
    pkt_t in;
    if (parse_icmp_inner(p, &in) != PARSE_OK)
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    /* The embedded packet, as its sender wrote it. */
    const flow_key_t key = { in.src_ip, in.dst_ip, in.src_port, in.dst_port,
                             in.proto };
    bool inner_is_reply = false;
    const flow_t *f = ft_lookup(e->ft, &key, now, &inner_is_reply);
    if (!f)
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    /* The offending packet came from the originator (or the responder, if
     * inner_is_reply); the error must arrive from the opposite side. */
    const dir_t inner_sent_on = inner_is_reply ? !f->orig_dir : f->orig_dir;
    if (dir == inner_sent_on)
        return do_drop(e, p, dir, now, DROP_SPOOF, reason);

    e->st.icmp_related++;
    return do_allow(e, reason);
}

verdict_t engine_decide(engine_t *e, const pkt_t *p, dir_t dir,
                        uint64_t now_ns, drop_reason_t *reason)
{
    e->st.pkts_total++;

    /* Anti-spoofing (only when the rules declare `inside` networks): the
     * outside may not use inside addresses, the inside must use them. */
    if (e->rules->ninside &&
        rules_is_inside(e->rules, p->src_ip) != (dir == DIR_IN))
        return do_drop(e, p, dir, now_ns, DROP_BAD_SRC, reason);

    if (p->proto == FW_PROTO_ICMP && icmp_is_error(p->icmp_type)) {
        /* Checked before the flow lookup: an error's own (ip, ip, 0, 0)
         * tuple must never be mistaken for an echo flow with identifier 0. */
        return decide_icmp_error(e, p, dir, now_ns, reason);
    }

    const flow_key_t key = { p->src_ip, p->dst_ip, p->src_port, p->dst_port,
                             p->proto };
    bool is_reply = false;
    flow_t *f = ft_lookup(e->ft, &key, now_ns, &is_reply);

    /* A new SYN may reuse a tuple whose connection already finished. */
    if (f && p->proto == FW_PROTO_TCP && !is_reply && dir == f->orig_dir &&
        (f->tcp_state == TCPS_TIME_WAIT || f->tcp_state == TCPS_CLOSED) &&
        tcp_is_pure_syn(p->tcp_flags)) {
        log_flow("CLOSE", f, now_ns);
        ft_remove(e->ft, f);
        f = NULL;
    }

    /* ---- fast path ---- */
    if (f) {
        e->st.fastpath++;
        const bool from_orig = !is_reply;

        /* Tuple matches but it arrived on the wrong interface: spoofing. */
        if (from_orig != (dir == f->orig_dir))
            return do_drop(e, p, dir, now_ns, DROP_SPOOF, reason);

        if (p->proto == FW_PROTO_TCP) {
            tcp_state_t before = f->tcp_state;
            if (!tcp_track(f, p->tcp_flags, from_orig))
                return do_drop(e, p, dir, now_ns, DROP_TCP_STATE, reason);
            if (f->tcp_state != before &&
                (f->tcp_state == TCPS_TIME_WAIT || f->tcp_state == TCPS_CLOSED)) {
                f->pkts[from_orig ? 0 : 1]++;     /* so the log line is current */
                f->bytes[from_orig ? 0 : 1] += p->ip_len;
                log_flow("CLOSE", f, now_ns);
                f->pkts[from_orig ? 0 : 1]--;
                f->bytes[from_orig ? 0 : 1] -= p->ip_len;
            }
        }
        const int side = from_orig ? 0 : 1;
        f->pkts[side]++;
        f->bytes[side] += p->ip_len;
        if (!from_orig) f->seen_reply = true;
        f->last_seen_ns = now_ns;
        f->expires_ns = now_ns + flow_timeout_ns(f);
        return do_allow(e, reason);
    }

    /* ---- slow path: no flow ---- */
    e->st.slowpath++;

    if (p->proto == FW_PROTO_TCP) {
        if (!tcp_is_pure_syn(p->tcp_flags))
            return do_drop(e, p, dir, now_ns, DROP_NOT_SYN, reason);
    } else if (p->proto == FW_PROTO_ICMP) {
        if (p->icmp_type == ICMP_ECHO_REPLY)
            return do_drop(e, p, dir, now_ns, DROP_NO_FLOW, reason);
        if (p->icmp_type != ICMP_ECHO_REQUEST)
            return do_drop(e, p, dir, now_ns, DROP_UNSUPPORTED, reason);
    } else if (p->proto != FW_PROTO_UDP) {
        return do_drop(e, p, dir, now_ns, DROP_UNSUPPORTED, reason);
    }

    const rule_t *r = rules_match(e->rules, p, dir);
    if (!r)
        return do_drop(e, p, dir, now_ns, DROP_NO_RULE, reason);
    if (r->action == ACT_DENY)
        return do_drop(e, p, dir, now_ns, DROP_RULE_DENY, reason);

    f = ft_insert(e->ft, &key, dir, now_ns);
    if (!f)
        return do_drop(e, p, dir, now_ns, DROP_TABLE_FULL, reason);

    f->rule_line = r->line;
    if (p->proto == FW_PROTO_TCP) tcp_flow_init(f);
    f->pkts[0] = 1;
    f->bytes[0] = p->ip_len;
    f->expires_ns = now_ns + flow_timeout_ns(f);
    e->st.flows_created++;
    log_flow("NEW", f, now_ns);
    return do_allow(e, reason);
}

static void expire_cb(const flow_t *f, void *ud)
{
    log_flow("EXPIRE", f, *(uint64_t *)ud);
}

size_t engine_expire(engine_t *e, uint64_t now_ns)
{
    return ft_expire(e->ft, now_ns, expire_cb, &now_ns);
}

void engine_get_stats(const engine_t *e, engine_stats_t *out)
{
    *out = e->st;
    out->flows_expired = ft_expired_total(e->ft);
    out->flows_active = ft_count(e->ft);
}

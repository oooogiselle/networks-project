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
#include "rules.h"
#include "tcpstate.h"

#define DEFAULT_BUCKETS  (1u << 16)
#define DEFAULT_MAX_FLOWS (1u << 18)

struct engine {
    rules_t     *rules;
    flowtable_t *ft;
    engine_stats_t st;
};

engine_t *engine_create_with_rules(rules_t *rules)
{
    if (!rules) return NULL;
    engine_t *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->rules = rules;
    e->ft = ft_create(DEFAULT_BUCKETS, DEFAULT_MAX_FLOWS);
    if (!e->ft) { free(e); return NULL; }
    return e;
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

verdict_t engine_decide(engine_t *e, const pkt_t *p, dir_t dir,
                        uint64_t now_ns, drop_reason_t *reason)
{
    e->st.pkts_total++;

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

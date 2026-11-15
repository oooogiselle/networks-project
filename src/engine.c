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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flowtable.h"
#include "fwalloc.h"
#include "log.h"
#include "parser.h"
#include "rules.h"
#include "tcpstate.h"


_Static_assert(PARSE_RESULT_COUNT <= ENGINE_PARSE_KINDS,
               "grow ENGINE_PARSE_KINDS in engine.h");

static void expire_cb(const flow_t *f, void *ud);

#define RECLAIM_MIN_INTERVAL_NS 1000000000ull   /* 1 s: table-reclaim and ICMP-error windows */

struct engine {
    rules_t     *rules;
    flowtable_t *ft;
    engine_stats_t st;
    uint64_t     clock_ns;       /* time of the packet/sweep being handled, for log lines */
    uint64_t     last_reclaim_ns;
    bool         reclaimed_once;
};

engine_t *engine_create_with_rules_sized(rules_t *rules, size_t max_flows)
{
    if (!rules) return NULL;
    /* Anti-spoofing is not optional: without an `inside` network there is no
     * way to tell a spoofed source address from a genuine one. */
    if (rules->ninside == 0) { rules_free(rules); return NULL; }
    engine_t *e = fw_calloc(1, sizeof *e);
    if (!e) { rules_free(rules); return NULL; }     /* we own rules, always */
    e->rules = rules;
    /* about one bucket per flow slot keeps chains short at capacity */
    e->ft = ft_create(max_flows, max_flows);
    if (!e->ft) { rules_free(rules); free(e); return NULL; }
    ft_set_expire_hook(e->ft, expire_cb, e);
    return e;
}

engine_t *engine_create_with_rules(rules_t *rules)
{
    engine_t *e = engine_create_with_rules_sized(rules, FW_DEFAULT_MAX_FLOWS);
    if (e && !engine_set_limits(e, FW_DEFAULT_MAX_PER_SOURCE, FW_DEFAULT_MAX_OUTSIDE)) {
        engine_destroy(e);
        return NULL;
    }
    return e;
}

bool engine_set_limits(engine_t *e, size_t max_per_source, size_t max_outside)
{
    return ft_set_limits(e->ft, max_per_source, max_outside);
}

engine_t *engine_create(const char *rules_path, char *err, size_t errlen)
{
    rules_t *r = rules_load_file(rules_path, err, errlen);
    if (!r) return NULL;
    if (r->ninside == 0) {
        if (err && errlen)
            snprintf(err, errlen, "%s: declares no inside network (add e.g. "
                     "'inside 10.0.1.0/24'): anti-spoofing needs one", rules_path);
        rules_free(r);
        return NULL;
    }
    engine_t *e = engine_create_with_rules(r);       /* frees r if it fails */
    if (!e && err && errlen) snprintf(err, errlen, "out of memory");
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

/* One CLOSE line per flow, however the close is noticed. */
static void log_close_once(flow_t *f, uint64_t now_ns)
{
    if (f->close_logged) return;
    f->close_logged = true;
    log_flow("CLOSE", f, now_ns);
}

/*
 * ICMP error (unreachable, time exceeded, ...). It is allowed only if
 *   - it is addressed to the sender of the packet it embeds (an error about
 *     A's packet goes to A, so one sent to anyone else cannot be genuine),
 *   - that embedded packet belongs to a tracked flow, and the error travels
 *     back toward the packet's sender,
 *   - a TCP flow is still active (not TIME_WAIT / CLOSED), and
 *   - the flow has not used up its budget of ICMP_ERRORS_PER_FLOW_PER_SEC.
 * The error's own source is deliberately not checked: it is a router on the
 * path, not the flow's peer. Errors never change a flow's state or refresh
 * its timer, so they cannot keep a flow alive; only the rate-limit window
 * is bookkept.
 */
static verdict_t decide_icmp_error(engine_t *e, const pkt_t *p, dir_t dir,
                                   uint64_t now, drop_reason_t *reason)
{
    pkt_t in;
    if (parse_icmp_inner(p, &in) != PARSE_OK)
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    if (p->dst_ip != in.src_ip)
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    /* The embedded packet, as its sender wrote it. */
    const flow_key_t key = { in.src_ip, in.dst_ip, in.src_port, in.dst_port,
                             in.proto };
    bool inner_is_reply = false;
    flow_t *f = ft_lookup(e->ft, &key, now, &inner_is_reply);
    if (!f)
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    /* The offending packet came from the originator (or the responder, if
     * inner_is_reply); the error must arrive from the opposite side. */
    const dir_t inner_sent_on = inner_is_reply ? !f->orig_dir : f->orig_dir;
    if (dir == inner_sent_on)
        return do_drop(e, p, dir, now, DROP_SPOOF, reason);

    if (f->key.proto == FW_PROTO_TCP &&
        (f->tcp_state == TCPS_TIME_WAIT || f->tcp_state == TCPS_CLOSED))
        return do_drop(e, p, dir, now, DROP_ICMP_ERR, reason);

    /* Per-flow budget in one-second windows. */
    if (now - f->icmp_err_window_ns >= RECLAIM_MIN_INTERVAL_NS ||
        now < f->icmp_err_window_ns) {
        f->icmp_err_window_ns = now;
        f->icmp_err_count = 0;
    }
    if (f->icmp_err_count >= ICMP_ERRORS_PER_FLOW_PER_SEC)
        return do_drop(e, p, dir, now, DROP_ICMP_RATE, reason);
    f->icmp_err_count++;

    e->st.icmp_related++;
    return do_allow(e, reason);
}

/*
 * The table is full. Flows that timed out since the last periodic sweep still
 * hold slots, which would refuse new connections for no good reason, so sweep
 * once and let the caller retry. Limited to one sweep per second: a flood into
 * a table of live flows must not make every packet pay for a full scan.
 * Returns true if at least one slot was freed.
 */
static bool reclaim_expired(engine_t *e, uint64_t now_ns)
{
    if (e->reclaimed_once && now_ns - e->last_reclaim_ns < RECLAIM_MIN_INTERVAL_NS)
        return false;
    e->reclaimed_once = true;
    e->last_reclaim_ns = now_ns;
    return ft_expire(e->ft, now_ns, expire_cb, e) > 0;
}

verdict_t engine_decide(engine_t *e, const pkt_t *p, dir_t dir,
                        uint64_t now_ns, drop_reason_t *reason)
{
    e->st.pkts_total++;
    e->clock_ns = now_ns;

    /* Anti-spoofing: the outside may not use inside addresses, the inside must
     * use them. engine creation guarantees an `inside` network exists. */
    if (rules_is_inside(e->rules, p->src_ip) != (dir == DIR_IN))
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
        log_close_once(f, now_ns);     /* already logged when it closed */
        ft_remove(e->ft, f);
        f = NULL;
    }

    /* ---- fast path ---- */
    if (f) {
        e->st.fastpath++;
        const bool from_orig = !is_reply;

        /* A packet on this flow's tuple always arrives on the right interface
         * by now: the anti-spoofing check above makes every inside source
         * arrive on the inside and every outside source on the outside, and a
         * flow only ever starts between an inside and an outside host (see the
         * destination check on the slow path). So there is no separate
         * wrong-interface case left to test for here. */

        /* An echo flow carries requests from its originator and replies from
         * its peer, nothing else. Without this a host spoofing the peer could
         * send requests inward on a flow that only ever allowed replies. The
         * packet is dropped before any counter or timer is touched. */
        if (p->proto == FW_PROTO_ICMP &&
            p->icmp_type != (from_orig ? ICMP_ECHO_REQUEST : ICMP_ECHO_REPLY))
            return do_drop(e, p, dir, now_ns, DROP_ICMP_TYPE, reason);

        /* A finished TCP connection (TIME_WAIT, CLOSED) must not be kept alive
         * by traffic: only the packet that closed it starts its short timer. */
        bool refresh = true;
        if (p->proto == FW_PROTO_TCP) {
            tcp_state_t before = f->tcp_state;
            if (!tcp_track_ex(f, p->tcp_flags, from_orig, p->payload_len))
                return do_drop(e, p, dir, now_ns, DROP_TCP_STATE, reason);
            refresh = f->tcp_state != before ||
                      (f->tcp_state != TCPS_TIME_WAIT && f->tcp_state != TCPS_CLOSED);
            if (f->tcp_state != before &&
                (f->tcp_state == TCPS_TIME_WAIT || f->tcp_state == TCPS_CLOSED)) {
                f->pkts[from_orig ? 0 : 1]++;     /* so the log line is current */
                f->bytes[from_orig ? 0 : 1] += p->ip_len;
                log_close_once(f, now_ns);
                f->pkts[from_orig ? 0 : 1]--;
                f->bytes[from_orig ? 0 : 1] -= p->ip_len;
            }
        }
        const int side = from_orig ? 0 : 1;
        f->pkts[side]++;
        f->bytes[side] += p->ip_len;
        if (!from_orig) f->seen_reply = true;
        if (refresh) {
            f->last_seen_ns = now_ns;
            f->expires_ns = now_ns + flow_timeout_ns(f);
        }
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

    /* A flow runs between an inside and an outside host. A packet from the
     * inside aimed at an inside address (or from the outside at an outside
     * one) has no business crossing the firewall, and nothing may be sent to
     * an inside network's broadcast address: whatever the rules say. */
    const bool dst_inside = rules_is_inside(e->rules, p->dst_ip);
    if (dst_inside == (dir == DIR_IN) ||
        rules_is_inside_broadcast(e->rules, p->dst_ip))
        return do_drop(e, p, dir, now_ns, DROP_BAD_DST, reason);

    const rule_t *r = rules_match(e->rules, p, dir);
    if (!r)
        return do_drop(e, p, dir, now_ns, DROP_NO_RULE, reason);
    if (r->action == ACT_DENY)
        return do_drop(e, p, dir, now_ns, DROP_RULE_DENY, reason);

    ft_status_t why = FT_OK;
    f = ft_insert_ex(e->ft, &key, dir, now_ns, &why);
    if (!f && reclaim_expired(e, now_ns))     /* timed-out flows may be holding the room */
        f = ft_insert_ex(e->ft, &key, dir, now_ns, &why);
    if (!f)
        return do_drop(e, p, dir, now_ns,
                       why == FT_SRC_LIMIT      ? DROP_SRC_LIMIT :
                       why == FT_OUTSIDE_QUOTA  ? DROP_OUTSIDE_QUOTA : DROP_TABLE_FULL,
                       reason);

    f->rule_line = r->line;
    if (p->proto == FW_PROTO_TCP) tcp_flow_init(f);
    f->pkts[0] = 1;
    f->bytes[0] = p->ip_len;
    f->expires_ns = now_ns + flow_timeout_ns(f);
    e->st.flows_created++;
    log_flow("NEW", f, now_ns);
    return do_allow(e, reason);
}

/* A flow whose CLOSE was logged is already reported; do not log it again. */
static void expire_cb(const flow_t *f, void *ud)
{
    const engine_t *e = ud;
    if (!f->close_logged) log_flow("EXPIRE", f, e->clock_ns);
}

size_t engine_expire(engine_t *e, uint64_t now_ns)
{
    e->clock_ns = now_ns;
    return ft_expire(e->ft, now_ns, expire_cb, e);
}

bool engine_undo_new_flow(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now_ns)
{
    const flow_key_t key = { p->src_ip, p->dst_ip, p->src_port, p->dst_port, p->proto };
    bool is_reply = false;
    flow_t *f = ft_lookup(e->ft, &key, now_ns, &is_reply);
    /* Only the very packet that created the flow: it was the first from its
     * originator and nothing has come back. */
    const bool created_by_it = f && !is_reply && dir == f->orig_dir &&
                               f->pkts[0] == 1 && f->pkts[1] == 0;
    if (created_by_it) {
        ft_remove(e->ft, f);
        e->st.flows_created--;
    }
    e->st.pkts_allowed--;                  /* it was never delivered */
    e->st.pkts_dropped++;
    e->st.drops[DROP_WRITE_FAILED]++;
    log_drop(p, dir, DROP_WRITE_FAILED, now_ns);
    return created_by_it;
}

void engine_get_stats(const engine_t *e, engine_stats_t *out)
{
    *out = e->st;
    out->flows_expired = ft_expired_total(e->ft);
    out->flows_active = ft_count(e->ft);
}

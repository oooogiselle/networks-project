/*=============================================================================
 * File Name:   engine.c
 * Author:      Eva Tate and Giselle Wu
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
 *   blocked source -> dropped (a port scanner, see scandetect.h)
 *   existing flow  -> FAST PATH: hash lookup + state update, no rules
 *   no flow        -> SLOW PATH: sanity-check, evaluate rules, maybe create
 *                     (an allow rule's `limit` is checked here, ratelimit.h)
 *   TCP on a flow  -> also inside its sequence window (tcpseq.h), if on
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
#include "ratelimit.h"
#include "scandetect.h"
#include "tcpseq.h"
#include "tcpstate.h"


_Static_assert(PARSE_RESULT_COUNT <= ENGINE_PARSE_KINDS,
               "grow ENGINE_PARSE_KINDS in engine.h");

static void expire_cb(const flow_t *f, void *ud);
static void identify_app(engine_t *e, flow_t *f, const pkt_t *p, uint64_t now_ns);

#define RECLAIM_MIN_INTERVAL_NS 1000000000ull   /* 1 s: table-reclaim and ICMP-error windows */

struct engine {
    rules_t     *rules;
    flowtable_t *ft;
    scan_t      *scan;           /* port-scan detection; NULL = off */
    scan_cfg_t   scan_cfg;
    rl_t        *rl;             /* per-rule connection rate limits (ratelimit.h) */
    bool         tcp_window;     /* TCP sequence-number checks (tcpseq.h) */
    engine_stats_t st;
    uint64_t     clock_ns;       /* time of the packet/sweep being handled, for log lines */
    uint64_t     last_reclaim_ns;
    bool         reclaimed_once;
    uint64_t     reject_window_ns;   /* start of the current REJECTS_PER_SEC window */
    unsigned     rejects_in_window;
    uint64_t     evicted_since_sweep;   /* for the once-a-second SYNFLOOD line */
    uint64_t     last_sweep_ns;         /* 0 until the first engine_expire() */
    uint64_t     first_evict_ns;        /* first eviction since the last sweep */
    /* The existing flow the last engine_decide() changed, and a copy of it as
     * it was before, so engine_undo_new_flow() can put it back if the packet
     * is never delivered. NULL when the last decision changed no flow. */
    flow_t      *undo_flow;
    flow_t       undo_copy;
    bool         undo_icmp_related;
    /* The rate-limit admission the last engine_decide() used up, if any, so
     * engine_undo_new_flow() can give it back. */
    const rule_t *undo_rl_rule;
    uint32_t     undo_rl_idx;
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
    e->rl = rl_create();
    if (!e->rl) { ft_destroy(e->ft); rules_free(rules); free(e); return NULL; }
    ft_set_expire_hook(e->ft, expire_cb, e);
    return e;
}

engine_t *engine_create_with_rules(rules_t *rules)
{
    engine_t *e = engine_create_with_rules_sized(rules, FW_DEFAULT_MAX_FLOWS);
    const scan_cfg_t scan = { SCAN_DEFAULT_PORTS, SCAN_DEFAULT_WINDOW_S,
                              SCAN_DEFAULT_BLOCK_S };
    if (e && (!engine_set_limits(e, FW_DEFAULT_MAX_PER_SOURCE, FW_DEFAULT_MAX_OUTSIDE) ||
              !engine_set_scan(e, &scan))) {
        engine_destroy(e);
        return NULL;
    }
    return e;
}

bool engine_set_limits(engine_t *e, size_t max_per_source, size_t max_outside)
{
    return ft_set_limits(e->ft, max_per_source, max_outside);
}

rules_t *engine_load_rules(const char *path, char *err, size_t errlen)
{
    rules_t *r = rules_load_file(path, err, errlen);
    if (!r) return NULL;
    if (r->ninside == 0) {
        if (err && errlen)
            snprintf(err, errlen, "%s: declares no inside network (add e.g. "
                     "'inside 10.0.1.0/24'): anti-spoofing needs one", path);
        rules_free(r);
        return NULL;
    }
    return r;
}

engine_t *engine_create(const char *rules_path, char *err, size_t errlen)
{
    rules_t *r = engine_load_rules(rules_path, err, errlen);
    if (!r) return NULL;
    engine_t *e = engine_create_with_rules(r);       /* frees r if it fails */
    if (!e && err && errlen) snprintf(err, errlen, "out of memory");
    return e;
}

void engine_destroy(engine_t *e)
{
    if (!e) return;
    ft_destroy(e->ft);
    rl_destroy(e->rl);
    scan_destroy(e->scan);
    rules_free(e->rules);
    free(e);
}

/*
 * Count one probe toward port-scan detection: an outside TCP/UDP packet the
 * policy refused. Logs SCAN when it pushes its source over the threshold.
 */
static void scan_count(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now)
{
    uint64_t span;
    if (e->scan && dir == DIR_OUT &&
        (p->proto == FW_PROTO_TCP || p->proto == FW_PROTO_UDP) &&
        scan_hit(e->scan, p->src_ip, p->proto, p->dst_port, now, &span)) {
        e->st.scans_detected++;
        log_scan(p->src_ip, e->scan_cfg.ports, span, e->scan_cfg.block_s, now);
    }
}

static verdict_t do_drop(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now,
                         drop_reason_t why, drop_reason_t *out)
{
    e->st.pkts_dropped++;
    e->st.drops[why]++;
    log_drop(p, dir, why, now);
    if (out) *out = why;
    /* Probing for open ports: refused by the policy, or a TCP packet with no
     * connection (ACK, FIN, Xmas, NULL scans). Drops on existing flows, of
     * spoofed sources, of wrong destinations and for full tables do not count. */
    if (why == DROP_NO_RULE || why == DROP_RULE_DENY || why == DROP_RULE_REJECT ||
        why == DROP_NOT_SYN)
        scan_count(e, p, dir, now);
    return VERDICT_DROP;
}

void engine_note_unsolicited(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now_ns)
{
    e->clock_ns = now_ns;
    scan_count(e, p, dir, now_ns);
}

/* Remember f as it is now, before this packet changes it. */
static void save_for_undo(engine_t *e, flow_t *f)
{
    e->undo_flow = f;
    e->undo_copy = *f;
}

/* A reject rule matched: a drop that is also answered, within the budget. */
static verdict_t do_reject(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now,
                           drop_reason_t *out)
{
    do_drop(e, p, dir, now, DROP_RULE_REJECT, out);
    if (now - e->reject_window_ns >= RECLAIM_MIN_INTERVAL_NS || now < e->reject_window_ns) {
        e->reject_window_ns = now;
        e->rejects_in_window = 0;
    }
    if (e->rejects_in_window >= REJECTS_PER_SEC) {
        e->st.rejects_limited++;
        return VERDICT_DROP;
    }
    e->rejects_in_window++;
    return VERDICT_REJECT;
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
    save_for_undo(e, f);
    e->undo_icmp_related = true;
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
    e->undo_flow = NULL;
    e->undo_icmp_related = false;
    e->undo_rl_rule = NULL;

    /* Anti-spoofing: the outside may not use inside addresses, the inside must
     * use them. engine creation guarantees an `inside` network exists. */
    if (rules_is_inside(e->rules, p->src_ip) != (dir == DIR_IN))
        return do_drop(e, p, dir, now_ns, DROP_BAD_SRC, reason);

    /* A blocked port scanner gets nothing through, not even on existing
     * flows. Costs nothing while nobody is blocked. */
    if (dir == DIR_OUT && e->scan && scan_nblocked(e->scan) &&
        scan_blocked(e->scan, p->src_ip, now_ns))
        return do_drop(e, p, dir, now_ns, DROP_SCAN_BLOCKED, reason);

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

        /* From here on the packet changes the flow. Keep a copy, in case the
         * other side never receives it (see engine_undo_new_flow). A packet
         * tcp_track_ex() rejects leaves the flow untouched. */
        save_for_undo(e, f);

        /* A finished TCP connection (TIME_WAIT, CLOSED) must not be kept alive
         * by traffic: only the packet that closed it starts its short timer. */
        bool refresh = true;
        if (p->proto == FW_PROTO_TCP) {
            tcp_state_t before = f->tcp_state;
            /* Outside the sequence window: forged (a blind RST or injected
             * data) or hopelessly stale. Dropped before it touches the flow. */
            if (e->tcp_window && !tcpseq_check(f, p, from_orig))
                return do_drop(e, p, dir, now_ns, DROP_TCP_WINDOW, reason);
            if (!tcp_track_ex(f, p->tcp_flags, from_orig, p->payload_len))
                return do_drop(e, p, dir, now_ns, DROP_TCP_STATE, reason);
            tcpseq_update(f, p, from_orig);
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
        identify_app(e, f, p, now_ns);
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
    switch (r->action) {
    case ACT_ALLOW:
        break;
    case ACT_REJECT:
        return do_reject(e, p, dir, now_ns, reason);
    case ACT_DENY:
    default:                       /* an unknown action never allows */
        return do_drop(e, p, dir, now_ns, DROP_RULE_DENY, reason);
    }

    /* `limit N/PERIOD`: this source may only open so many connections
     * through this rule. Only admitted connections count; the admission is
     * given back below if the flow cannot be created after all. */
    const uint32_t ridx = (uint32_t)(r - e->rules->v);
    if (r->limit_n) {
        bool first = false;
        if (!rl_admit(e->rl, ridx, p->src_ip, r->limit_n, r->limit_period_ns,
                      now_ns, &first)) {
            if (first)
                log_ratelimit(p->src_ip, r->limit_n, r->limit_period_ns, r->line, now_ns);
            return do_drop(e, p, dir, now_ns, DROP_RATE_LIMITED, reason);
        }
    }

    ft_status_t why = FT_OK;
    f = ft_insert_ex(e->ft, &key, dir, now_ns, &why);
    if (!f && reclaim_expired(e, now_ns))     /* timed-out flows may be holding the room */
        f = ft_insert_ex(e->ft, &key, dir, now_ns, &why);
    /* SYN flood: forged SYNs fill the room with connections that will never
     * complete. Push out the oldest one, as Linux does with its SYN backlog,
     * so real clients still get in. Only an outside TCP flow that never
     * finished its handshake is ever evicted, and never to make room for a
     * source that is over its own cap. */
    if (!f && (why == FT_FULL || why == FT_OUTSIDE_QUOTA) &&
        !ft_source_at_limit(e->ft, p->src_ip) && ft_evict_halfopen(e->ft, NULL, NULL)) {
        e->st.flows_evicted++;
        if (e->evicted_since_sweep++ == 0) e->first_evict_ns = now_ns;
        f = ft_insert_ex(e->ft, &key, dir, now_ns, &why);
    }
    if (!f && r->limit_n)
        rl_refund(e->rl, ridx, p->src_ip, r->limit_n, r->limit_period_ns);
    if (!f)
        return do_drop(e, p, dir, now_ns,
                       why == FT_SRC_LIMIT      ? DROP_SRC_LIMIT :
                       why == FT_OUTSIDE_QUOTA  ? DROP_OUTSIDE_QUOTA : DROP_TABLE_FULL,
                       reason);

    f->rule_line = r->line;
    if (r->limit_n) {
        e->undo_rl_rule = r;
        e->undo_rl_idx = ridx;
    }
    if (p->proto == FW_PROTO_TCP) {
        tcp_flow_init(f);
        tcpseq_init(f, p);         /* always kept, so turning checks on costs nothing */
    }
    f->pkts[0] = 1;
    f->bytes[0] = p->ip_len;
    f->expires_ns = now_ns + flow_timeout_ns(f);
    e->st.flows_created++;
    log_flow("NEW", f, now_ns);
    identify_app(e, f, p, now_ns);          /* e.g. a DNS query, or data in a SYN */
    return do_allow(e, reason);
}

/*
 * Label a flow by what its payload is (see appid.h). The first few
 * data-carrying packets of either direction are examined; the first
 * recognized protocol wins, and after APPID_MAX_TRIES unrecognized data
 * packets the flow is called "other". It is logged once when decided. This
 * only labels: it is called after the verdict, and never changes it.
 */
static void identify_app(engine_t *e, flow_t *f, const pkt_t *p, uint64_t now_ns)
{
    if (f->app != APP_UNKNOWN || p->payload_len == 0 ||
        (p->proto != FW_PROTO_TCP && p->proto != FW_PROTO_UDP))
        return;
    app_t a = appid_detect(p->proto, p->payload, p->payload_len);
    if (a == APP_UNKNOWN) {
        if (++f->app_tries < APPID_MAX_TRIES) return;
        a = APP_OTHER;
    }
    f->app = (uint8_t)a;
    e->st.app_flows[a]++;
    const app_t expected = appid_expected_for_port(f->key.proto, f->key.dst_port);
    if (expected != APP_UNKNOWN && expected != a) e->st.app_mismatch++;
    log_flow("APP", f, now_ns);
}

/* A flow whose CLOSE was logged is already reported; do not log it again. */
static void expire_cb(const flow_t *f, void *ud)
{
    const engine_t *e = ud;
    if (!f->close_logged) log_flow("EXPIRE", f, e->clock_ns);
}

static void unblock_cb(uint32_t ip, uint64_t dropped, void *ud)
{
    const engine_t *e = ud;
    log_unblock(ip, dropped, e->clock_ns);
}

size_t engine_expire(engine_t *e, uint64_t now_ns)
{
    e->clock_ns = now_ns;
    if (e->evicted_since_sweep) {
        const uint64_t since = e->last_sweep_ns ? e->last_sweep_ns : e->first_evict_ns;
        log_synflood(e->evicted_since_sweep, now_ns - since, now_ns);
        e->evicted_since_sweep = 0;
    }
    e->last_sweep_ns = now_ns;
    if (e->scan) scan_expire(e->scan, now_ns, unblock_cb, e);
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
                               f->pkts[0] == 1 && f->pkts[1] == 0 && f != e->undo_flow;
    if (created_by_it) {
        ft_remove(e->ft, f);
        e->st.flows_created--;
        if (e->undo_rl_rule)       /* the connection never happened */
            rl_refund(e->rl, e->undo_rl_idx, p->src_ip, e->undo_rl_rule->limit_n,
                      e->undo_rl_rule->limit_period_ns);
    } else if (e->undo_flow) {
        /* A packet on an existing flow: the other side never saw it, so it
         * must not count, move the TCP state (a FIN that was never delivered
         * must not close the flow), refresh the timer, or use up an ICMP
         * error budget. Two things stay: the hash-chain link, which may have
         * changed, and the application label, which describes what the
         * payload was and has already been counted and logged. */
        flow_t *u = e->undo_flow;
        flow_t *next = u->next;
        flow_t *ho_prev = u->ho_prev, *ho_next = u->ho_next;
        const bool ho_linked = u->ho_linked;
        const uint8_t app = u->app, app_tries = u->app_tries;
        *u = e->undo_copy;
        u->next = next;
        u->ho_prev = ho_prev;          /* the half-open queue links, like the chain */
        u->ho_next = ho_next;
        u->ho_linked = ho_linked;
        u->app = app;
        u->app_tries = app_tries;
        if (e->undo_icmp_related) e->st.icmp_related--;
    }
    e->undo_flow = NULL;
    e->undo_icmp_related = false;
    e->undo_rl_rule = NULL;
    e->st.pkts_allowed--;                  /* it was never delivered */
    e->st.pkts_dropped++;
    e->st.drops[DROP_WRITE_FAILED]++;
    log_drop(p, dir, DROP_WRITE_FAILED, now_ns);
    return created_by_it;
}

bool engine_flow_origin(engine_t *e, const pkt_t *p, uint64_t now_ns, dir_t *orig_dir)
{
    const flow_key_t key = { p->src_ip, p->dst_ip, p->src_port, p->dst_port, p->proto };
    bool is_reply = false;
    const flow_t *f = ft_lookup(e->ft, &key, now_ns, &is_reply);
    if (f && orig_dir) *orig_dir = f->orig_dir;
    return f != NULL;
}

bool engine_replace_rules(engine_t *e, rules_t *r)
{
    if (!r || r->ninside == 0) { rules_free(r); return false; }
    rules_free(e->rules);
    e->rules = r;
    rl_clear(e->rl);               /* rule numbers changed: start counting afresh */
    e->undo_rl_rule = NULL;        /* it pointed into the old rules */
    return true;
}

bool engine_reload_rules(engine_t *e, const char *path, char *err, size_t errlen)
{
    rules_t *r = engine_load_rules(path, err, errlen);
    return r && engine_replace_rules(e, r);
}

const rules_t *engine_rules(const engine_t *e)
{
    return e->rules;
}

void engine_get_stats(const engine_t *e, engine_stats_t *out)
{
    *out = e->st;
    out->flows_expired = ft_expired_total(e->ft);
    out->flows_active = ft_count(e->ft);
    out->hosts_blocked = e->scan ? scan_nblocked(e->scan) : 0;
}

void engine_set_tcp_window(engine_t *e, bool on)
{
    e->tcp_window = on;
}

bool engine_set_scan(engine_t *e, const scan_cfg_t *cfg)
{
    scan_t *s = NULL;
    if (cfg->ports) {
        s = scan_create(cfg);
        if (!s) return false;
    }
    scan_destroy(e->scan);
    e->scan = s;
    e->scan_cfg = *cfg;
    return true;
}

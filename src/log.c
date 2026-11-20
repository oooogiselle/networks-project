/*=============================================================================
 * File Name:   log.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Logging implementation. Flow open/close lines include duration,
 *              packets and bytes; drops are logged with a reason; counters are
 *              printed on demand.
 =============================================================================*/

#include "log.h"

#include <inttypes.h>
#include <stdarg.h>
#include <string.h>

#include "appid.h"
#include "parser.h"

static FILE *g_out = NULL;
static log_level_t g_level = LOG_OFF;

/*
 * The limiter is a GCRA ("virtual scheduling") bucket: each line adds one
 * interval to a theoretical arrival time, and a line is allowed while that
 * time is less than FW_LOG_BURST intervals ahead of now. It needs one
 * integer, handles fractional rates exactly, and costs a compare per line.
 */
#define LOG_INTERVAL_NS (1000000000ull / FW_LOG_LINES_PER_SEC)
#define LOG_WINDOW_NS   ((uint64_t)FW_LOG_BURST * LOG_INTERVAL_NS)

static uint64_t g_tat;               /* theoretical arrival time of the next line */
static uint64_t g_suppressed;        /* since fw_log_set() */
static uint64_t g_pending;           /* suppressed since the last summary line */

void fw_log_set(FILE *out, log_level_t level)
{
    g_out = out;
    g_level = level;
    g_tat = g_suppressed = g_pending = 0;
}

uint64_t fw_log_suppressed(void) { return g_suppressed; }

/* May a line be written at now_ns? If lines were dropped before, say so first. */
static bool log_allowed(uint64_t now_ns)
{
    if (g_tat > now_ns + 2 * LOG_WINDOW_NS)    /* the clock went backwards */
        g_tat = now_ns;
    if (g_tat >= now_ns + LOG_WINDOW_NS) {
        g_suppressed++;
        g_pending++;
        return false;
    }
    g_tat = (now_ns > g_tat ? now_ns : g_tat) + LOG_INTERVAL_NS;
    if (g_pending) {
        fprintf(g_out, "[%10.6f] LOG %" PRIu64 " log lines suppressed (limit %d/s)\n",
                now_ns / 1e9, g_pending, FW_LOG_LINES_PER_SEC);
        g_pending = 0;
    }
    return true;
}

bool fw_log_enabled(log_level_t level)
{
    return g_out && g_level >= level;
}

const char *ip_str(uint32_t ip, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 0xff,
             (ip >> 8) & 0xff, ip & 0xff);
    return buf;
}

const char *proto_str(uint8_t proto)
{
    switch (proto) {
    case FW_PROTO_TCP:  return "tcp";
    case FW_PROTO_UDP:  return "udp";
    case FW_PROTO_ICMP: return "icmp";
    }
    return "ip";
}

const char *drop_reason_str(drop_reason_t r)
{
    switch (r) {
    case DROP_NONE:        return "none";
    case DROP_NO_RULE:     return "no-rule(default-deny)";
    case DROP_RULE_DENY:   return "rule-deny";
    case DROP_NOT_SYN:     return "tcp-not-syn(no-flow)";
    case DROP_TCP_STATE:   return "tcp-bad-state";
    case DROP_NO_FLOW:     return "no-flow";
    case DROP_SPOOF:       return "wrong-direction";
    case DROP_TABLE_FULL:  return "table-full";
    case DROP_UNSUPPORTED: return "unsupported";
    case DROP_BAD_SRC:     return "bad-source-address(anti-spoof)";
    case DROP_ICMP_ERR:    return "icmp-error-unrelated";
    case DROP_ICMP_TYPE:   return "icmp-bad-type";
    case DROP_ICMP_RATE:   return "icmp-error-rate-limited";
    case DROP_BAD_DST:     return "wrong-destination";
    case DROP_SRC_LIMIT:   return "per-source-limit";
    case DROP_OUTSIDE_QUOTA: return "outside-quota";
    case DROP_WRITE_FAILED: return "write-failed";
    case DROP_RULE_REJECT: return "rule-reject";
    case DROP_SCAN_BLOCKED: return "scan-blocked";
    case DROP_RATE_LIMITED: return "rate-limited";
    case DROP_TCP_WINDOW:  return "tcp-out-of-window";
    case DROP_APP_BLOCKED: return "app-not-allowed";
    case DROP_REASON_COUNT: break;
    }
    return "?";
}

void log_flow(const char *event, const flow_t *f, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_INFO) || !log_allowed(now_ns)) return;
    char a[16], b[16];
    /* Duration = how long the flow was active. An EXPIRE is logged at sweep
     * time, which is after the idle timeout; count up to the last packet. */
    const uint64_t end = strcmp(event, "EXPIRE") == 0 ? f->last_seen_ns : now_ns;
    const double dur = end > f->created_ns ? (end - f->created_ns) / 1e9 : 0.0;
    fprintf(g_out,
            "[%10.6f] FLOW %-6s %s %s:%u -> %s:%u state=%s rule=%d app=%s dur=%.3fs "
            "pkts=%" PRIu64 "/%" PRIu64 " bytes=%" PRIu64 "/%" PRIu64,
            now_ns / 1e9, event, proto_str(f->key.proto),
            ip_str(f->key.src_ip, a, sizeof a), f->key.src_port,
            ip_str(f->key.dst_ip, b, sizeof b), f->key.dst_port,
            tcp_state_str(f->tcp_state), f->rule_line, app_name((app_t)f->app), dur,
            f->pkts[0], f->pkts[1], f->bytes[0], f->bytes[1]);
    /* The port says one thing, the payload another: say so on the APP line. */
    const app_t expected = appid_expected_for_port(f->key.proto, f->key.dst_port);
    if (strcmp(event, "APP") == 0 && expected != APP_UNKNOWN && expected != (app_t)f->app)
        fprintf(g_out, " mismatch(port suggests %s)", app_name(expected));
    fputc('\n', g_out);
}

void log_scan(uint32_t ip, unsigned nports, uint64_t span_ns, uint32_t block_s,
              uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_INFO) || !log_allowed(now_ns)) return;
    char a[16];
    fprintf(g_out, "[%10.6f] SCAN    %s dropped on %u ports in %.2fs, blocking for %us\n",
            now_ns / 1e9, ip_str(ip, a, sizeof a), nports, span_ns / 1e9,
            (unsigned)block_s);
}

void log_unblock(uint32_t ip, uint64_t dropped, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_INFO) || !log_allowed(now_ns)) return;
    char a[16];
    fprintf(g_out, "[%10.6f] UNBLOCK %s (dropped %" PRIu64 " packets while blocked)\n",
            now_ns / 1e9, ip_str(ip, a, sizeof a), dropped);
}

void log_ratelimit(uint32_t ip, uint32_t n, uint64_t period_ns, int rule_line,
                   uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_INFO) || !log_allowed(now_ns)) return;
    char a[16];
    const char *unit = period_ns >= 3600 * 1000000000ull ? "hour" :
                       period_ns >= 60 * 1000000000ull   ? "min"  : "sec";
    fprintf(g_out, "[%10.6f] LIMIT   %s over %" PRIu32 "/%s on rule line %d, "
            "dropping its new connections\n",
            now_ns / 1e9, ip_str(ip, a, sizeof a), n, unit, rule_line);
}

void log_synflood(uint64_t n, uint64_t window_ns, uint64_t now_ns)
{
    /* Emitted at most once per engine_expire() (about once a second), so it
     * cannot flood; it skips the per-line limiter deliberately, or a flood
     * of FLOW NEW lines would suppress the very summary that reports it. */
    if (!fw_log_enabled(LOG_INFO)) return;
    fprintf(g_out, "[%10.6f] SYNFLOOD table under pressure: evicted %" PRIu64
            " half-open connections in the last %.1fs to admit new ones\n",
            now_ns / 1e9, n, window_ns / 1e9);
}

void log_drop(const pkt_t *p, dir_t dir, drop_reason_t why, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_DEBUG) || !log_allowed(now_ns)) return;
    char a[16], b[16];
    fprintf(g_out, "[%10.6f] DROP %s %s:%u -> %s:%u flags=0x%02x on=%s why=%s\n",
            now_ns / 1e9, proto_str(p->proto),
            ip_str(p->src_ip, a, sizeof a), p->src_port,
            ip_str(p->dst_ip, b, sizeof b), p->dst_port, p->tcp_flags,
            dir == DIR_IN ? "in" : "out", drop_reason_str(why));
}

void log_parse_fail(unsigned result, dir_t dir, size_t len, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_DEBUG) || !log_allowed(now_ns)) return;
    fprintf(g_out, "[%10.6f] DROP unparsable len=%zu on=%s why=%s\n",
            now_ns / 1e9, len, dir == DIR_IN ? "in" : "out",
            parse_result_str((parse_result_t)result));
}

void engine_stats_print(const engine_stats_t *s, FILE *out)
{
    fprintf(out, "packets: total=%" PRIu64 " allowed=%" PRIu64 " dropped=%" PRIu64 "\n",
            s->pkts_total, s->pkts_allowed, s->pkts_dropped);
    fprintf(out, "icmp:    related-errors-allowed=%" PRIu64 "\n", s->icmp_related);
    fprintf(out, "path:    fast=%" PRIu64 " slow=%" PRIu64 "\n", s->fastpath, s->slowpath);
    fprintf(out, "apps:    http=%" PRIu64 " tls=%" PRIu64 " dns=%" PRIu64 " other=%" PRIu64
            " mismatched=%" PRIu64 " blocked=%" PRIu64 "\n",
            s->app_flows[APP_HTTP], s->app_flows[APP_TLS], s->app_flows[APP_DNS],
            s->app_flows[APP_OTHER], s->app_mismatch, s->apps_blocked);
    fprintf(out, "flows:   created=%" PRIu64 " expired=%" PRIu64 " active=%" PRIu64
            " evicted=%" PRIu64 "\n",
            s->flows_created, s->flows_expired, s->flows_active, s->flows_evicted);
    fprintf(out, "scan:    detected=%" PRIu64 " blocked-now=%" PRIu64 "\n",
            s->scans_detected, s->hosts_blocked);
    for (int i = 1; i < PARSE_RESULT_COUNT; i++)
        if (s->parse_fail[i])
            fprintf(out, "parse-fail[%s]=%" PRIu64 "\n",
                    parse_result_str((parse_result_t)i), s->parse_fail[i]);
    for (int i = 1; i < DROP_REASON_COUNT; i++)
        if (s->drops[i])
            fprintf(out, "drop[%s]=%" PRIu64 "\n", drop_reason_str((drop_reason_t)i),
                    s->drops[i]);
    if (s->rejects_limited)
        fprintf(out, "reject:  over-the-rate-limit(dropped-silently)=%" PRIu64 "\n",
                s->rejects_limited);
}

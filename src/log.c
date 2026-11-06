#include "log.h"

#include <inttypes.h>
#include <stdarg.h>

static FILE *g_out = NULL;
static log_level_t g_level = LOG_OFF;

void fw_log_set(FILE *out, log_level_t level)
{
    g_out = out;
    g_level = level;
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
    case DROP_REASON_COUNT: break;
    }
    return "?";
}

void log_flow(const char *event, const flow_t *f, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_INFO)) return;
    char a[16], b[16];
    fprintf(g_out,
            "[%10.6f] FLOW %-6s %s %s:%u -> %s:%u state=%s rule=%d "
            "pkts=%" PRIu64 "/%" PRIu64 " bytes=%" PRIu64 "/%" PRIu64 "\n",
            now_ns / 1e9, event, proto_str(f->key.proto),
            ip_str(f->key.src_ip, a, sizeof a), f->key.src_port,
            ip_str(f->key.dst_ip, b, sizeof b), f->key.dst_port,
            tcp_state_str(f->tcp_state), f->rule_line,
            f->pkts[0], f->pkts[1], f->bytes[0], f->bytes[1]);
}

void log_drop(const pkt_t *p, dir_t dir, drop_reason_t why, uint64_t now_ns)
{
    if (!fw_log_enabled(LOG_DEBUG)) return;
    char a[16], b[16];
    fprintf(g_out, "[%10.6f] DROP %s %s:%u -> %s:%u flags=0x%02x on=%s why=%s\n",
            now_ns / 1e9, proto_str(p->proto),
            ip_str(p->src_ip, a, sizeof a), p->src_port,
            ip_str(p->dst_ip, b, sizeof b), p->dst_port, p->tcp_flags,
            dir == DIR_IN ? "in" : "out", drop_reason_str(why));
}

void engine_stats_print(const engine_stats_t *s, FILE *out)
{
    fprintf(out, "packets: total=%" PRIu64 " allowed=%" PRIu64 " dropped=%" PRIu64 "\n",
            s->pkts_total, s->pkts_allowed, s->pkts_dropped);
    fprintf(out, "path:    fast=%" PRIu64 " slow=%" PRIu64 "\n", s->fastpath, s->slowpath);
    fprintf(out, "flows:   created=%" PRIu64 " expired=%" PRIu64 " active=%" PRIu64 "\n",
            s->flows_created, s->flows_expired, s->flows_active);
    for (int i = 1; i < DROP_REASON_COUNT; i++)
        if (s->drops[i])
            fprintf(out, "drop[%s]=%" PRIu64 "\n", drop_reason_str((drop_reason_t)i),
                    s->drops[i]);
}

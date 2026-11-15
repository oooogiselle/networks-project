/*=============================================================================
 * File Name:   test_log.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Unit tests for logging: names for protocols and drop reasons, the per-drop
 *              debug line, log-level gating, and the statistics summary.
 =============================================================================*/

#include "log.h"
#include "parser.h"
#include "testutil.h"

static char *slurp(FILE *f)
{
    static char buf[4096];
    rewind(f);
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    return buf;
}

static void test_protocol_and_ip_names(void)
{
    CHECK(strcmp(proto_str(FW_PROTO_TCP), "tcp") == 0);
    CHECK(strcmp(proto_str(FW_PROTO_UDP), "udp") == 0);
    CHECK(strcmp(proto_str(FW_PROTO_ICMP), "icmp") == 0);
    CHECK(strcmp(proto_str(47), "ip") == 0);               /* anything else */
    char b[16];
    CHECK(strcmp(ip_str(IP(10,0,1,2), b, sizeof b), "10.0.1.2") == 0);
    CHECK(strcmp(ip_str(IP(255,255,255,255), b, sizeof b), "255.255.255.255") == 0);
}

static void test_every_drop_reason_has_its_own_name(void)
{
    for (int a = 0; a < DROP_REASON_COUNT; a++) {
        const char *na = drop_reason_str((drop_reason_t)a);
        CHECK(strcmp(na, "?") != 0);                  /* a new reason needs a name */
        for (int b = a + 1; b < DROP_REASON_COUNT; b++)
            CHECK(strcmp(na, drop_reason_str((drop_reason_t)b)) != 0);
    }
    CHECK(strcmp(drop_reason_str(DROP_REASON_COUNT), "?") == 0);
}

static void test_tcp_state_names(void)
{
    const tcp_state_t all[] = { TCPS_NONE, TCPS_SYN_SENT, TCPS_SYN_RECV,
        TCPS_ESTABLISHED, TCPS_FIN_WAIT, TCPS_TIME_WAIT, TCPS_CLOSED };
    for (size_t a = 0; a < sizeof all / sizeof *all; a++) {
        CHECK(strcmp(tcp_state_str(all[a]), "?") != 0);
        for (size_t b = a + 1; b < sizeof all / sizeof *all; b++)
            CHECK(strcmp(tcp_state_str(all[a]), tcp_state_str(all[b])) != 0);
    }
    CHECK(strcmp(tcp_state_str(TCPS_ESTABLISHED), "ESTABLISHED") == 0);
    CHECK(strcmp(tcp_state_str((tcp_state_t)99), "?") == 0);
}

static void test_drop_line_format_and_level_gating(void)
{
    pkt_t p = mk_tcp(IP(198,51,100,66), 4444, IP(10,0,1,3), 22, TCP_SYN);
    FILE *log = tmpfile();

    fw_log_set(log, LOG_INFO);                 /* drops are DEBUG-only */
    log_drop(&p, DIR_OUT, DROP_NO_RULE, 2 * SEC);
    CHECK(slurp(log)[0] == '\0');
    CHECK(!fw_log_enabled(LOG_DEBUG) && fw_log_enabled(LOG_INFO));

    fw_log_set(log, LOG_DEBUG);
    CHECK(fw_log_enabled(LOG_DEBUG));
    log_drop(&p, DIR_OUT, DROP_NO_RULE, 2 * SEC);
    const char *line = slurp(log);
    CHECK(strstr(line, "DROP tcp 198.51.100.66:4444 -> 10.0.1.3:22") != NULL);
    CHECK(strstr(line, "flags=0x02") != NULL);
    CHECK(strstr(line, "on=out") != NULL);
    CHECK(strstr(line, "why=no-rule(default-deny)") != NULL);

    fw_log_set(NULL, LOG_OFF);                 /* off: nothing, no crash */
    CHECK(!fw_log_enabled(LOG_INFO));
    log_drop(&p, DIR_IN, DROP_BAD_SRC, 3 * SEC);
    log_parse_fail(PARSE_MALFORMED, DIR_IN, 5, 3 * SEC);

    fw_log_set(log, LOG_DEBUG);                /* the "in" direction too */
    rewind(log);
    log_drop(&p, DIR_IN, DROP_BAD_SRC, 3 * SEC);
    CHECK(strstr(slurp(log), "on=in") != NULL);
    fw_log_set(NULL, LOG_OFF);
    fclose(log);
}

static void test_stats_summary_lists_each_nonzero_reason(void)
{
    engine_stats_t s;
    memset(&s, 0, sizeof s);
    s.pkts_total = 10; s.pkts_allowed = 3; s.pkts_dropped = 7;
    s.fastpath = 2; s.slowpath = 8;
    s.flows_created = 4; s.flows_expired = 1; s.flows_active = 3;
    s.icmp_related = 2;
    s.drops[DROP_NO_RULE] = 4;
    s.drops[DROP_BAD_SRC] = 1;
    s.parse_fail[PARSE_BAD_CSUM] = 2;

    FILE *out = tmpfile();
    engine_stats_print(&s, out);
    const char *t = slurp(out);
    CHECK(strstr(t, "packets: total=10 allowed=3 dropped=7") != NULL);
    CHECK(strstr(t, "path:    fast=2 slow=8") != NULL);
    CHECK(strstr(t, "flows:   created=4 expired=1 active=3") != NULL);
    CHECK(strstr(t, "related-errors-allowed=2") != NULL);
    CHECK(strstr(t, "drop[no-rule(default-deny)]=4") != NULL);
    CHECK(strstr(t, "drop[bad-source-address(anti-spoof)]=1") != NULL);
    CHECK(strstr(t, "parse-fail[bad-checksum]=2") != NULL);
    CHECK(strstr(t, "drop[rule-deny]") == NULL);           /* zero: omitted */
    fclose(out);
}

int main(void)
{
    RUN(test_protocol_and_ip_names);
    RUN(test_every_drop_reason_has_its_own_name);
    RUN(test_tcp_state_names);
    RUN(test_drop_line_format_and_level_gating);
    RUN(test_stats_summary_lists_each_nonzero_reason);
    TEST_DONE();
}

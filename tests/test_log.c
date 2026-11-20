/*=============================================================================
 * File Name:   test_log.c
 * Author:      Eva Tate and Giselle Wu
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

#define SEC_NS 1000000000ull

/* The whole file (the rate-limit tests write a lot). */
static char *slurp_all(FILE *f)
{
    static char big[400000];
    rewind(f);
    size_t n = fread(big, 1, sizeof big - 1, f);
    big[n] = '\0';
    return big;
}

static char *slurp(FILE *f)
{
    static char buf[4096];
    rewind(f);
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    return buf;
}

static int count_lines(FILE *f)
{
    rewind(f);
    int n = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
    return n;
}

static void test_a_flood_of_log_lines_is_rate_limited(void)
{
    /* A scan or flood must not turn into a flood of log writes: at most
     * FW_LOG_BURST lines at once, FW_LOG_LINES_PER_SEC sustained, then one
     * summary line saying how many were dropped when logging resumes. */
    FILE *f = tmpfile();
    fw_log_set(f, LOG_DEBUG);
    pkt_t p = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    const uint64_t t0 = 5 * SEC_NS;
    for (int i = 0; i < FW_LOG_BURST + 500; i++)
        log_drop(&p, DIR_OUT, DROP_NO_RULE, t0);
    CHECK(count_lines(f) == FW_LOG_BURST);
    CHECK(fw_log_suppressed() == 500);

    /* two seconds later there is room again: a summary, then the line itself */
    log_drop(&p, DIR_OUT, DROP_NO_RULE, t0 + 2 * SEC_NS);
    CHECK(count_lines(f) == FW_LOG_BURST + 2);
    const char *out = slurp_all(f);
    const char *sum = strstr(out + strlen(out) - 400, "500 log lines suppressed");
    CHECK(sum != NULL);
    CHECK(fw_log_suppressed() == 500);                  /* running total keeps counting */
    log_drop(&p, DIR_OUT, DROP_NO_RULE, t0 + 2 * SEC_NS + 1);
    CHECK(count_lines(f) == FW_LOG_BURST + 3);          /* no second summary */
    fw_log_set(NULL, LOG_OFF);
    fclose(f);
}

static void test_every_kind_of_log_line_shares_one_budget(void)
{
    FILE *f = tmpfile();
    fw_log_set(f, LOG_DEBUG);
    pkt_t p = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    flow_t fl;
    memset(&fl, 0, sizeof fl);
    fl.key.proto = FW_PROTO_TCP;
    for (int i = 0; i < 400; i++) log_drop(&p, DIR_OUT, DROP_NO_RULE, SEC_NS);
    for (int i = 0; i < 400; i++) log_flow("NEW", &fl, SEC_NS);
    for (int i = 0; i < 400; i++) log_parse_fail(1, DIR_IN, 20, SEC_NS);
    CHECK(count_lines(f) == FW_LOG_BURST);
    CHECK(fw_log_suppressed() == 200);
    fw_log_set(NULL, LOG_OFF);
    fclose(f);
}

static void test_a_steady_rate_within_the_limit_loses_nothing(void)
{
    FILE *f = tmpfile();
    fw_log_set(f, LOG_DEBUG);
    pkt_t p = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    /* one line every 2 ms = 500 per second, for 4 seconds */
    for (int i = 0; i < 2000; i++)
        log_drop(&p, DIR_OUT, DROP_NO_RULE, SEC_NS + (uint64_t)i * 2000000ull);
    CHECK(count_lines(f) == 2000);
    CHECK(fw_log_suppressed() == 0);
    fw_log_set(NULL, LOG_OFF);
    fclose(f);
}

static void test_the_limiter_survives_the_clock_going_backwards(void)
{
    FILE *f = tmpfile();
    fw_log_set(f, LOG_DEBUG);
    pkt_t p = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    for (int i = 0; i < FW_LOG_BURST + 10; i++)
        log_drop(&p, DIR_OUT, DROP_NO_RULE, 100000 * SEC_NS);
    const int before = count_lines(f);
    log_drop(&p, DIR_OUT, DROP_NO_RULE, 1 * SEC_NS);    /* hours earlier */
    CHECK(count_lines(f) > before);                     /* logged, not silenced for hours */
    fw_log_set(NULL, LOG_OFF);
    fclose(f);
}

static void test_setting_the_log_resets_the_limiter(void)
{
    FILE *f = tmpfile();
    fw_log_set(f, LOG_DEBUG);
    pkt_t p = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    for (int i = 0; i < FW_LOG_BURST + 10; i++) log_drop(&p, DIR_OUT, DROP_NO_RULE, SEC_NS);
    CHECK(fw_log_suppressed() == 10);
    fw_log_set(f, LOG_DEBUG);
    CHECK(fw_log_suppressed() == 0);
    for (int i = 0; i < FW_LOG_BURST; i++) log_drop(&p, DIR_OUT, DROP_NO_RULE, SEC_NS);
    CHECK(fw_log_suppressed() == 0);
    fw_log_set(NULL, LOG_OFF);
    fclose(f);
}

static void test_stats_show_the_application_counts(void)
{
    engine_stats_t st;
    memset(&st, 0, sizeof st);
    FILE *f = tmpfile();
    engine_stats_print(&st, f);
    CHECK(strstr(slurp(f), "apps:    http=0 tls=0 dns=0 other=0 mismatched=0") != NULL);
    st.app_flows[APP_HTTP] = 3; st.app_flows[APP_TLS] = 2; st.app_flows[APP_DNS] = 1;
    st.app_flows[APP_OTHER] = 4; st.app_mismatch = 5;
    fclose(f);
    f = tmpfile();
    engine_stats_print(&st, f);
    CHECK(strstr(slurp(f), "apps:    http=3 tls=2 dns=1 other=4 mismatched=5\n") != NULL);
    fclose(f);
}

static void test_the_app_label_and_mismatch_note_in_a_flow_line(void)
{
    FILE *f = tmpfile();
    fw_log_set(f, LOG_INFO);
    flow_t fl;
    memset(&fl, 0, sizeof fl);
    fl.key = (flow_key_t){ IP(10,0,1,2), IP(93,184,216,34), 50000, 443, FW_PROTO_TCP };
    fl.app = APP_HTTP;                                   /* HTTP on the TLS port */
    log_flow("APP", &fl, SEC_NS);
    log_flow("NEW", &fl, SEC_NS);                        /* only the APP line carries the note */
    fl.app = APP_TLS;                                    /* TLS on the TLS port: nothing to note */
    log_flow("APP", &fl, SEC_NS);
    fl.key.dst_port = 8443; fl.app = APP_HTTP;           /* a port with no expectation */
    log_flow("APP", &fl, SEC_NS);
    fw_log_set(NULL, LOG_OFF);
    const char *out = slurp(f);
    CHECK(strstr(out, "app=http dur=1.000s pkts=0/0 bytes=0/0 mismatch(port suggests tls)\n") != NULL);
    const char *note = strstr(out, "mismatch(");
    CHECK(note != NULL && strstr(note + 1, "mismatch(") == NULL);      /* exactly one note */
    CHECK(strstr(out, "FLOW NEW    tcp 10.0.1.2:50000 -> 93.184.216.34:443 state=- rule=0 app=http") != NULL);
    CHECK(strstr(out, "app=tls dur") != NULL);
    fclose(f);
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
    RUN(test_a_flood_of_log_lines_is_rate_limited);
    RUN(test_every_kind_of_log_line_shares_one_budget);
    RUN(test_a_steady_rate_within_the_limit_loses_nothing);
    RUN(test_the_limiter_survives_the_clock_going_backwards);
    RUN(test_setting_the_log_resets_the_limiter);
    RUN(test_stats_show_the_application_counts);
    RUN(test_the_app_label_and_mismatch_note_in_a_flow_line);
    RUN(test_protocol_and_ip_names);
    RUN(test_every_drop_reason_has_its_own_name);
    RUN(test_tcp_state_names);
    RUN(test_drop_line_format_and_level_gating);
    RUN(test_stats_summary_lists_each_nonzero_reason);
    TEST_DONE();
}

#include "rules.h"
#include "testutil.h"

static rules_t *parse(const char *text)
{
    char err[128];
    rules_t *r = rules_parse_string(text, err, sizeof err);
    if (!r) fprintf(stderr, "  parse error: %s\n", err);
    return r;
}

static void test_parse_basic_and_comments(void)
{
    rules_t *r = parse(
        "# web out\n"
        "\n"
        "allow tcp from 10.0.0.0/24 to any port 80   # trailing comment\n"
        "deny any from any to any\n");
    CHECK(r && r->n == 2);
    CHECK(r->v[0].action == ACT_ALLOW);
    CHECK(r->v[0].dir == DIR_IN);              /* default direction */
    CHECK(r->v[0].proto == FW_PROTO_TCP);
    CHECK(r->v[0].line == 3);                  /* line numbers count blanks */
    CHECK(r->v[1].line == 4);
    rules_free(r);
}

static void test_first_match_wins(void)
{
    rules_t *r = parse(
        "deny  tcp from any to 93.184.216.34 port 80\n"
        "allow tcp from any to any port 80\n");
    pkt_t bad  = mk_tcp(IP(10,0,0,2), 5000, IP(93,184,216,34), 80, TCP_SYN);
    pkt_t good = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 80, TCP_SYN);
    CHECK(rules_match(r, &bad, DIR_IN)->action == ACT_DENY);
    CHECK(rules_match(r, &good, DIR_IN)->action == ACT_ALLOW);
    rules_free(r);
}

static void test_no_match_returns_null_for_default_deny(void)
{
    rules_t *r = parse("allow tcp from any to any port 80\n");
    pkt_t p = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 22, TCP_SYN);
    CHECK(rules_match(r, &p, DIR_IN) == NULL);
    rules_free(r);
    r = parse("");                              /* empty file: deny all */
    CHECK(r && rules_match(r, &p, DIR_IN) == NULL);
    rules_free(r);
}

static void test_cidr_matching(void)
{
    rules_t *r = parse("allow tcp from 10.1.2.0/24 to any\n");
    pkt_t in  = mk_tcp(IP(10,1,2,200), 1, IP(8,8,8,8), 80, TCP_SYN);
    pkt_t out = mk_tcp(IP(10,1,3,1),   1, IP(8,8,8,8), 80, TCP_SYN);
    CHECK(rules_match(r, &in, DIR_IN));
    CHECK(!rules_match(r, &out, DIR_IN));
    rules_free(r);

    r = parse("allow tcp from 10.1.2.3 to any\n");         /* bare = /32 */
    pkt_t exact = mk_tcp(IP(10,1,2,3), 1, IP(8,8,8,8), 80, TCP_SYN);
    pkt_t near  = mk_tcp(IP(10,1,2,4), 1, IP(8,8,8,8), 80, TCP_SYN);
    CHECK(rules_match(r, &exact, DIR_IN));
    CHECK(!rules_match(r, &near, DIR_IN));
    rules_free(r);

    r = parse("allow tcp from 0.0.0.0/0 to any\n");        /* /0 = anything */
    CHECK(rules_match(r, &out, DIR_IN));
    rules_free(r);
}

static void test_port_ranges(void)
{
    rules_t *r = parse("allow udp from any to any port 1000-2000\n");
    pkt_t lo = mk_udp(IP(10,0,0,2), 5, IP(8,8,8,8), 1000);
    pkt_t hi = mk_udp(IP(10,0,0,2), 5, IP(8,8,8,8), 2000);
    pkt_t no = mk_udp(IP(10,0,0,2), 5, IP(8,8,8,8), 2001);
    CHECK(rules_match(r, &lo, DIR_IN));
    CHECK(rules_match(r, &hi, DIR_IN));
    CHECK(!rules_match(r, &no, DIR_IN));
    rules_free(r);
}

static void test_source_port_match(void)
{
    rules_t *r = parse("allow udp from any port 53 to any\n");
    pkt_t a = mk_udp(IP(1,1,1,1), 53, IP(10,0,0,2), 40000);
    pkt_t b = mk_udp(IP(1,1,1,1), 54, IP(10,0,0,2), 40000);
    CHECK(rules_match(r, &a, DIR_IN));
    CHECK(!rules_match(r, &b, DIR_IN));
    rules_free(r);
}

static void test_direction_keyword(void)
{
    rules_t *r = parse("allow out tcp from any to 10.0.0.5 port 22\n");
    pkt_t p = mk_tcp(IP(8,8,8,8), 1234, IP(10,0,0,5), 22, TCP_SYN);
    CHECK(rules_match(r, &p, DIR_OUT));
    CHECK(!rules_match(r, &p, DIR_IN));
    rules_free(r);
}

static void test_protocol_any_and_icmp(void)
{
    rules_t *r = parse("allow icmp from 10.0.0.0/24 to any\n"
                       "allow any from 10.0.0.9 to any\n");
    pkt_t ping = mk_icmp(IP(10,0,0,2), IP(8,8,8,8), ICMP_ECHO_REQUEST, 7);
    pkt_t udp  = mk_udp(IP(10,0,0,9), 1, IP(8,8,8,8), 9);
    pkt_t udp2 = mk_udp(IP(10,0,0,2), 1, IP(8,8,8,8), 9);
    CHECK(rules_match(r, &ping, DIR_IN));
    CHECK(rules_match(r, &udp, DIR_IN));
    CHECK(!rules_match(r, &udp2, DIR_IN));
    rules_free(r);
}

static void expect_error(const char *text, int line)
{
    char err[128] = "";
    rules_t *r = rules_parse_string(text, err, sizeof err);
    CHECK(r == NULL);
    char want[32];
    snprintf(want, sizeof want, "line %d:", line);
    CHECK(strncmp(err, want, strlen(want)) == 0);
}

static void test_syntax_errors_report_line(void)
{
    expect_error("permit tcp from any to any\n", 1);
    expect_error("allow tcp from any to any\nallow icmp\n", 2);
    expect_error("allow sctp from any to any\n", 1);
    expect_error("allow tcp from 10.0.0.256 to any\n", 1);
    expect_error("allow tcp from 10.0.0.0/33 to any\n", 1);
    expect_error("allow tcp from any to any port 70000\n", 1);
    expect_error("allow tcp from any to any port 90-80\n", 1);
    expect_error("allow tcp from any to any port\n", 1);
    expect_error("allow tcp from any to any extra\n", 1);
    expect_error("allow tcp to any from any\n", 1);
}

static void test_load_missing_file(void)
{
    char err[128];
    CHECK(rules_load_file("/nonexistent/rules.conf", err, sizeof err) == NULL);
    CHECK(strstr(err, "cannot open") != NULL);
}

int main(void)
{
    RUN(test_parse_basic_and_comments);
    RUN(test_first_match_wins);
    RUN(test_no_match_returns_null_for_default_deny);
    RUN(test_cidr_matching);
    RUN(test_port_ranges);
    RUN(test_source_port_match);
    RUN(test_direction_keyword);
    RUN(test_protocol_any_and_icmp);
    RUN(test_syntax_errors_report_line);
    RUN(test_load_missing_file);
    TEST_DONE();
}

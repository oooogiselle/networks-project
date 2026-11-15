/*=============================================================================
 * File Name:   test_rules.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Unit tests for the rule parser and matcher: first match wins,
 *              CIDR and port edge cases, compact syntax, inside networks, and
 *              syntax errors.
 =============================================================================*/

#include <stdlib.h>
#include <unistd.h>

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
    /* "in" = inbound: the first packet arrives on tun-out. */
    rules_t *r = parse("allow in tcp from any to 10.0.0.5 port 22\n");
    pkt_t p = mk_tcp(IP(8,8,8,8), 1234, IP(10,0,0,5), 22, TCP_SYN);
    CHECK(r->v[0].dir == DIR_OUT);
    CHECK(rules_match(r, &p, DIR_OUT));
    CHECK(!rules_match(r, &p, DIR_IN));
    rules_free(r);

    /* "out" = outbound: the first packet arrives on tun-in. */
    r = parse("allow out tcp from 10.0.0.0/24 to any port 80\n");
    pkt_t q = mk_tcp(IP(10,0,0,2), 50000, IP(8,8,8,8), 80, TCP_SYN);
    CHECK(r->v[0].dir == DIR_IN);
    CHECK(rules_match(r, &q, DIR_IN));
    CHECK(!rules_match(r, &q, DIR_OUT));
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

static void test_port_lists(void)
{
    rules_t *r = parse("allow tcp from any to any port 80,443\n"
                       "allow tcp from any to any port 22,8000-8100,9000\n");
    CHECK(r && r->n == 2 && r->v[0].dport.n == 2 && r->v[1].dport.n == 3);
    pkt_t p80  = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 80, TCP_SYN);
    pkt_t p443 = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 443, TCP_SYN);
    pkt_t p81  = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 81, TCP_SYN);
    CHECK(rules_match(r, &p80, DIR_IN) == &r->v[0]);
    CHECK(rules_match(r, &p443, DIR_IN) == &r->v[0]);
    CHECK(!rules_match(r, &p81, DIR_IN));            /* between list items */
    const uint16_t second[] = {22, 8000, 8050, 8100, 9000};
    for (size_t i = 0; i < sizeof second / sizeof *second; i++) {
        pkt_t p = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), second[i], TCP_SYN);
        CHECK(rules_match(r, &p, DIR_IN) == &r->v[1]);
    }
    pkt_t out = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), 8101, TCP_SYN);
    CHECK(!rules_match(r, &out, DIR_IN));
    rules_free(r);

    /* lists work on the source side too */
    r = parse("allow udp from any port 53,5353 to any\n");
    pkt_t a = mk_udp(IP(1,1,1,1), 5353, IP(10,0,0,2), 40000);
    pkt_t b = mk_udp(IP(1,1,1,1), 5354, IP(10,0,0,2), 40000);
    CHECK(rules_match(r, &a, DIR_IN));
    CHECK(!rules_match(r, &b, DIR_IN));
    rules_free(r);

    /* a full 8-item list is fine, 9 is not */
    r = parse("allow tcp from any to any port 1,2,3,4,5,6,7,8\n");
    CHECK(r != NULL);
    rules_free(r);
}

static void test_port_list_errors(void)
{
    expect_error("allow tcp from any to any port 80,\n", 1);
    expect_error("allow tcp from any to any port ,80\n", 1);
    expect_error("allow tcp from any to any port 80,,443\n", 1);
    expect_error("allow tcp from any to any port 80,x\n", 1);
    expect_error("allow tcp from any to any port 80,70000\n", 1);
    expect_error("allow tcp from any to any port 80,90-80\n", 1);
    expect_error("allow tcp from any to any port 80, 443\n", 1);   /* space */
    expect_error("allow tcp from any to any port 1,2,3,4,5,6,7,8,9\n", 1);
}

static void test_inside_directive(void)
{
    rules_t *r = parse("# trusted\n"
                       "inside 10.0.1.0/24\n"
                       "allow tcp from 10.0.1.0/24 to any port 80\n"
                       "inside 192.168.5.7\n");
    CHECK(r && r->n == 1 && r->ninside == 2);
    CHECK(r->v[0].line == 3);                 /* line numbers unaffected */
    CHECK(rules_is_inside(r, IP(10,0,1,200)));
    CHECK(rules_is_inside(r, IP(192,168,5,7)));
    CHECK(!rules_is_inside(r, IP(192,168,5,8)));
    CHECK(!rules_is_inside(r, IP(10,0,2,1)));
    rules_free(r);

    r = parse("allow tcp from any to any port 80\n");
    CHECK(r && r->ninside == 0);              /* none declared: check is off */
    rules_free(r);
}

static void test_inside_errors(void)
{
    expect_error("inside\n", 1);
    expect_error("inside any\n", 1);
    expect_error("inside 10.0.0.0/33\n", 1);
    expect_error("inside 10.0.0.0/24 extra\n", 1);
    expect_error("allow icmp from any to any\ninside bogus\n", 2);
    expect_error("inside 10.0.0.0/24\ninside 10.0.1.0/24\ninside 10.0.2.0/24\n"
                 "inside 10.0.3.0/24\ninside 10.0.4.0/24\ninside 10.0.5.0/24\n"
                 "inside 10.0.6.0/24\ninside 10.0.7.0/24\ninside 10.0.8.0/24\n", 9);
}

static void test_compact_syntax_matches_spec_example(void)
{
    /* the example rule file from the requirements spec, verbatim */
    rules_t *r = parse(
        "# action dir proto src dst ports\n"
        "allow out tcp 10.0.1.0/24 any 80,443\n"
        "allow out udp 10.0.1.0/24 any 53\n"
        "allow out icmp 10.0.1.0/24 any echo\n"
        "allow in tcp any 10.0.1.3 22\n"
        "# anything not matched is denied\n");
    CHECK(r && r->n == 4);
    CHECK(r->v[0].dir == DIR_IN && r->v[3].dir == DIR_OUT);

    pkt_t web = mk_tcp(IP(10,0,1,2), 40000, IP(93,184,216,34), 443, TCP_SYN);
    pkt_t odd = mk_tcp(IP(10,0,1,2), 40000, IP(93,184,216,34), 8080, TCP_SYN);
    pkt_t dns = mk_udp(IP(10,0,1,2), 40000, IP(10,0,2,2), 53);
    pkt_t png = mk_icmp(IP(10,0,1,2), IP(8,8,8,8), ICMP_ECHO_REQUEST, 7);
    pkt_t ssh = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 22, TCP_SYN);
    pkt_t rdp = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    CHECK(rules_match(r, &web, DIR_IN) == &r->v[0]);
    CHECK(!rules_match(r, &odd, DIR_IN));
    CHECK(rules_match(r, &dns, DIR_IN) == &r->v[1]);
    CHECK(rules_match(r, &png, DIR_IN) == &r->v[2]);
    CHECK(rules_match(r, &ssh, DIR_OUT) == &r->v[3]);
    CHECK(!rules_match(r, &rdp, DIR_OUT));         /* default deny */
    CHECK(!rules_match(r, &ssh, DIR_IN));          /* wrong direction */
    rules_free(r);
}

static void test_compact_defaults_and_equivalence(void)
{
    /* direction is optional (default out); ports optional / `any` = all */
    rules_t *c = parse("allow tcp 10.0.0.0/24 any\n"
                       "deny  udp any 8.8.8.8 any\n"
                       "allow in any any 10.0.1.3\n");
    CHECK(c && c->n == 3);
    CHECK(c->v[0].dir == DIR_IN && c->v[0].dport.n == 1 &&
          c->v[0].dport.r[0].lo == 0 && c->v[0].dport.r[0].hi == 65535);
    CHECK(c->v[1].action == ACT_DENY);
    CHECK(c->v[2].dir == DIR_OUT && c->v[2].proto == 0);

    /* the same policy written both ways behaves identically */
    rules_t *v = parse("allow tcp from 10.0.0.0/24 to any port 80,8000-8100\n");
    rules_t *k = parse("allow tcp 10.0.0.0/24 any 80,8000-8100\n");
    const uint16_t ports[] = {79, 80, 81, 8000, 8100, 8101};
    for (size_t i = 0; i < sizeof ports / sizeof *ports; i++) {
        pkt_t p = mk_tcp(IP(10,0,0,2), 5000, IP(8,8,8,8), ports[i], TCP_SYN);
        CHECK((rules_match(v, &p, DIR_IN) != NULL) ==
              (rules_match(k, &p, DIR_IN) != NULL));
    }
    /* and the two forms can be mixed in one file */
    rules_t *m = parse("allow tcp from any to any port 22\n"
                       "allow tcp 10.0.0.0/24 any 80\n");
    CHECK(m && m->n == 2);
    rules_free(c); rules_free(v); rules_free(k); rules_free(m);
}

static void test_compact_syntax_errors(void)
{
    expect_error("allow tcp 10.0.0.0/24\n", 1);                  /* no dst */
    expect_error("allow tcp bogus any 80\n", 1);
    expect_error("allow tcp 10.0.0.0/24 bogus 80\n", 1);
    expect_error("allow tcp 10.0.0.0/24 any 70000\n", 1);
    expect_error("allow tcp 10.0.0.0/24 any 80, 443\n", 1);      /* space */
    expect_error("allow tcp 10.0.0.0/24 any 80 extra\n", 1);
    expect_error("allow tcp 10.0.0.0/24 any echo\n", 1);         /* echo: icmp only */
    expect_error("allow udp 10.0.0.0/24 any echo\n", 1);
    expect_error("allow icmp 10.0.0.0/24 any 80\n", 1);          /* icmp: no ports */
    expect_error("allow icmp 10.0.0.0/24 any echo extra\n", 1);
    expect_error("allow out\n", 1);
    expect_error("allow tcp 10.0.0.0/24 any 80\nallow in tcp any\n", 2);
}

static void test_shipped_example_config_loads(void)
{
    /* run from the repo root by `make test` */
    char err[128] = "";
    rules_t *r = rules_load_file("config/rules.example.conf", err, sizeof err);
    if (!r) fprintf(stderr, "  %s\n", err);
    CHECK(r != NULL);
    if (!r) return;
    CHECK(r->n == 5 && r->ninside == 1);
    pkt_t web = mk_tcp(IP(10,0,1,2), 40000, IP(93,184,216,34), 443, TCP_SYN);
    pkt_t ssh = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 22, TCP_SYN);
    pkt_t rdp = mk_tcp(IP(10,0,2,3), 4444, IP(10,0,1,3), 3389, TCP_SYN);
    pkt_t rogue = mk_udp(IP(10,0,1,2), 40000, IP(8,8,8,8), 53);
    CHECK(rules_match(r, &web, DIR_IN) && rules_match(r, &web, DIR_IN)->action == ACT_ALLOW);
    CHECK(rules_match(r, &ssh, DIR_OUT) && rules_match(r, &ssh, DIR_OUT)->action == ACT_ALLOW);
    CHECK(!rules_match(r, &rdp, DIR_OUT));
    CHECK(rules_match(r, &rogue, DIR_IN) && rules_match(r, &rogue, DIR_IN)->action == ACT_DENY);
    rules_free(r);
}

static void test_load_directory_is_an_error_not_an_empty_ruleset(void)
{
    /* fopen() succeeds on a directory and fread() then fails: that must not
     * look like an empty (deny-all, spoof-check-less) rules file. */
    char err[128] = "";
    CHECK(rules_load_file("/tmp", err, sizeof err) == NULL);
    CHECK(strstr(err, "error reading") != NULL);
}

static void test_load_file_with_nul_byte_is_an_error(void)
{
    /* A NUL would silently cut the file there, dropping every later line
     * (including `inside` and deny rules). */
    char path[512];
    const char *dir = getenv("TMPDIR");
    snprintf(path, sizeof path, "%s/fw_rules_nul_XXXXXX", dir && *dir ? dir : "/tmp");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    const char text[] = "allow out tcp any any 80\n\0deny out tcp any any 22\ngarbage\n";
    CHECK(write(fd, text, sizeof text - 1) == (ssize_t)(sizeof text - 1));
    close(fd);
    char err[128] = "";
    CHECK(rules_load_file(path, err, sizeof err) == NULL);
    CHECK(strstr(err, "NUL") != NULL);
    unlink(path);
}

static bool parse_fails_with(const char *text, const char *line_prefix, const char *msg)
{
    char err[128] = "";
    rules_t *r = rules_parse_string(text, err, sizeof err);
    if (r) { rules_free(r); return false; }
    return strncmp(err, line_prefix, strlen(line_prefix)) == 0 && strstr(err, msg) != NULL;
}

static void test_ports_only_allowed_on_tcp_and_udp_rules(void)
{
    /* ICMP has no ports and an `any` rule would apply them to TCP/UDP only,
     * silently opening ICMP too. Refuse such rules instead of widening them. */
    const char *m = "only valid for tcp and udp";
    /* compact form */
    CHECK(parse_fails_with("allow out any 10.0.1.0/24 any 80\n", "line 1:", m));
    CHECK(parse_fails_with("deny in any any 10.0.1.3 22,8000-8100\n", "line 1:", m));
    CHECK(parse_fails_with("# c\n\nallow out any any any 443\n", "line 3:", m));
    /* verbose form: a `port` clause on either side */
    CHECK(parse_fails_with("allow icmp from any to any port 80\n", "line 1:", m));
    CHECK(parse_fails_with("allow any from any to any port 22\n", "line 1:", m));
    CHECK(parse_fails_with("allow any from any port 53 to any\n", "line 1:", m));
    CHECK(parse_fails_with("allow icmp from any port 8 to any\n", "line 1:", m));
    /* the existing icmp compact message still applies */
    CHECK(parse_fails_with("allow out icmp any any 80\n", "line 1:", "echo"));

    /* everything that does not use a port is still fine on any/icmp ... */
    rules_t *r = parse("allow out any 10.0.0.0/24 any\n"
                       "allow out any 10.0.0.0/24 any any\n"
                       "allow any from any to any\n"
                       "allow icmp from any to any\n"
                       "allow out icmp 10.0.0.0/24 any echo\n");
    CHECK(r != NULL && r->n == 5);
    rules_free(r);
    /* ... and ports are still fine on tcp and udp, both forms */
    r = parse("allow out tcp 10.0.0.0/24 any 80,443\n"
              "allow out udp 10.0.0.0/24 any 53\n"
              "allow tcp from any port 1024-65535 to any port 80\n"
              "allow udp from any to any port 53\n");
    CHECK(r != NULL && r->n == 4);
    rules_free(r);
}

static void test_port_and_token_limits_are_enforced(void)
{
    CHECK(parse_fails_with("allow out tcp any any 65536\n", "line 1:", "port"));     /* 16-bit */
    CHECK(parse_fails_with("allow out tcp any any 99999\n", "line 1:", "port"));
    rules_t *r = parse("allow out tcp any any 65535\nallow out tcp any any 1-65535\n");
    CHECK(r != NULL && r->n == 2);
    rules_free(r);
    /* a line of 16 tokens is the most allowed; a 17th is refused */
    CHECK(parse_fails_with("allow tcp from any to any port 80 a b c d e f g h i\n", "line 1:", "too many tokens"));
    r = parse("allow tcp from any to any port 80\n");                       /* 8 tokens: fine */
    CHECK(r != NULL);
    rules_free(r);
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
    RUN(test_port_lists);
    RUN(test_port_list_errors);
    RUN(test_inside_directive);
    RUN(test_inside_errors);
    RUN(test_compact_syntax_matches_spec_example);
    RUN(test_compact_defaults_and_equivalence);
    RUN(test_compact_syntax_errors);
    RUN(test_shipped_example_config_loads);
    RUN(test_load_missing_file);
    RUN(test_port_and_token_limits_are_enforced);
    RUN(test_ports_only_allowed_on_tcp_and_udp_rules);
    RUN(test_load_directory_is_an_error_not_an_empty_ruleset);
    RUN(test_load_file_with_nul_byte_is_an_error);
    TEST_DONE();
}

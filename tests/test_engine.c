/* End-to-end decision tests: the walkthroughs from the project proposal. */
#include "engine.h"
#include "rules.h"
#include "testutil.h"

#define CLIENT_A IP(10,0,0,2)
#define CLIENT_B IP(10,0,0,3)
#define SERVER   IP(93,184,216,34)
#define ATTACKER IP(198,51,100,66)

static const char *RULES =
    "allow tcp from 10.0.0.0/24 to any port 80\n"
    "allow tcp from 10.0.0.0/24 to any port 443\n"
    "allow udp from 10.0.0.0/24 to any port 53\n"
    "allow icmp from 10.0.0.0/24 to any\n";

static engine_t *make_engine(const char *rules)
{
    char err[128];
    rules_t *r = rules_parse_string(rules, err, sizeof err);
    return engine_create_with_rules(r);
}

static verdict_t send_pkt(engine_t *e, pkt_t p, dir_t d, uint64_t t,
                          drop_reason_t *why)
{
    return engine_decide(e, &p, d, t, why);
}

static void test_web_fetch_allowed(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    uint64_t t = SEC;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, t+1, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, t+2, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK|TCP_PSH), DIR_IN, t+3, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK|TCP_PSH), DIR_OUT, t+4, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN|TCP_ACK), DIR_OUT, t+5, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN|TCP_ACK), DIR_IN, t+6, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t+7, &w) == VERDICT_ALLOW);

    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.slowpath == 1);            /* only the SYN evaluated rules */
    CHECK(s.fastpath == 7);
    CHECK(s.flows_created == 1);
    CHECK(s.pkts_dropped == 0);
    engine_destroy(e);
}

static void test_unsolicited_inbound_syn_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NO_RULE);
    engine_destroy(e);
}

static void test_inbound_allowed_only_to_exposed_service(void)
{
    engine_t *e = make_engine("allow out tcp from any to 10.0.0.3 port 22\n");
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_B, 23, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_A, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_outbound_to_disallowed_port_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 22, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NO_RULE);
    engine_destroy(e);
}

static void test_explicit_deny_reported(void)
{
    engine_t *e = make_engine("deny tcp from any to any port 80\nallow tcp from any to any\n");
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_RULE_DENY);
    engine_destroy(e);
}

static void test_nmap_style_scans_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    int allowed = 0;
    for (uint16_t port = 1; port <= 1024; port++) {                 /* SYN scan */
        allowed += send_pkt(e, mk_tcp(ATTACKER, 40000, CLIENT_B, port, TCP_SYN), DIR_OUT, SEC, &w);
    }
    uint8_t odd[] = { 0, TCP_FIN, TCP_FIN|TCP_PSH|TCP_URG, TCP_ACK, TCP_SYN|TCP_ACK, TCP_RST };
    for (size_t i = 0; i < sizeof odd; i++)                         /* null/FIN/Xmas/ACK */
        allowed += send_pkt(e, mk_tcp(ATTACKER, 40001, CLIENT_B, 80, odd[i]), DIR_OUT, SEC, &w);
    CHECK(allowed == 0);
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.flows_created == 0);       /* scans never allocate state */
    CHECK(s.flows_active == 0);
    engine_destroy(e);
}

static void test_tcp_reply_without_flow_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NOT_SYN);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_inbound_data_before_handshake_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    /* attacker guesses the tuple and injects data before any SYN-ACK */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK|TCP_PSH), DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_TCP_STATE);
    engine_destroy(e);
}

static void test_spoofed_direction_dropped(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    /* same tuple as the inside client's packets, but arriving from outside */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_SPOOF);
    /* and the server's reply tuple arriving from inside */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_IN, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_SPOOF);
    engine_destroy(e);
}

static void test_half_open_flow_expires(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    /* SYN-ACK arrives long after the 30s SYN timeout */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, 100*SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_established_flow_idle_timeout_and_refresh(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    uint64_t t = SEC;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, t, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, t, &w);
    /* traffic every 200s keeps it alive well beyond a single timeout */
    for (int i = 1; i <= 5; i++)
        CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t + i*200*SEC, &w) == VERDICT_ALLOW);
    /* but silence for 10 minutes does not */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t + 1700*SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_sweep_expires_flows(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    for (uint16_t i = 0; i < 10; i++)
        send_pkt(e, mk_tcp(CLIENT_A, 50000 + i, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    CHECK(engine_expire(e, 10*SEC) == 0);
    CHECK(engine_expire(e, 100*SEC) == 10);
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.flows_active == 0);
    CHECK(s.flows_expired == 10);
    engine_destroy(e);
}

static void test_port_reuse_after_close(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    uint64_t t = SEC;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST|TCP_ACK), DIR_OUT, t+1, &w);
    /* same 5-tuple, new connection */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t+2, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, t+3, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_udp_pseudo_flow(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    uint32_t dns = IP(8,8,8,8);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 5353, dns, 53), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(dns, 53, CLIENT_A, 5353), DIR_OUT, SEC+1, &w) == VERDICT_ALLOW);
    /* unsolicited UDP from the same server to a different client port */
    CHECK(send_pkt(e, mk_udp(dns, 53, CLIENT_A, 5354), DIR_OUT, SEC+2, &w) == VERDICT_DROP);
    /* reply after the 30s one-way timeout (none seen yet) is dropped */
    send_pkt(e, mk_udp(CLIENT_A, 6000, dns, 53), DIR_IN, 10*SEC, &w);
    CHECK(send_pkt(e, mk_udp(dns, 53, CLIENT_A, 6000), DIR_OUT, 60*SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_icmp_echo(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 77), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REPLY, 77), DIR_OUT, SEC+1, &w) == VERDICT_ALLOW);
    /* wrong identifier => not our ping */
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REPLY, 78), DIR_OUT, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_NO_FLOW);
    /* outside ping of an inside host: no rule */
    CHECK(send_pkt(e, mk_icmp(ATTACKER, CLIENT_B, ICMP_ECHO_REQUEST, 1), DIR_OUT, SEC+3, &w) == VERDICT_DROP);
    /* other ICMP types are not tracked */
    CHECK(send_pkt(e, mk_icmp(ATTACKER, CLIENT_B, 3, 1), DIR_OUT, SEC+4, &w) == VERDICT_DROP);
    CHECK(w == DROP_UNSUPPORTED);
    engine_destroy(e);
}

static void test_unknown_protocol_dropped(void)
{
    engine_t *e = make_engine("allow any from any to any\n");
    drop_reason_t w;
    pkt_t p = mk_udp(CLIENT_A, 1, SERVER, 1);
    p.proto = 47;   /* GRE */
    CHECK(send_pkt(e, p, DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_UNSUPPORTED);
    engine_destroy(e);
}

static void test_stats_add_up(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    send_pkt(e, mk_tcp(ATTACKER, 1, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w);
    send_pkt(e, mk_tcp(ATTACKER, 1, CLIENT_B, 23, TCP_SYN), DIR_OUT, SEC, &w);
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.pkts_total == 3);
    CHECK(s.pkts_allowed == 1);
    CHECK(s.pkts_dropped == 2);
    CHECK(s.drops[DROP_NO_RULE] == 2);
    CHECK(s.pkts_allowed + s.pkts_dropped == s.pkts_total);
    engine_destroy(e);
}

int main(void)
{
    RUN(test_web_fetch_allowed);
    RUN(test_unsolicited_inbound_syn_dropped);
    RUN(test_inbound_allowed_only_to_exposed_service);
    RUN(test_outbound_to_disallowed_port_dropped);
    RUN(test_explicit_deny_reported);
    RUN(test_nmap_style_scans_dropped);
    RUN(test_tcp_reply_without_flow_dropped);
    RUN(test_inbound_data_before_handshake_dropped);
    RUN(test_spoofed_direction_dropped);
    RUN(test_half_open_flow_expires);
    RUN(test_established_flow_idle_timeout_and_refresh);
    RUN(test_sweep_expires_flows);
    RUN(test_port_reuse_after_close);
    RUN(test_udp_pseudo_flow);
    RUN(test_icmp_echo);
    RUN(test_unknown_protocol_dropped);
    RUN(test_stats_add_up);
    TEST_DONE();
}

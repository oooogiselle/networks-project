/*=============================================================================
 * File Name:   test_engine.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: End-to-end tests for the decision engine: the allowed and denied
 *              walkthroughs, ICMP errors, anti-spoofing, parse-failure stats,
 *              table capacity, and log output.
 =============================================================================*/

/* End-to-end decision tests: the walkthroughs from the project proposal. */
#include <stdlib.h>
#include <unistd.h>

#include "engine.h"
#include "log.h"
#include "parser.h"
#include "pktbuild.h"
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

/* The engine requires an `inside` network (anti-spoofing is not optional), so
 * fixtures get one unless they declare their own. Clients are 10.0.0.0/24. */
static char *with_inside(const char *rules)
{
    static char buf[2048];
    snprintf(buf, sizeof buf, "%s%s", strstr(rules, "inside ") ? "" : "inside 10.0.0.0/24\n", rules);
    return buf;
}

static engine_t *make_engine(const char *rules)
{
    char err[128];
    rules_t *r = rules_parse_string(with_inside(rules), err, sizeof err);
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
    engine_t *e = make_engine("allow in tcp from any to 10.0.0.3 port 22\n");
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
    /* same tuple as the inside client's packets, but arriving from outside:
     * the address check catches it first (an inside source on the outside) */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    /* and the server's reply tuple arriving from inside */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_IN, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
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
    /* established connections idle for just under an hour survive (and the
     * timer restarts)... */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t + 1000*SEC + 3599*SEC, &w) == VERDICT_ALLOW);
    /* ...but an hour of silence ends them */
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t + 4599*SEC + 3600*SEC, &w) == VERDICT_DROP);
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
    /* ICMP types we don't track at all (5 = redirect) */
    CHECK(send_pkt(e, mk_icmp(ATTACKER, CLIENT_B, 5, 1), DIR_OUT, SEC+4, &w) == VERDICT_DROP);
    CHECK(w == DROP_UNSUPPORTED);
    /* an ICMP error with no embedded packet is not related to anything */
    CHECK(send_pkt(e, mk_icmp(ATTACKER, CLIENT_B, ICMP_DEST_UNREACH, 1), DIR_OUT, SEC+5, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);
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

/* ---- ICMP errors, anti-spoofing, parse failures ------------------------- */

#define ROUTER_OUT IP(203,0,113,1)     /* a router on the outside path */

static const char *RULES_IN =
    "inside 10.0.0.0/24\n"
    "allow tcp from 10.0.0.0/24 to any port 80\n"
    "allow udp from 10.0.0.0/24 to any port 53\n"
    "allow icmp from 10.0.0.0/24 to any\n"
    "allow in tcp from any to 10.0.0.3 port 22\n";

/* Parse a wire packet; it must be valid. */
static pkt_t parsed(const uint8_t *buf, size_t len)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    CHECK(parse_packet(buf, len, &p) == PARSE_OK);
    return p;
}

/*
 * A real wire-format ICMP error from `from` to `to`, embedding the first
 * 28 bytes (IP header + 8) of the packet in orig, as routers do. The result
 * points into errbuf, which must outlive it.
 */
static pkt_t icmp_error(uint8_t *errbuf, uint32_t from, uint32_t to,
                        uint8_t type, const uint8_t *orig)
{
    size_t n = pb_icmp_error(errbuf, 256, NULL, from, to, type, 0, orig, 28);
    CHECK(n > 0);
    return parsed(errbuf, n);
}

static void test_icmp_error_for_outbound_tcp_allowed(void)
{
    /* traceroute / PMTU: a router returns "time exceeded" or "frag needed"
     * about the client's own SYN. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);

    pkt_t te = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, syn);
    CHECK(send_pkt(e, te, DIR_OUT, SEC+1, &w) == VERDICT_ALLOW);
    CHECK(w == DROP_NONE);
    pkt_t du = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, du, DIR_OUT, SEC+2, &w) == VERDICT_ALLOW);

    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.icmp_related == 2);
    CHECK(s.flows_created == 1 && s.flows_active == 1);   /* no new flow */
    engine_destroy(e);
}

static void test_icmp_error_after_reply_direction(void)
{
    /* Inbound-initiated flow (exposed ssh). An outside router reports a
     * problem with the inside host's REPLY: the embedded packet is the
     * responder's, and the error still travels toward the inside. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t synack[128], err[256];
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 1234, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    size_t n = pb_tcp(synack, sizeof synack, NULL, CLIENT_B, 22, ATTACKER, 1234,
                      TCP_SYN|TCP_ACK, NULL, 0);
    CHECK(send_pkt(e, parsed(synack, n), DIR_IN, SEC+1, &w) == VERDICT_ALLOW);

    pkt_t te = icmp_error(err, ROUTER_OUT, CLIENT_B, ICMP_DEST_UNREACH, synack);
    CHECK(send_pkt(e, te, DIR_OUT, SEC+2, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_icmp_error_unrelated_dropped(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t orig[128], err[256];
    /* embeds a packet from CLIENT_B that was never sent */
    size_t n = pb_tcp(orig, sizeof orig, NULL, CLIENT_B, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    (void)n;
    pkt_t bad = icmp_error(err, ATTACKER, CLIENT_B, ICMP_DEST_UNREACH, orig);
    CHECK(send_pkt(e, bad, DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);

    /* same tuple but a different port than the real flow */
    uint8_t syn[128], other[128];
    n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    pb_tcp(other, sizeof other, NULL, CLIENT_A, 50001, SERVER, 80, TCP_SYN, NULL, 0);
    pkt_t bad2 = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, other);
    CHECK(send_pkt(e, bad2, DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);

    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.icmp_related == 0);
    CHECK(s.drops[DROP_ICMP_ERR] == 2);
    engine_destroy(e);
}

static void test_icmp_error_wrong_direction_dropped(void)
{
    /* An inside host forging an "error" about its own outbound flow: the
     * error arrives from the same side the embedded packet was sent from. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    pkt_t forged = icmp_error(err, CLIENT_B, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, forged, DIR_IN, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_SPOOF);
    engine_destroy(e);
}

static void test_icmp_echo_type_must_match_direction(void)
{
    /* On an existing echo flow the originator may only send requests and the
     * peer may only send replies. Otherwise a host that spoofs the peer could
     * send echo REQUESTS inward with no `allow in icmp` rule. */
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 7), DIR_IN, SEC, &w) == VERDICT_ALLOW);

    /* request travelling inward on the flow's own tuple */
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REQUEST, 7), DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_TYPE);
    /* reply "from the originator" outward */
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, ICMP_ECHO_REPLY, 7), DIR_IN, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_TYPE);
    /* any other ICMP type on the tuple, either way */
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, 13, 7), DIR_OUT, SEC+3, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_TYPE);
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, 13, 7), DIR_IN, SEC+4, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_TYPE);

    /* the legitimate request/reply pairs (ping repeats the id) still work */
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 7), DIR_IN, SEC+5, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REPLY, 7), DIR_OUT, SEC+6, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_icmp_rejected_packets_do_not_refresh_flow(void)
{
    /* Wrong-type packets must not extend the flow's life (they used to). */
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 9), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    for (int i = 1; i <= 5; i++)       /* one every 20 s: would keep it alive */
        CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REQUEST, 9), DIR_OUT,
                       SEC + (uint64_t)i * 20 * SEC, &w) == VERDICT_DROP);
    /* original flow expired 30 s after its only accepted packet */
    CHECK(send_pkt(e, mk_icmp(SERVER, CLIENT_A, ICMP_ECHO_REPLY, 9), DIR_OUT, 101 * SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NO_FLOW);
    engine_destroy(e);
}

static void test_icmp_error_must_be_addressed_to_the_embedded_senders(void)
{
    /* An error about a packet from A is sent TO A. One addressed to anyone
     * else cannot be a genuine error about that packet. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);

    pkt_t to_b = icmp_error(err, ROUTER_OUT, CLIENT_B, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, to_b, DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);
    pkt_t to_attacker = icmp_error(err, ROUTER_OUT, ATTACKER, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, to_attacker, DIR_OUT, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);

    pkt_t to_a = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, to_a, DIR_OUT, SEC+3, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_icmp_errors_only_for_active_tcp_flows(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, 2*SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, 3*SEC, &w) == VERDICT_ALLOW);

    pkt_t live = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, live, DIR_OUT, 4*SEC, &w) == VERDICT_ALLOW);      /* established */

    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, 5*SEC, &w) == VERDICT_ALLOW);
    pkt_t dead = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, dead, DIR_OUT, 6*SEC, &w) == VERDICT_DROP);       /* CLOSED */
    CHECK(w == DROP_ICMP_ERR);
    engine_destroy(e);
}

static void test_icmp_errors_are_rate_limited_per_flow(void)
{
    /* A forger who knows a flow's tuple must not be able to pour errors into
     * it at wire speed. Budget: ICMP_ERRORS_PER_FLOW_PER_SEC per flow. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn1[128], syn2[128], err[256];
    size_t n1 = pb_tcp(syn1, sizeof syn1, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    size_t n2 = pb_tcp(syn2, sizeof syn2, NULL, CLIENT_A, 50001, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn1, n1), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, parsed(syn2, n2), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    pkt_t err1 = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, syn1);

    const uint64_t MS = SEC / 1000;
    for (int i = 0; i < ICMP_ERRORS_PER_FLOW_PER_SEC; i++)
        CHECK(send_pkt(e, err1, DIR_OUT, 2*SEC + (uint64_t)i * MS, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, err1, DIR_OUT, 2*SEC + 500*MS, &w) == VERDICT_DROP);   /* over budget */
    CHECK(w == DROP_ICMP_RATE);
    CHECK(send_pkt(e, err1, DIR_OUT, 2*SEC + 999*MS, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_RATE);

    /* another flow has its own budget */
    pkt_t err2 = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, syn2);
    CHECK(send_pkt(e, err2, DIR_OUT, 2*SEC + 600*MS, &w) == VERDICT_ALLOW);
    /* the window rolls over after a second */
    pkt_t again = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, syn1);
    CHECK(send_pkt(e, again, DIR_OUT, 3*SEC + 1*MS, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_icmp_error_about_echo(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t ping[128], other[128], err[256];
    size_t n = pb_icmp_echo(ping, sizeof ping, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 77, 1, NULL, 0);
    CHECK(send_pkt(e, parsed(ping, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);

    pkt_t ok = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, ping);
    CHECK(send_pkt(e, ok, DIR_OUT, SEC+1, &w) == VERDICT_ALLOW);

    pb_icmp_echo(other, sizeof other, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 78, 1, NULL, 0);
    pkt_t bad = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, other);
    CHECK(send_pkt(e, bad, DIR_OUT, SEC+2, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);
    engine_destroy(e);
}

static void test_icmp_error_does_not_refresh_flow(void)
{
    /* Errors must not keep a flow alive: the UDP one-way timeout is 30 s. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t dgram[128], err[256];
    size_t n = pb_udp(dgram, sizeof dgram, NULL, CLIENT_A, 6000, SERVER, 53, "x", 1);
    CHECK(send_pkt(e, parsed(dgram, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    pkt_t er = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, dgram);
    CHECK(send_pkt(e, er, DIR_OUT, 29*SEC, &w) == VERDICT_ALLOW);
    CHECK(engine_expire(e, 40*SEC) == 1);
    engine_destroy(e);
}

static void test_icmp_error_never_matches_echo_id_zero(void)
{
    /* An error's own tuple is (ip, ip, 0, 0, icmp), which equals the key of
     * an echo flow with identifier 0. It must not be treated as one. */
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_icmp(CLIENT_A, ROUTER_OUT, ICMP_ECHO_REQUEST, 0), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    uint8_t orig[128], err[256];
    pb_tcp(orig, sizeof orig, NULL, CLIENT_A, 50000, ROUTER_OUT, 80, TCP_SYN, NULL, 0);
    pkt_t bad = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, orig);
    CHECK(send_pkt(e, bad, DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_ICMP_ERR);
    engine_destroy(e);
}

static void test_antispoof_outside_claiming_inside_address(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    /* attacker claims to be an inside host, aiming at the exposed ssh */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 53, CLIENT_B, 5000), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    /* ...and the same against an established flow (injection) */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_RST), DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    /* the genuine outside host is still fine */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC+2, &w) == VERDICT_ALLOW);

    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.drops[DROP_BAD_SRC] == 3);
    CHECK(s.flows_created == 2);              /* spoofed packets made none */
    engine_destroy(e);
}

static void test_antispoof_inside_with_foreign_address(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    /* an inside host using a source address that is not inside: would
     * otherwise pass the "any destination" rules */
    CHECK(send_pkt(e, mk_tcp(IP(8,8,8,8), 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_antispoof_covers_icmp_errors(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    /* error from the outside, but with an inside source address */
    pkt_t forged = icmp_error(err, CLIENT_B, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, forged, DIR_OUT, SEC+1, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);
    engine_destroy(e);
}

static void test_engine_refuses_rules_without_an_inside_network(void)
{
    /* Anti-spoofing is a requirement, not an option: with no `inside` network
     * there is no way to tell a spoofed source from a real one, so the engine
     * must not start rather than quietly run without the check. */
    char err[128];
    rules_t *r = rules_parse_string(RULES, err, sizeof err);      /* no inside */
    CHECK(r != NULL && r->ninside == 0);
    CHECK(engine_create_with_rules(r) == NULL);                   /* frees r */
    r = rules_parse_string(RULES, err, sizeof err);
    CHECK(engine_create_with_rules_sized(r, 16) == NULL);
    engine_t *e = make_engine(RULES);                             /* with one: fine */
    CHECK(e != NULL);
    engine_destroy(e);
}

static void test_parse_failures_counted_and_logged(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);

    /* a real corrupted packet, through the real parser */
    uint8_t buf[128];
    size_t n = pb_tcp(buf, sizeof buf, NULL, ATTACKER, 1, CLIENT_B, 22, TCP_SYN, NULL, 0);
    buf[n - 1] ^= 0xff;
    pkt_t scratch;
    parse_result_t pr = parse_packet(buf, n, &scratch);
    CHECK(pr != PARSE_OK);

    FILE *log = tmpfile();
    CHECK(log != NULL);
    fw_log_set(log, LOG_DEBUG);
    engine_parse_failed(e, pr, DIR_OUT, n, SEC + 1);
    engine_parse_failed(e, PARSE_MALFORMED, DIR_OUT, 7, SEC + 2);
    engine_parse_failed(e, PARSE_MALFORMED, DIR_IN, 9, SEC + 3);
    engine_parse_failed(e, PARSE_FRAGMENT, DIR_OUT, 60, SEC + 4);
    engine_parse_failed(e, PARSE_OK, DIR_OUT, 60, SEC + 5);            /* ignored */
    engine_parse_failed(e, PARSE_RESULT_COUNT, DIR_OUT, 60, SEC + 6);  /* ignored */
    fw_log_set(NULL, LOG_OFF);

    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.parse_fail[pr] == 1);
    CHECK(s.parse_fail[PARSE_MALFORMED] == 2);
    CHECK(s.parse_fail[PARSE_FRAGMENT] == 1);
    CHECK(s.pkts_total == 5 && s.pkts_dropped == 4 && s.pkts_allowed == 1);
    CHECK(s.pkts_allowed + s.pkts_dropped == s.pkts_total);

    char line[256] = "";
    rewind(log);
    int lines = 0, found = 0;
    while (fgets(line, sizeof line, log)) {
        lines++;
        if (strstr(line, "unparsable len=7 on=out why=malformed")) found = 1;
    }
    CHECK(lines == 4 && found);
    fclose(log);

    /* the summary shows them next to the engine's drop reasons */
    FILE *out = tmpfile();
    engine_stats_print(&s, out);
    rewind(out);
    char all[1024] = "";
    size_t got = fread(all, 1, sizeof all - 1, out);
    all[got] = '\0';
    CHECK(strstr(all, "parse-fail[malformed]=2") != NULL);
    CHECK(strstr(all, "parse-fail[fragment]=1") != NULL);
    fclose(out);
    engine_destroy(e);
}

/* ---- table capacity and flow log lines ---------------------------------- */

static rules_t *rules_of(const char *text)
{
    char err[128];
    return rules_parse_string(with_inside(text), err, sizeof err);
}

static void test_default_capacity_is_65536_and_full_table_keeps_flows(void)
{
    CHECK(FW_DEFAULT_MAX_FLOWS == 65536u);
    engine_t *e = engine_create_with_rules(rules_of("allow udp any any\n"));
    CHECK(engine_set_limits(e, 0, 0));      /* this test is about raw capacity, not the caps */
    drop_reason_t w;
    /* fill the table with distinct UDP flows (client port x server port) */
    for (uint32_t i = 0; i < FW_DEFAULT_MAX_FLOWS; i++) {
        pkt_t p = mk_udp(CLIENT_A, (uint16_t)(1024 + i % 60000), SERVER,
                         (uint16_t)(1 + i / 60000));
        if (send_pkt(e, p, DIR_IN, SEC, &w) != VERDICT_ALLOW) {
            CHECK(!"flow table filled before 65536 flows");
            break;
        }
    }
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.flows_active == FW_DEFAULT_MAX_FLOWS);

    /* one more is refused... */
    CHECK(send_pkt(e, mk_udp(CLIENT_B, 5000, SERVER, 9999), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_TABLE_FULL);
    /* ...but existing flows keep working in both directions */
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 1024, SERVER, 1), DIR_IN, SEC+1, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(SERVER, 1, CLIENT_A, 1024), DIR_OUT, SEC+2, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_table_full_recovers_after_expiry(void)
{
    engine_t *e = engine_create_with_rules_sized(rules_of("allow udp any any\n"), 2);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 1, SERVER, 53), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 2, SERVER, 53), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_TABLE_FULL);
    CHECK(send_pkt(e, mk_udp(SERVER, 53, CLIENT_A, 1), DIR_OUT, SEC+1, &w) == VERDICT_ALLOW);

    /* flow 1 saw a reply, so it has the longer 120 s UDP timeout */
    CHECK(engine_expire(e, 100*SEC) == 1);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 101*SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 4, SERVER, 53), DIR_IN, 101*SEC, &w) == VERDICT_DROP);
    CHECK(engine_expire(e, 300*SEC) == 2);
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.drops[DROP_TABLE_FULL] == 2);
    engine_destroy(e);
}

/* Read everything the logger wrote to f. */
static char *slurp(FILE *f)
{
    static char buf[4096];
    rewind(f);
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    return buf;
}

static void test_flow_close_log_has_duration_packets_bytes(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    uint64_t t = 10 * SEC;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, t + 1*SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, t + 2*SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN|TCP_ACK), DIR_IN, t + 4*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN|TCP_ACK), DIR_OUT, t + 5*SEC, &w);
    fw_log_set(NULL, LOG_OFF);

    const char *out = slurp(log);
    CHECK(strstr(out, "FLOW NEW") && strstr(out, "dur=0.000s"));
    const char *close = strstr(out, "FLOW CLOSE");
    CHECK(close != NULL);
    if (close) {
        CHECK(strstr(close, "state=TIME_WAIT") != NULL);
        CHECK(strstr(close, "dur=5.000s") != NULL);          /* t .. t+5 s */
        CHECK(strstr(close, "pkts=3/2") != NULL);
        CHECK(strstr(close, "bytes=180/120") != NULL);
        CHECK(strstr(close, "10.0.0.2:50000 -> 93.184.216.34:80") != NULL);
    }
    fclose(log);
    engine_destroy(e);
}

static void test_expire_log_counts_to_last_packet_not_sweep_time(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    send_pkt(e, mk_udp(CLIENT_A, 6000, SERVER, 53), DIR_IN, 10*SEC, &w);
    send_pkt(e, mk_udp(SERVER, 53, CLIENT_A, 6000), DIR_OUT, 12*SEC, &w);
    CHECK(engine_expire(e, 1000*SEC) == 1);                  /* long after */
    fw_log_set(NULL, LOG_OFF);
    const char *x = strstr(slurp(log), "FLOW EXPIRE");
    CHECK(x != NULL && strstr(x, "dur=2.000s") != NULL);
    fclose(log);
    engine_destroy(e);
}

static int count_str(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static void test_lazy_expiry_is_logged(void)
{
    /* A flow found expired when its tuple shows up again (no sweep ran in
     * between) must still get its EXPIRE line: every flow close is logged. */
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    send_pkt(e, mk_udp(CLIENT_A, 6000, SERVER, 53), DIR_IN, 1*SEC, &w);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 6000, SERVER, 53), DIR_IN, 100*SEC, &w) == VERDICT_ALLOW);
    fw_log_set(NULL, LOG_OFF);
    const char *out = slurp(log);
    CHECK(count_str(out, "FLOW NEW") == 2);
    CHECK(count_str(out, "FLOW EXPIRE") == 1);
    const char *x = strstr(out, "FLOW EXPIRE");
    CHECK(x && strstr(x, "10.0.0.2:6000 -> 93.184.216.34:53") != NULL);
    CHECK(x && out < x && strstr(out, "FLOW NEW") < x);        /* expire comes before the 2nd NEW */
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.flows_expired == 1);
    fclose(log);
    engine_destroy(e);
}

static void test_close_is_logged_once_per_flow(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    /* handshake, RST (-> CLOSED), a second RST, then the same tuple reused */
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, 1*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN|TCP_ACK), DIR_OUT, 2*SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, 3*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, 4*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, 5*SEC, &w);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, 6*SEC, &w) == VERDICT_ALLOW);
    char *out = slurp(log);
    CHECK(count_str(out, "FLOW CLOSE") == 1);                  /* not again on reuse */
    CHECK(count_str(out, "FLOW NEW") == 2);

    /* the closed flow is gone; only the new one is still open and expires */
    CHECK(engine_expire(e, 1000*SEC) == 1);
    fw_log_set(NULL, LOG_OFF);
    out = slurp(log);
    CHECK(count_str(out, "FLOW CLOSE") == 1);
    CHECK(count_str(out, "FLOW EXPIRE") == 1);

    /* a TIME_WAIT flow that times out was already logged as closed */
    rewind(log);
    CHECK(ftruncate(fileno(log), 0) == 0);
    fw_log_set(log, LOG_INFO);
    send_pkt(e, mk_tcp(CLIENT_B, 51000, SERVER, 80, TCP_SYN), DIR_IN, 2000*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_B, 51000, TCP_SYN|TCP_ACK), DIR_OUT, 2001*SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_B, 51000, SERVER, 80, TCP_ACK), DIR_IN, 2002*SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_B, 51000, SERVER, 80, TCP_FIN|TCP_ACK), DIR_IN, 2003*SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_B, 51000, TCP_FIN|TCP_ACK), DIR_OUT, 2004*SEC, &w);
    CHECK(engine_expire(e, 9000*SEC) == 1);
    fw_log_set(NULL, LOG_OFF);
    out = slurp(log);
    CHECK(count_str(out, "FLOW CLOSE") == 1);
    CHECK(count_str(out, "FLOW EXPIRE") == 0);
    fclose(log);
    engine_destroy(e);
}

static void test_table_full_reclaims_expired_flows_on_insert(void)
{
    /* Both slots hold flows that timed out but no sweep ran: a new flow must
     * get a slot instead of being refused as table-full. */
    engine_t *e = engine_create_with_rules_sized(rules_of("allow udp any any\n"), 2);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 1, SERVER, 53), DIR_IN, 1*SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 2, SERVER, 53), DIR_IN, 1*SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 1000*SEC, &w) == VERDICT_ALLOW);
    engine_stats_t s;
    engine_get_stats(e, &s);
    CHECK(s.drops[DROP_TABLE_FULL] == 0);
    CHECK(s.flows_expired == 2);
    CHECK(s.flows_active == 1);
    engine_destroy(e);
}

static void test_table_full_reclaim_is_rate_limited(void)
{
    /* A flood into a table of live flows must not make every packet scan the
     * whole table: at most one reclaim sweep per second. */
    engine_t *e = engine_create_with_rules_sized(rules_of("allow udp any any\n"), 2);
    drop_reason_t w;
    const uint64_t MS = SEC / 1000;
    send_pkt(e, mk_udp(CLIENT_A, 1, SERVER, 53), DIR_IN, 0, &w);        /* expire at 30 s */
    send_pkt(e, mk_udp(CLIENT_A, 2, SERVER, 53), DIR_IN, 0, &w);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 29*SEC + 900*MS, &w) == VERDICT_DROP);  /* sweep: nothing yet */
    CHECK(w == DROP_TABLE_FULL);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 30*SEC + 200*MS, &w) == VERDICT_DROP);  /* < 1 s: no sweep */
    CHECK(w == DROP_TABLE_FULL);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 31*SEC, &w) == VERDICT_ALLOW);          /* sweep runs */
    engine_destroy(e);
}

static engine_t *established_flow(uint64_t *t);
static char *slurp(FILE *f);
static rules_t *rules_of(const char *text);

static void test_the_icmp_error_budget_resets_at_exactly_one_second(void)
{
    engine_t *e = make_engine(RULES_IN);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(send_pkt(e, parsed(syn, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    pkt_t er = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_TIME_EXCEEDED, syn);
    const uint64_t t0 = 10 * SEC;
    for (int i = 0; i < ICMP_ERRORS_PER_FLOW_PER_SEC; i++)
        CHECK(send_pkt(e, er, DIR_OUT, t0, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, er, DIR_OUT, t0 + SEC - 1, &w) == VERDICT_DROP);   /* 1 ns short */
    CHECK(w == DROP_ICMP_RATE);
    CHECK(send_pkt(e, er, DIR_OUT, t0 + SEC, &w) == VERDICT_ALLOW);      /* exactly a second */
    /* a clock that jumps backwards must not freeze the flow's budget */
    for (int i = 1; i < ICMP_ERRORS_PER_FLOW_PER_SEC; i++)
        CHECK(send_pkt(e, er, DIR_OUT, t0 + SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, er, DIR_OUT, t0 + SEC, &w) == VERDICT_DROP);       /* budget used up */
    CHECK(send_pkt(e, er, DIR_OUT, 2 * SEC, &w) == VERDICT_ALLOW);       /* time went backwards: reset */
    engine_destroy(e);
}

static void test_icmp_errors_about_a_time_wait_flow_are_dropped(void)
{
    uint64_t t = SEC;
    engine_t *e = established_flow(&t);
    drop_reason_t w;
    uint8_t syn[128], err[256];
    size_t n = pb_tcp(syn, sizeof syn, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN | TCP_ACK), DIR_IN, t += SEC, &w);
    pkt_t early = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, early, DIR_OUT, t += SEC, &w) == VERDICT_ALLOW);   /* FIN_WAIT: still open */
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN | TCP_ACK), DIR_OUT, t += SEC, &w);
    pkt_t late = icmp_error(err, ROUTER_OUT, CLIENT_A, ICMP_DEST_UNREACH, syn);
    CHECK(send_pkt(e, late, DIR_OUT, t += SEC, &w) == VERDICT_DROP);     /* TIME_WAIT */
    CHECK(w == DROP_ICMP_ERR);
    (void)n;
    engine_destroy(e);
}

static void test_the_reclaim_sweep_runs_at_exactly_one_second(void)
{
    engine_t *e = engine_create_with_rules_sized(rules_of("allow udp any any\n"), 2);
    drop_reason_t w;
    const uint64_t MS = SEC / 1000;
    send_pkt(e, mk_udp(CLIENT_A, 1, SERVER, 53), DIR_IN, 0, &w);          /* both expire at 30 s */
    send_pkt(e, mk_udp(CLIENT_A, 2, SERVER, 53), DIR_IN, 0, &w);
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 29 * SEC + 500 * MS, &w) == VERDICT_DROP);
    /* exactly one second after that sweep the flows are expired and the sweep may run again */
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 3, SERVER, 53), DIR_IN, 30 * SEC + 500 * MS, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_flow_log_lines_name_the_rule_and_use_the_packet_time(void)
{
    engine_t *e = make_engine("allow tcp from 10.0.0.0/24 to any port 80\nallow udp from 10.0.0.0/24 to any port 53\n");
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, 10 * SEC, &w);
    send_pkt(e, mk_udp(CLIENT_A, 6000, SERVER, 53), DIR_IN, 12 * SEC, &w);
    CHECK(engine_expire(e, 500 * SEC) == 2);
    fw_log_set(NULL, LOG_OFF);
    const char *out = slurp(log);
    /* make_engine prepends the inside line, so the rules are on lines 2 and 3 */
    CHECK(strstr(out, "[ 10.000000] FLOW NEW    tcp 10.0.0.2:50000 -> 93.184.216.34:80 state=SYN_SENT rule=2") != NULL);
    CHECK(strstr(out, "[ 12.000000] FLOW NEW    udp 10.0.0.2:6000 -> 93.184.216.34:53") != NULL);
    CHECK(strstr(out, "rule=3") != NULL);
    CHECK(strstr(out, "[500.000000] FLOW EXPIRE tcp") != NULL);     /* stamped with the sweep time */
    CHECK(strstr(out, "[500.000000] FLOW EXPIRE udp") != NULL);
    fclose(log);
    engine_destroy(e);
}

/* ---- who may start a flow, and how many ------------------------------------ */

static void test_a_flow_must_run_between_inside_and_outside(void)
{
    /* Whatever the rules say: inside-to-inside and outside-to-outside traffic
     * has no business crossing the firewall, nor has anything addressed to an
     * inside network's broadcast address. */
    engine_t *e = make_engine("allow any any any\nallow in any any any\n");
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);

    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50001, CLIENT_B, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_DST);                                  /* inside -> inside   */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50002, CLIENT_A, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_DST);                                  /* to its own address */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4445, SERVER, 80, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_DST);                                  /* outside -> outside */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4446, IP(10,0,0,255), 80, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_DST);                                  /* inside broadcast   */
    CHECK(send_pkt(e, mk_udp(ATTACKER, 4447, IP(10,0,0,255), 53), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_DST);
    /* .0 and .254 are ordinary hosts */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4448, IP(10,0,0,254), 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);

    /* a /32 inside network has no broadcast address */
    e = make_engine("inside 10.0.0.2/32\nallow in any any any\n");
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4449, CLIENT_A, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_only_a_plain_syn_starts_a_tcp_flow(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    /* ECN setup bits ride on a SYN legitimately */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN | TCP_ECE | TCP_CWR), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    /* PSH / URG on a SYN is a scanner's trick, not a connection */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50001, SERVER, 80, TCP_SYN | TCP_PSH), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NOT_SYN);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50002, SERVER, 80, TCP_SYN | TCP_URG), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NOT_SYN);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50003, SERVER, 80, TCP_SYN | TCP_PSH | TCP_URG), DIR_IN, SEC, &w) == VERDICT_DROP);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.flows_created == 1);
    /* A SYN that carries data is allowed on purpose: TCP Fast Open sends data
     * in the SYN, and the destination was already approved by a rule. */
    uint8_t b[256], data[16] = "fast-open-data";
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50004, SERVER, 80, TCP_SYN, data, sizeof data);
    CHECK(send_pkt(e, parsed(b, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static engine_t *established_flow(uint64_t *t)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, *t, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN | TCP_ACK), DIR_OUT, *t += SEC, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, *t += SEC, &w);
    return e;
}

static void test_a_closed_connection_cannot_be_kept_alive_or_carry_data(void)
{
    uint64_t t = SEC;
    engine_t *e = established_flow(&t);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN | TCP_ACK), DIR_IN, t += SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN | TCP_ACK), DIR_OUT, t += SEC, &w);
    const uint64_t closed_at = t;               /* TIME_WAIT: 30 s from here */

    /* data on a connection both sides have closed: dropped */
    t += 10 * SEC;
    uint8_t b[256], data[8] = "payload";
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 80, TCP_ACK | TCP_PSH, data, sizeof data);
    CHECK(send_pkt(e, parsed(b, n), DIR_IN, t, &w) == VERDICT_DROP);
    CHECK(w == DROP_TCP_STATE);
    /* bare ACKs are fine, but they do not extend the flow's life */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, t = closed_at + 20 * SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, closed_at + 29 * SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, closed_at + 31 * SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NOT_SYN);                   /* the flow is gone: no flow, not a SYN */
    engine_destroy(e);

    /* a reset connection (CLOSED, 5 s) is not kept alive by repeated RSTs */
    t = SEC;
    e = established_flow(&t);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, t += SEC, &w);
    const uint64_t reset_at = t;
    for (int i = 1; i <= 4; i++)
        CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, reset_at + i * SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_RST), DIR_OUT, reset_at + 6 * SEC, &w) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_a_half_closed_connection_survives_a_long_pause(void)
{
    /* The client sends its request and half-closes (shutdown(WR)); the server
     * takes 75 s to answer, which a real server may. */
    uint64_t t = SEC;
    engine_t *e = established_flow(&t);
    drop_reason_t w;
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN | TCP_ACK), DIR_IN, t += SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK | TCP_PSH), DIR_OUT, t + 75 * SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN | TCP_ACK), DIR_OUT, t + 76 * SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_a_tuple_in_time_wait_can_be_reused_by_a_new_syn(void)
{
    uint64_t t = SEC;
    engine_t *e = established_flow(&t);
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_FIN | TCP_ACK), DIR_IN, t += SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_FIN | TCP_ACK), DIR_OUT, t += SEC, &w);
    /* anything but a plain SYN from the originator does not revive it */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN | TCP_ACK), DIR_IN, t += SEC, &w) == VERDICT_DROP);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN), DIR_OUT, t += SEC, &w) == VERDICT_DROP);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.flows_active == 1);
    /* a fresh SYN from the originator starts over */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, t += SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN | TCP_ACK), DIR_OUT, t += SEC, &w) == VERDICT_ALLOW);
    engine_get_stats(e, &st);
    CHECK(st.flows_created == 2 && st.flows_active == 1);
    engine_destroy(e);
}

static void test_one_source_cannot_hold_more_than_its_share_of_flows(void)
{
    engine_t *e = make_engine("allow in tcp from any to 10.0.0.3 port 22\nallow udp from 10.0.0.0/24 to any\n");
    CHECK(engine_set_limits(e, 3, 0));
    drop_reason_t w;
    for (int i = 0; i < 3; i++)
        CHECK(send_pkt(e, mk_tcp(ATTACKER, (uint16_t)(4000 + i), CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4010, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_SRC_LIMIT);
    /* a SYN retransmit on an existing flow is not a new flow */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4000, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    /* other sources are untouched, inside or outside */
    CHECK(send_pkt(e, mk_tcp(IP(198,51,100,67), 4000, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    for (int i = 0; i < 3; i++) {
        CHECK(send_pkt(e, mk_udp(CLIENT_A, (uint16_t)(5000 + i), SERVER, 53), DIR_IN, SEC, &w) == VERDICT_ALLOW);
        CHECK(send_pkt(e, mk_udp(CLIENT_B, (uint16_t)(5000 + i), SERVER, 53), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    }
    /* the cap applies to every originating address, an inside host included */
    CHECK(send_pkt(e, mk_udp(CLIENT_A, 5003, SERVER, 53), DIR_IN, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_SRC_LIMIT);
    /* flows that time out give the source its room back */
    CHECK(send_pkt(e, mk_tcp(ATTACKER, 4010, CLIENT_B, 22, TCP_SYN), DIR_OUT, 100 * SEC, &w) == VERDICT_ALLOW);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.drops[DROP_SRC_LIMIT] == 2);
    engine_destroy(e);
}

static void test_outside_flows_cannot_take_the_inside_users_reserve(void)
{
    engine_t *e = make_engine("allow in tcp from any to 10.0.0.3 port 22\nallow tcp from 10.0.0.0/24 to any port 80\n");
    CHECK(engine_set_limits(e, 0, 4));
    drop_reason_t w;
    for (int i = 0; i < 4; i++)
        CHECK(send_pkt(e, mk_tcp(IP(198,51,100,i + 1), 4000, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(IP(198,51,100,99), 4000, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_OUTSIDE_QUOTA);
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_a_spoofed_flood_from_outside_leaves_the_inside_working(void)
{
    /* The default engine, the example policy, and an attacker using a fresh
     * (spoofed) source address for every SYN so no per-source cap helps. */
    engine_t *e = make_engine("allow in tcp from any to 10.0.0.3 port 22\nallow tcp from 10.0.0.0/24 to any port 80\n");
    drop_reason_t w;
    uint32_t allowed = 0, quota = 0;
    for (uint32_t i = 0; i < 60000; i++) {
        uint32_t src = IP(198,18,0,0) + 1 + i;
        verdict_t v = send_pkt(e, mk_tcp(src, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w);
        if (v == VERDICT_ALLOW) allowed++; else if (w == DROP_OUTSIDE_QUOTA) quota++;
    }
    CHECK(allowed == FW_DEFAULT_MAX_OUTSIDE);
    CHECK(quota == 60000 - FW_DEFAULT_MAX_OUTSIDE);
    /* the inside users still get through, over and over */
    for (int i = 0; i < 100; i++)
        CHECK(send_pkt(e, mk_tcp(CLIENT_A, (uint16_t)(40000 + i), SERVER, 80, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_the_default_engine_caps_one_source_at_a_sixteenth(void)
{
    engine_t *e = make_engine("allow in tcp from any to 10.0.0.3 port 22\n");
    drop_reason_t w;
    uint32_t ok = 0;
    for (uint32_t i = 0; i < FW_DEFAULT_MAX_PER_SOURCE + 50; i++)
        if (send_pkt(e, mk_tcp(ATTACKER, (uint16_t)(1024 + i), CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW) ok++;
    CHECK(ok == FW_DEFAULT_MAX_PER_SOURCE);
    CHECK(w == DROP_SRC_LIMIT);
    CHECK(FW_DEFAULT_MAX_PER_SOURCE == 4096 && FW_DEFAULT_MAX_OUTSIDE == 49152);
    CHECK(send_pkt(e, mk_tcp(IP(198,51,100,200), 1024, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    engine_destroy(e);
}

static void test_undoing_a_write_that_failed_forgets_only_the_new_flow(void)
{
    engine_t *e = make_engine(RULES);
    drop_reason_t w;
    pkt_t syn = mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN);
    CHECK(send_pkt(e, syn, DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(engine_undo_new_flow(e, &syn, DIR_IN, SEC));
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.flows_active == 0 && st.flows_created == 0);
    CHECK(st.pkts_allowed == 0 && st.pkts_dropped == 1 && st.drops[DROP_WRITE_FAILED] == 1);
    CHECK(send_pkt(e, syn, DIR_IN, SEC + 1, &w) == VERDICT_ALLOW);      /* the retry works */

    /* a packet on an existing flow: the flow stays */
    pkt_t sa = mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_SYN | TCP_ACK);
    CHECK(send_pkt(e, sa, DIR_OUT, SEC + 2, &w) == VERDICT_ALLOW);
    CHECK(!engine_undo_new_flow(e, &sa, DIR_OUT, SEC + 2));
    pkt_t syn_again = mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_SYN);     /* a retransmit of the SYN */
    CHECK(send_pkt(e, syn_again, DIR_IN, SEC + 3, &w) == VERDICT_ALLOW);
    CHECK(!engine_undo_new_flow(e, &syn_again, DIR_IN, SEC + 3));       /* not the creating packet */
    engine_get_stats(e, &st);
    CHECK(st.flows_active == 1);
    engine_destroy(e);
}

/* ---- application identification: labels only, never a verdict ---------------- */

static const char *OPEN_RULES =
    "allow tcp from 10.0.0.0/24 to any\nallow udp from 10.0.0.0/24 to any\nallow icmp from 10.0.0.0/24 to any\n";

static const char HTTP_GET[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const char HTTP_OK[]  = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/* A TLS ClientHello record header (enough for identification). */
static size_t tls_client_hello(uint8_t *b)
{
    static const uint8_t hello[] = { 0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,
                                     1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                                     0, 0, 0, 0 };
    memcpy(b, hello, sizeof hello);
    return sizeof hello;
}

/* A DNS query for example.com (type A). */
static size_t dns_query(uint8_t *b)
{
    static const uint8_t q[] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                                 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0, 1, 0, 1 };
    memcpy(b, q, sizeof q);
    return sizeof q;
}

static verdict_t send_data(engine_t *e, dir_t dir, uint32_t src, uint16_t sp, uint32_t dst, uint16_t dp,
                           int proto, const void *data, size_t n, uint64_t t, drop_reason_t *w)
{
    uint8_t b[512];
    size_t len = proto == FW_PROTO_TCP
        ? pb_tcp(b, sizeof b, NULL, src, sp, dst, dp, TCP_ACK | TCP_PSH, data, n)
        : pb_udp(b, sizeof b, NULL, src, sp, dst, dp, data, n);
    return send_pkt(e, parsed(b, len), dir, t, w);
}

/* handshake for CLIENT_A:cp -> SERVER:sp, returns the time after it */
static uint64_t handshake(engine_t *e, uint16_t cp, uint16_t sp, uint64_t t)
{
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, cp, SERVER, sp, TCP_SYN), DIR_IN, t, &w);
    send_pkt(e, mk_tcp(SERVER, sp, CLIENT_A, cp, TCP_SYN | TCP_ACK), DIR_OUT, t + 1, &w);
    send_pkt(e, mk_tcp(CLIENT_A, cp, SERVER, sp, TCP_ACK), DIR_IN, t + 2, &w);
    return t + 3;
}

static void test_a_flow_is_labelled_by_its_payload_not_its_port(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    uint8_t buf[128];
    uint64_t t = handshake(e, 50000, 8080, SEC);                 /* HTTP on port 8080 */
    CHECK(send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 8080, FW_PROTO_TCP, HTTP_GET, sizeof HTTP_GET - 1, t, &w) == VERDICT_ALLOW);
    t = handshake(e, 50001, 8081, t + 10);                       /* TLS on port 8081 */
    size_t n = tls_client_hello(buf);
    CHECK(send_data(e, DIR_IN, CLIENT_A, 50001, SERVER, 8081, FW_PROTO_TCP, buf, n, t, &w) == VERDICT_ALLOW);
    n = dns_query(buf);                                          /* DNS on UDP port 5353 */
    CHECK(send_data(e, DIR_IN, CLIENT_A, 6000, SERVER, 5353, FW_PROTO_UDP, buf, n, t + 10, &w) == VERDICT_ALLOW);
    fw_log_set(NULL, LOG_OFF);

    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_HTTP] == 1 && st.app_flows[APP_TLS] == 1 && st.app_flows[APP_DNS] == 1);
    CHECK(st.app_flows[APP_OTHER] == 0 && st.app_mismatch == 0);     /* none of these ports suggests anything */
    const char *out = slurp(log);
    CHECK(strstr(out, "FLOW APP    tcp 10.0.0.2:50000 -> 93.184.216.34:8080") != NULL);
    CHECK(strstr(out, "app=http") != NULL && strstr(out, "app=tls") != NULL && strstr(out, "app=dns") != NULL);
    CHECK(strstr(out, "mismatch") == NULL);
    fclose(log);
    engine_destroy(e);
}

static void test_a_port_that_disagrees_with_the_payload_is_flagged(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    uint8_t buf[128];
    uint64_t t = handshake(e, 50000, 443, SEC);                   /* HTTP on 443: not TLS */
    send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 443, FW_PROTO_TCP, HTTP_GET, sizeof HTTP_GET - 1, t, &w);
    t = handshake(e, 50001, 80, t + 10);                          /* TLS on 80: not HTTP */
    size_t n = tls_client_hello(buf);
    send_data(e, DIR_IN, CLIENT_A, 50001, SERVER, 80, FW_PROTO_TCP, buf, n, t, &w);
    t = handshake(e, 50002, 80, t + 10);                          /* HTTP on 80: as expected */
    send_data(e, DIR_IN, CLIENT_A, 50002, SERVER, 80, FW_PROTO_TCP, HTTP_GET, sizeof HTTP_GET - 1, t, &w);
    t = handshake(e, 50003, 443, t + 10);                         /* TLS on 443: as expected */
    n = tls_client_hello(buf);
    send_data(e, DIR_IN, CLIENT_A, 50003, SERVER, 443, FW_PROTO_TCP, buf, n, t, &w);
    n = dns_query(buf);                                           /* DNS on 53 and on 8053 */
    send_data(e, DIR_IN, CLIENT_A, 6000, SERVER, 53, FW_PROTO_UDP, buf, n, t + 10, &w);
    send_data(e, DIR_IN, CLIENT_A, 6001, SERVER, 8053, FW_PROTO_UDP, buf, n, t + 10, &w);
    send_data(e, DIR_IN, CLIENT_A, 6002, SERVER, 53, FW_PROTO_UDP, "not dns at all", 14, t + 10, &w);   /* junk on 53 */
    fw_log_set(NULL, LOG_OFF);

    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_HTTP] == 2 && st.app_flows[APP_TLS] == 2 && st.app_flows[APP_DNS] == 2);
    CHECK(st.app_mismatch == 2);              /* HTTP on 443, TLS on 80; junk on 53 is still undecided */
    const char *out = slurp(log);
    CHECK(strstr(out, "50000 -> 93.184.216.34:443 state=ESTABLISHED rule=2 app=http") != NULL);
    CHECK(strstr(out, "mismatch(port suggests tls)") != NULL);
    CHECK(strstr(out, "mismatch(port suggests http)") != NULL);
    CHECK(count_str(out, "mismatch") == 2);
    fclose(log);
    engine_destroy(e);
}

static void test_unrecognized_traffic_is_called_other_after_three_data_packets(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    uint64_t t = handshake(e, 50000, 443, SEC);                   /* something on 443 that is not TLS */
    engine_stats_t st;
    for (int i = 1; i <= APPID_MAX_TRIES; i++) {
        CHECK(send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 443, FW_PROTO_TCP, "SSH-2.0-OpenSSH_9.6\r\n", 21, t + i, &w) == VERDICT_ALLOW);
        engine_get_stats(e, &st);
        CHECK(st.app_flows[APP_OTHER] == (i == APPID_MAX_TRIES ? 1u : 0u));   /* undecided until the last try */
    }
    CHECK(st.app_mismatch == 1);                                  /* "other" on a TLS port is a mismatch */
    /* the decision is final: a recognizable packet later does not change it */
    uint8_t buf[64];
    size_t n = tls_client_hello(buf);
    CHECK(send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 443, FW_PROTO_TCP, buf, n, t + 10, &w) == VERDICT_ALLOW);
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_TLS] == 0 && st.app_flows[APP_OTHER] == 1 && st.app_mismatch == 1);
    engine_destroy(e);
}

static void test_the_first_recognized_protocol_wins_and_is_counted_once(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    uint64_t t = handshake(e, 50000, 8080, SEC);
    /* an unrecognized packet first, then HTTP: still HTTP */
    send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 8080, FW_PROTO_TCP, "hello", 5, t, &w);
    send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 8080, FW_PROTO_TCP, HTTP_GET, sizeof HTTP_GET - 1, t + 1, &w);
    /* the server's response (HTTP) and a later TLS-looking packet change nothing */
    send_data(e, DIR_OUT, SERVER, 8080, CLIENT_A, 50000, FW_PROTO_TCP, HTTP_OK, sizeof HTTP_OK - 1, t + 2, &w);
    uint8_t buf[64];
    size_t n = tls_client_hello(buf);
    send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 8080, FW_PROTO_TCP, buf, n, t + 3, &w);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_HTTP] == 1 && st.app_flows[APP_TLS] == 0 && st.app_flows[APP_OTHER] == 0);
    engine_destroy(e);
}

static void test_the_server_speaking_first_can_identify_the_flow(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    uint64_t t = handshake(e, 50000, 8080, SEC);
    send_data(e, DIR_OUT, SERVER, 8080, CLIENT_A, 50000, FW_PROTO_TCP, HTTP_OK, sizeof HTTP_OK - 1, t, &w);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_HTTP] == 1);
    /* and a DNS response on a UDP flow */
    uint8_t q[64];
    size_t n = dns_query(q);
    send_data(e, DIR_IN, CLIENT_A, 6000, SERVER, 53, FW_PROTO_UDP, "x", 1, t + 5, &w);          /* a non-DNS first datagram */
    send_data(e, DIR_OUT, SERVER, 53, CLIENT_A, 6000, FW_PROTO_UDP, q, n, t + 6, &w);            /* then a DNS reply */
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_DNS] == 1);
    engine_destroy(e);
}

static void test_nothing_is_labelled_without_payload_or_on_icmp(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    uint64_t t = handshake(e, 50000, 80, SEC);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 80, TCP_ACK), DIR_IN, t, &w);       /* bare ACKs carry no data */
    send_pkt(e, mk_tcp(SERVER, 80, CLIENT_A, 50000, TCP_ACK), DIR_OUT, t + 1, &w);
    uint8_t b[128], payload[40] = "GET / HTTP/1.1";
    size_t n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST, 7, 1, payload, sizeof payload);
    for (int i = 0; i < 2 * APPID_MAX_TRIES; i++)       /* more echoes than the labelling would ever try */
        CHECK(send_pkt(e, parsed(b, n), DIR_IN, t + 2 + (uint64_t)i, &w) == VERDICT_ALLOW);   /* ICMP never carries an app */
    engine_stats_t st;
    engine_get_stats(e, &st);
    uint64_t total = 0;
    for (int a = 0; a < APP_COUNT; a++) total += st.app_flows[a];
    CHECK(total == 0 && st.app_mismatch == 0);
    engine_destroy(e);
}

static void test_data_in_a_syn_labels_the_flow_at_once(void)
{
    /* TCP Fast Open: the request rides in the SYN itself */
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    uint8_t b[256];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 8080, TCP_SYN, HTTP_GET, sizeof HTTP_GET - 1);
    CHECK(send_pkt(e, parsed(b, n), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_HTTP] == 1);
    engine_destroy(e);
}

static void test_labelling_never_changes_a_verdict(void)
{
    /* Same rules, three payloads on port 443 (TLS, HTTP, garbage): every one is
     * allowed, because the rules allowed the port. And a refused flow is never labelled. */
    engine_t *e = make_engine("allow tcp from 10.0.0.0/24 to any port 443\n");
    drop_reason_t w;
    uint8_t buf[64];
    size_t n = tls_client_hello(buf);
    const uint16_t ports[3] = { 50000, 50001, 50002 };
    for (int i = 0; i < 3; i++) {
        uint64_t t = handshake(e, ports[i], 443, SEC + (uint64_t)i * 100);
        const void *d = i == 0 ? (const void *)buf : i == 1 ? (const void *)HTTP_GET : (const void *)"junk junk junk";
        const size_t dl = i == 0 ? n : i == 1 ? sizeof HTTP_GET - 1 : 14;
        for (int k = 0; k < 4; k++)
            CHECK(send_data(e, DIR_IN, CLIENT_A, ports[i], SERVER, 443, FW_PROTO_TCP, d, dl, t + (uint64_t)k, &w) == VERDICT_ALLOW);
    }
    /* a refused flow: the SYN is dropped, so nothing about it is ever labelled */
    CHECK(send_pkt(e, mk_tcp(CLIENT_A, 51000, SERVER, 8443, TCP_SYN), DIR_IN, 10 * SEC, &w) == VERDICT_DROP);
    CHECK(send_data(e, DIR_IN, CLIENT_A, 51000, SERVER, 8443, FW_PROTO_TCP, HTTP_GET, sizeof HTTP_GET - 1, 10 * SEC + 1, &w) == VERDICT_DROP);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.app_flows[APP_TLS] == 1 && st.app_flows[APP_HTTP] == 1 && st.app_flows[APP_OTHER] == 1);
    CHECK(st.pkts_dropped == 2);
    engine_destroy(e);
}

static void test_the_label_is_in_every_flow_log_line_after_it_is_known(void)
{
    engine_t *e = make_engine(OPEN_RULES);
    drop_reason_t w;
    FILE *log = tmpfile();
    fw_log_set(log, LOG_INFO);
    uint8_t buf[64];
    size_t n = tls_client_hello(buf);
    uint64_t t = handshake(e, 50000, 443, SEC);
    send_data(e, DIR_IN, CLIENT_A, 50000, SERVER, 443, FW_PROTO_TCP, buf, n, t, &w);
    send_pkt(e, mk_tcp(CLIENT_A, 50000, SERVER, 443, TCP_FIN | TCP_ACK), DIR_IN, t + SEC, &w);
    send_pkt(e, mk_tcp(SERVER, 443, CLIENT_A, 50000, TCP_FIN | TCP_ACK), DIR_OUT, t + 2 * SEC, &w);
    fw_log_set(NULL, LOG_OFF);
    const char *out = slurp(log);
    const char *nw = strstr(out, "FLOW NEW");
    CHECK(nw && strstr(nw, "app=-") != NULL && strstr(nw, "app=-") < strstr(nw, "\n"));   /* unknown at creation */
    const char *app = strstr(out, "FLOW APP");
    CHECK(app && strstr(app, "app=tls") != NULL);
    const char *close = strstr(out, "FLOW CLOSE");
    CHECK(close && strstr(close, "app=tls") != NULL);
    fclose(log);
    engine_destroy(e);
}

/* ---- creating an engine from a rules file --------------------------------- */

static void test_engine_create_from_the_shipped_config(void)
{
    char err[128] = "";
    engine_t *e = engine_create("config/rules.example.conf", err, sizeof err);
    CHECK(e != NULL);
    if (!e) return;
    drop_reason_t w;
    uint32_t a = IP(10,0,1,2), b = IP(10,0,1,3), web = IP(93,184,216,34),
             attacker = IP(10,0,2,3);
    CHECK(send_pkt(e, mk_tcp(a, 40000, web, 443, TCP_SYN), DIR_IN, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(attacker, 4444, b, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_ALLOW);
    CHECK(send_pkt(e, mk_tcp(attacker, 4444, b, 3389, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_NO_RULE);
    CHECK(send_pkt(e, mk_tcp(a, 4444, b, 22, TCP_SYN), DIR_OUT, SEC, &w) == VERDICT_DROP);
    CHECK(w == DROP_BAD_SRC);                      /* the file declares `inside` */
    engine_destroy(e);
}

static void test_engine_create_reports_bad_files(void)
{
    char err[128] = "";
    CHECK(engine_create("/nonexistent/rules.conf", err, sizeof err) == NULL);
    CHECK(strstr(err, "cannot open") != NULL);

    char path[512];
    const char *dir = getenv("TMPDIR");
    snprintf(path, sizeof path, "%s/fw_engine_test_XXXXXX", dir && *dir ? dir : "/tmp");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    const char *bad = "allow tcp 10.0.1.0/24 any 80\nallow bogus\n";
    CHECK(write(fd, bad, strlen(bad)) == (ssize_t)strlen(bad));
    close(fd);
    err[0] = '\0';
    CHECK(engine_create(path, err, sizeof err) == NULL);   /* refuses to start */
    CHECK(strncmp(err, path, strlen(path)) == 0);          /* names the file ... */
    CHECK(strstr(err, ": line 2:") != NULL);               /* ... and says which line */
    unlink(path);

    /* a valid file with no `inside` line is refused, and says why */
    snprintf(path, sizeof path, "%s/fw_engine_test_XXXXXX", dir && *dir ? dir : "/tmp");
    fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    const char *noinside = "allow out tcp 10.0.1.0/24 any 80\n";
    CHECK(write(fd, noinside, strlen(noinside)) == (ssize_t)strlen(noinside));
    close(fd);
    err[0] = '\0';
    CHECK(engine_create(path, err, sizeof err) == NULL);
    CHECK(strstr(err, "inside") != NULL);
    unlink(path);
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
    RUN(test_icmp_error_for_outbound_tcp_allowed);
    RUN(test_icmp_error_after_reply_direction);
    RUN(test_icmp_error_unrelated_dropped);
    RUN(test_icmp_error_wrong_direction_dropped);
    RUN(test_icmp_echo_type_must_match_direction);
    RUN(test_icmp_rejected_packets_do_not_refresh_flow);
    RUN(test_icmp_error_must_be_addressed_to_the_embedded_senders);
    RUN(test_icmp_errors_only_for_active_tcp_flows);
    RUN(test_icmp_errors_are_rate_limited_per_flow);
    RUN(test_icmp_error_about_echo);
    RUN(test_icmp_error_does_not_refresh_flow);
    RUN(test_icmp_error_never_matches_echo_id_zero);
    RUN(test_antispoof_outside_claiming_inside_address);
    RUN(test_antispoof_inside_with_foreign_address);
    RUN(test_antispoof_covers_icmp_errors);
    RUN(test_engine_refuses_rules_without_an_inside_network);
    RUN(test_parse_failures_counted_and_logged);
    RUN(test_default_capacity_is_65536_and_full_table_keeps_flows);
    RUN(test_table_full_recovers_after_expiry);
    RUN(test_flow_close_log_has_duration_packets_bytes);
    RUN(test_expire_log_counts_to_last_packet_not_sweep_time);
    RUN(test_lazy_expiry_is_logged);
    RUN(test_close_is_logged_once_per_flow);
    RUN(test_table_full_reclaims_expired_flows_on_insert);
    RUN(test_table_full_reclaim_is_rate_limited);
    RUN(test_a_flow_must_run_between_inside_and_outside);
    RUN(test_only_a_plain_syn_starts_a_tcp_flow);
    RUN(test_a_closed_connection_cannot_be_kept_alive_or_carry_data);
    RUN(test_a_half_closed_connection_survives_a_long_pause);
    RUN(test_a_tuple_in_time_wait_can_be_reused_by_a_new_syn);
    RUN(test_one_source_cannot_hold_more_than_its_share_of_flows);
    RUN(test_outside_flows_cannot_take_the_inside_users_reserve);
    RUN(test_a_spoofed_flood_from_outside_leaves_the_inside_working);
    RUN(test_the_default_engine_caps_one_source_at_a_sixteenth);
    RUN(test_undoing_a_write_that_failed_forgets_only_the_new_flow);
    RUN(test_the_icmp_error_budget_resets_at_exactly_one_second);
    RUN(test_icmp_errors_about_a_time_wait_flow_are_dropped);
    RUN(test_the_reclaim_sweep_runs_at_exactly_one_second);
    RUN(test_flow_log_lines_name_the_rule_and_use_the_packet_time);
    RUN(test_a_flow_is_labelled_by_its_payload_not_its_port);
    RUN(test_a_port_that_disagrees_with_the_payload_is_flagged);
    RUN(test_unrecognized_traffic_is_called_other_after_three_data_packets);
    RUN(test_the_first_recognized_protocol_wins_and_is_counted_once);
    RUN(test_the_server_speaking_first_can_identify_the_flow);
    RUN(test_nothing_is_labelled_without_payload_or_on_icmp);
    RUN(test_data_in_a_syn_labels_the_flow_at_once);
    RUN(test_labelling_never_changes_a_verdict);
    RUN(test_the_label_is_in_every_flow_log_line_after_it_is_known);
    RUN(test_engine_create_from_the_shipped_config);
    RUN(test_engine_create_reports_bad_files);
    TEST_DONE();
}

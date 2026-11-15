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

static void test_antispoof_off_without_inside_directive(void)
{
    engine_t *e = make_engine(RULES);          /* no `inside` line */
    drop_reason_t w;
    send_pkt(e, mk_tcp(CLIENT_A, 4444, CLIENT_B, 22, TCP_SYN), DIR_OUT, SEC, &w);
    CHECK(w != DROP_BAD_SRC);
    send_pkt(e, mk_tcp(IP(8,8,8,8), 5, SERVER, 80, TCP_SYN), DIR_IN, SEC, &w);
    CHECK(w != DROP_BAD_SRC);
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
    return rules_parse_string(text, err, sizeof err);
}

static void test_default_capacity_is_65536_and_full_table_keeps_flows(void)
{
    CHECK(FW_DEFAULT_MAX_FLOWS == 65536u);
    engine_t *e = engine_create_with_rules(rules_of("allow udp any any\n"));
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
    CHECK(strncmp(err, "line 2:", 7) == 0);                /* says which line */
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
    RUN(test_icmp_error_about_echo);
    RUN(test_icmp_error_does_not_refresh_flow);
    RUN(test_icmp_error_never_matches_echo_id_zero);
    RUN(test_antispoof_outside_claiming_inside_address);
    RUN(test_antispoof_inside_with_foreign_address);
    RUN(test_antispoof_covers_icmp_errors);
    RUN(test_antispoof_off_without_inside_directive);
    RUN(test_parse_failures_counted_and_logged);
    RUN(test_default_capacity_is_65536_and_full_table_keeps_flows);
    RUN(test_table_full_recovers_after_expiry);
    RUN(test_flow_close_log_has_duration_packets_bytes);
    RUN(test_expire_log_counts_to_last_packet_not_sweep_time);
    RUN(test_engine_create_from_the_shipped_config);
    RUN(test_engine_create_reports_bad_files);
    TEST_DONE();
}

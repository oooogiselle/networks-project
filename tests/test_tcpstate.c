/*=============================================================================
 * File Name:   test_tcpstate.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Unit tests for the TCP state machine: handshake, teardown, RST,
 *              illegal flag combinations, and timeouts.
 =============================================================================*/

#include "tcpstate.h"
#include "testutil.h"

#define SYN     TCP_SYN
#define SYNACK  (TCP_SYN | TCP_ACK)
#define ACK     TCP_ACK
#define FINACK  (TCP_FIN | TCP_ACK)
#define SEC_NS 1000000000ull
#define ORIG true
#define RESP false

static flow_t new_flow(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    f.key.proto = FW_PROTO_TCP;
    tcp_flow_init(&f);
    return f;
}

static flow_t established(void)
{
    flow_t f = new_flow();
    tcp_track(&f, SYN, ORIG);
    tcp_track(&f, SYNACK, RESP);
    tcp_track(&f, ACK, ORIG);
    return f;
}

static void test_three_way_handshake(void)
{
    flow_t f = new_flow();
    CHECK(f.tcp_state == TCPS_SYN_SENT);
    CHECK(tcp_track(&f, SYNACK, RESP));
    CHECK(f.tcp_state == TCPS_SYN_RECV);
    CHECK(tcp_track(&f, ACK, ORIG));
    CHECK(f.tcp_state == TCPS_ESTABLISHED);
}

static void test_data_flows_both_ways_when_established(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, ACK | TCP_PSH, ORIG));
    CHECK(tcp_track(&f, ACK, RESP));
    CHECK(tcp_track(&f, ACK | TCP_PSH, RESP));
    CHECK(f.tcp_state == TCPS_ESTABLISHED);
}

static void test_data_before_handshake_dropped(void)
{
    flow_t f = new_flow();
    CHECK(!tcp_track(&f, ACK, RESP));            /* reply w/o SYN-ACK */
    CHECK(!tcp_track(&f, ACK | TCP_PSH, ORIG));  /* data before SYN-ACK */
    CHECK(f.tcp_state == TCPS_SYN_SENT);         /* unchanged */
}

static void test_syn_retransmit_ok(void)
{
    flow_t f = new_flow();
    CHECK(tcp_track(&f, SYN, ORIG));
    CHECK(f.tcp_state == TCPS_SYN_SENT);
}

static void test_graceful_close(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, FINACK, ORIG));
    CHECK(f.tcp_state == TCPS_FIN_WAIT);
    CHECK(tcp_track(&f, ACK, RESP));             /* half-close: still legal */
    CHECK(tcp_track(&f, ACK, RESP));
    CHECK(tcp_track(&f, FINACK, RESP));
    CHECK(f.tcp_state == TCPS_TIME_WAIT);
    CHECK(tcp_track(&f, ACK, ORIG));             /* final ACK */
    CHECK(!tcp_track(&f, SYN, ORIG));            /* no resurrection here */
}

static void test_fin_from_responder_first(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, FINACK, RESP));
    CHECK(f.tcp_state == TCPS_FIN_WAIT);
    CHECK(tcp_track(&f, FINACK, ORIG));
    CHECK(f.tcp_state == TCPS_TIME_WAIT);
}

static void test_fin_retransmit_does_not_close(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, FINACK, ORIG));
    CHECK(tcp_track(&f, FINACK, ORIG));          /* same side again */
    CHECK(f.tcp_state == TCPS_FIN_WAIT);
}

static void test_rst_closes_from_any_state(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, TCP_RST, RESP));
    CHECK(f.tcp_state == TCPS_CLOSED);
    CHECK(!tcp_track(&f, ACK, ORIG));            /* nothing after RST */

    flow_t g = new_flow();                       /* connection refused */
    CHECK(tcp_track(&g, TCP_RST | TCP_ACK, RESP));
    CHECK(g.tcp_state == TCPS_CLOSED);
}

static void test_illegal_flag_combinations(void)
{
    flow_t f = established();
    CHECK(!tcp_track(&f, 0, ORIG));                      /* NULL scan   */
    CHECK(!tcp_track(&f, TCP_FIN, ORIG));                /* FIN scan    */
    CHECK(!tcp_track(&f, TCP_FIN | TCP_PSH | TCP_URG, ORIG)); /* Xmas   */
    CHECK(!tcp_track(&f, SYN | TCP_FIN, ORIG));
    CHECK(!tcp_track(&f, SYN | TCP_RST, ORIG));
    CHECK(!tcp_track(&f, TCP_FIN | TCP_RST, ORIG));
    CHECK(f.tcp_state == TCPS_ESTABLISHED);
}

static void test_new_syn_in_established_dropped(void)
{
    flow_t f = established();
    CHECK(!tcp_track(&f, SYN, ORIG));
    CHECK(!tcp_track(&f, SYN, RESP));
}

static void test_simultaneous_open(void)
{
    flow_t f = new_flow();
    CHECK(tcp_track(&f, SYN, RESP));             /* peer SYN crosses ours */
    CHECK(f.tcp_state == TCPS_SYN_RECV);
}

static void test_pure_syn_helper(void)
{
    CHECK(tcp_is_pure_syn(SYN));
    CHECK(!tcp_is_pure_syn(SYNACK));
    CHECK(!tcp_is_pure_syn(ACK));
    CHECK(!tcp_is_pure_syn(SYN | TCP_RST));
    /* a first packet is a SYN, optionally with the ECN bits; junk flags are not */
    CHECK(tcp_is_pure_syn(SYN | TCP_ECE | TCP_CWR));
    CHECK(!tcp_is_pure_syn(SYN | TCP_PSH));
    CHECK(!tcp_is_pure_syn(SYN | TCP_URG));
    CHECK(!tcp_is_pure_syn(SYN | TCP_PSH | TCP_URG));
    CHECK(!tcp_is_pure_syn(TCP_ECE | TCP_CWR));
}

static void test_simultaneous_open_with_synack_from_both_sides(void)
{
    /* Both ends connect at once: SYN crosses SYN, then each answers with
     * SYN-ACK. The originator's SYN-ACK used to be dropped. */
    flow_t f = new_flow();
    CHECK(tcp_track(&f, SYN, ORIG));
    CHECK(tcp_track(&f, SYN, RESP) && f.tcp_state == TCPS_SYN_RECV);
    CHECK(tcp_track(&f, SYNACK, ORIG));
    CHECK(tcp_track(&f, SYNACK, RESP));
    CHECK(tcp_track(&f, ACK, ORIG) && f.tcp_state == TCPS_ESTABLISHED);
    CHECK(tcp_track(&f, ACK, RESP));
    /* in SYN_SENT the originator may still only retransmit a bare SYN */
    flow_t g = new_flow();
    CHECK(!tcp_track(&g, SYNACK, ORIG));
    CHECK(g.tcp_state == TCPS_SYN_SENT);
}

static void test_closed_connection_cannot_carry_data(void)
{
    /* After both FINs the flow is TIME_WAIT: only payload-free ACKs (last-ACK
     * and FIN retransmits) make sense, never data, and never new handshakes. */
    flow_t f = established();
    tcp_track(&f, FINACK, ORIG);
    tcp_track(&f, FINACK, RESP);
    CHECK(f.tcp_state == TCPS_TIME_WAIT);
    CHECK(tcp_track_ex(&f, ACK, ORIG, 0));
    CHECK(tcp_track_ex(&f, FINACK, RESP, 0));              /* retransmitted FIN */
    CHECK(!tcp_track_ex(&f, ACK | TCP_PSH, ORIG, 100));    /* data from either side */
    CHECK(!tcp_track_ex(&f, ACK, RESP, 1));
    CHECK(!tcp_track_ex(&f, SYNACK, RESP, 0));
    CHECK(!tcp_track_ex(&f, SYN, ORIG, 0));
    CHECK(f.tcp_state == TCPS_TIME_WAIT);
    /* the 3-argument form means "no payload" */
    CHECK(tcp_track(&f, ACK, ORIG));
    /* payload is fine while the connection is open */
    flow_t e = established();
    CHECK(tcp_track_ex(&e, ACK | TCP_PSH, ORIG, 1400));
    CHECK(tcp_track_ex(&e, ACK | TCP_PSH, RESP, 1400));
}

static void test_syn_in_fin_wait_is_dropped(void)
{
    flow_t f = established();
    CHECK(tcp_track(&f, FINACK, ORIG) && f.tcp_state == TCPS_FIN_WAIT);
    CHECK(!tcp_track(&f, SYN, ORIG));
    CHECK(!tcp_track(&f, SYN, RESP));
    CHECK(!tcp_track(&f, SYNACK, RESP));
    CHECK(f.tcp_state == TCPS_FIN_WAIT);
}

static void test_each_state_has_its_own_timeout(void)
{
    flow_t f = new_flow();
    CHECK(flow_timeout_ns(&f) == 30 * SEC_NS);                 /* SYN_SENT */
    tcp_track(&f, SYNACK, RESP);
    CHECK(flow_timeout_ns(&f) == 30 * SEC_NS);                 /* SYN_RECV */
    tcp_track(&f, ACK, ORIG);
    CHECK(flow_timeout_ns(&f) == 3600 * SEC_NS);               /* ESTABLISHED */
    tcp_track(&f, FINACK, ORIG);
    /* One side has closed, the other may keep sending for as long as it likes
     * (ssh, rsync, a remote command after shutdown(WR)): same as established. */
    CHECK(f.tcp_state == TCPS_FIN_WAIT);
    CHECK(flow_timeout_ns(&f) == 3600 * SEC_NS);
    tcp_track(&f, FINACK, RESP);
    CHECK(f.tcp_state == TCPS_TIME_WAIT);
    CHECK(flow_timeout_ns(&f) == 30 * SEC_NS);
    flow_t c = established();
    tcp_track(&c, TCP_RST, RESP);
    CHECK(c.tcp_state == TCPS_CLOSED);
    CHECK(flow_timeout_ns(&c) == 5 * SEC_NS);
}

static void test_timeouts_depend_on_state(void)
{
    flow_t f = new_flow();
    uint64_t syn_to = flow_timeout_ns(&f);
    f = established();
    uint64_t est_to = flow_timeout_ns(&f);
    CHECK(est_to > syn_to);
    f.tcp_state = TCPS_CLOSED;
    CHECK(flow_timeout_ns(&f) < syn_to);
}

static void test_timeouts_match_the_spec(void)
{
    /* spec 4.5: half-open 30 s, established 1 hour, UDP 30-120 s, ICMP 30 s */
    flow_t f = new_flow();
    CHECK(flow_timeout_ns(&f) == 30 * SEC);                 /* SYN_SENT */
    f = established();
    CHECK(flow_timeout_ns(&f) == 3600 * SEC);

    flow_t u;
    memset(&u, 0, sizeof u);
    u.key.proto = FW_PROTO_UDP;
    CHECK(flow_timeout_ns(&u) == 30 * SEC);                 /* no reply yet */
    u.seen_reply = true;
    CHECK(flow_timeout_ns(&u) == 120 * SEC);

    flow_t i;
    memset(&i, 0, sizeof i);
    i.key.proto = FW_PROTO_ICMP;
    CHECK(flow_timeout_ns(&i) == 30 * SEC);
}

static void test_syn_recv_retransmits_and_illegal_packets(void)
{
    flow_t f = new_flow();
    tcp_track(&f, SYN, ORIG);
    CHECK(tcp_track(&f, SYNACK, RESP) && f.tcp_state == TCPS_SYN_RECV);

    /* the server's SYN-ACK is retransmitted (our ACK was lost): fine */
    CHECK(tcp_track(&f, SYNACK, RESP));
    CHECK(f.tcp_state == TCPS_SYN_RECV);
    /* but nothing else from the server makes sense before the handshake ends */
    CHECK(!tcp_track(&f, ACK, RESP));
    CHECK(!tcp_track(&f, ACK | TCP_PSH, RESP));
    /* the client may retransmit its SYN, but cannot send SYN-ACK or bare PSH */
    CHECK(tcp_track(&f, SYN, ORIG));
    CHECK(!tcp_track(&f, TCP_PSH, ORIG));
    CHECK(f.tcp_state == TCPS_SYN_RECV);          /* illegal packets: no change */
    /* a SYN-ACK from the originator is simultaneous open: allowed, no change */
    CHECK(tcp_track(&f, SYNACK, ORIG));
    CHECK(f.tcp_state == TCPS_SYN_RECV);
    CHECK(tcp_track(&f, ACK, ORIG) && f.tcp_state == TCPS_ESTABLISHED);
}

static void test_corrupt_state_is_never_allowed(void)
{
    flow_t f = new_flow();
    f.tcp_state = (tcp_state_t)99;
    CHECK(!tcp_track(&f, ACK, ORIG));
    CHECK(!tcp_track(&f, ACK, RESP));
    f.tcp_state = TCPS_NONE;
    CHECK(!tcp_track(&f, ACK, ORIG));
    CHECK(flow_timeout_ns(&f) == 30 * SEC);       /* TCP flow with no state */
}

int main(void)
{
    RUN(test_three_way_handshake);
    RUN(test_data_flows_both_ways_when_established);
    RUN(test_data_before_handshake_dropped);
    RUN(test_syn_retransmit_ok);
    RUN(test_graceful_close);
    RUN(test_fin_from_responder_first);
    RUN(test_fin_retransmit_does_not_close);
    RUN(test_rst_closes_from_any_state);
    RUN(test_illegal_flag_combinations);
    RUN(test_new_syn_in_established_dropped);
    RUN(test_simultaneous_open);
    RUN(test_pure_syn_helper);
    RUN(test_simultaneous_open_with_synack_from_both_sides);
    RUN(test_closed_connection_cannot_carry_data);
    RUN(test_syn_in_fin_wait_is_dropped);
    RUN(test_each_state_has_its_own_timeout);
    RUN(test_timeouts_depend_on_state);
    RUN(test_timeouts_match_the_spec);
    RUN(test_syn_recv_retransmits_and_illegal_packets);
    RUN(test_corrupt_state_is_never_allowed);
    TEST_DONE();
}

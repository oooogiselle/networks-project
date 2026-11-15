#include "tcpstate.h"
#include "testutil.h"

#define SYN     TCP_SYN
#define SYNACK  (TCP_SYN | TCP_ACK)
#define ACK     TCP_ACK
#define FINACK  (TCP_FIN | TCP_ACK)
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
    CHECK(tcp_is_pure_syn(SYN | TCP_PSH));
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
    RUN(test_timeouts_depend_on_state);
    TEST_DONE();
}

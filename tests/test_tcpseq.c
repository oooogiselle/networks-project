/*=============================================================================
 * File Name:   test_tcpseq.c
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Unit tests for TCP sequence-number checks (tcpseq.c): the
 *              handshake, data both ways, window scaling, wraparound, blind
 *              RSTs and injected data, stale acks, and the edge cases (zero
 *              window probes, keepalives, Fast Open, simultaneous open).
 =============================================================================*/

#include "tcpseq.h"
#include "testutil.h"

#define CLIENT IP(10,0,1,2)
#define SERVER IP(10,0,2,3)
#define C_ISN  1000u
#define S_ISN  5000u

/* A segment from the originator (orig = true) or the responder. */
static pkt_t seg(bool orig, uint8_t flags, uint32_t seq, uint32_t ack,
                 uint16_t win, uint16_t len)
{
    pkt_t p = orig ? mk_tcp(CLIENT, 40000, SERVER, 80, flags)
                   : mk_tcp(SERVER, 80, CLIENT, 40000, flags);
    p.tcp_seq = seq;
    p.tcp_ack = ack;
    p.tcp_win = win;
    p.payload_len = len;
    p.tcp_wscale = TCP_NO_WSCALE;
    return p;
}

/* What the engine does: check, and record the segment only if it passes. */
static bool step(flow_t *f, pkt_t p, bool orig)
{
    if (!tcpseq_check(f, &p, orig)) return false;
    tcpseq_update(f, &p, orig);
    return true;
}

/* A flow after SYN (wscale c_ws) / SYN-ACK (wscale s_ws) / ACK, with
 * windows of 64240 (client SYN), 65160 (server SYN-ACK) and 502 (ACK). */
static flow_t handshake(uint8_t c_ws, uint8_t s_ws)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 0);
    syn.tcp_wscale = c_ws;
    tcpseq_init(&f, &syn);
    pkt_t sa = seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0);
    sa.tcp_wscale = s_ws;
    CHECK(step(&f, sa, false));
    CHECK(step(&f, seg(true, TCP_ACK, C_ISN + 1, S_ISN + 1, 502, 0), true));
    return f;
}

static void test_handshake_sets_up_both_windows(void)
{
    flow_t f = handshake(TCP_NO_WSCALE, TCP_NO_WSCALE);
    CHECK(f.tw[0].init && f.tw[1].init);
    CHECK(f.tw[0].isn == C_ISN && f.tw[0].end == C_ISN + 1);
    CHECK(f.tw[1].isn == S_ISN && f.tw[1].end == S_ISN + 1);
    CHECK(f.tw[0].maxwin == 64240 && f.tw[1].maxwin == 65160);
    CHECK(f.tw[0].maxend == C_ISN + 1 + 65160);       /* what the server allowed */
    CHECK(f.tw[1].maxend == S_ISN + 1 + 64240);       /* from the client's SYN */
    CHECK(f.tw[0].scale == 0 && f.tw[1].scale == 0);
}

static void test_data_both_ways_and_close(void)
{
    flow_t f = handshake(TCP_NO_WSCALE, TCP_NO_WSCALE);
    uint32_t c = C_ISN + 1, s = S_ISN + 1;
    CHECK(step(&f, seg(true, TCP_ACK | TCP_PSH, c, s, 502, 100), true));        /* request */
    c += 100;
    for (int i = 0; i < 50; i++) {                                              /* response */
        CHECK(step(&f, seg(false, TCP_ACK, s, c, 65160, 1448), false));
        s += 1448;
        CHECK(step(&f, seg(true, TCP_ACK, c, s, 64240, 0), true));
    }
    CHECK(f.tw[1].end == s);
    CHECK(step(&f, seg(false, TCP_FIN | TCP_ACK, s, c, 65160, 0), false));      /* FIN counts 1 */
    CHECK(f.tw[1].end == s + 1);
    CHECK(step(&f, seg(true, TCP_FIN | TCP_ACK, c, s + 1, 64240, 0), true));
    CHECK(step(&f, seg(false, TCP_ACK, s + 1, c + 1, 65160, 0), false));        /* last ACK */
    CHECK(!step(&f, seg(false, TCP_ACK, s + 1, c + 2, 65160, 0), false));       /* past the FIN */
}

static void test_blind_rst_is_refused_and_an_in_window_rst_accepted(void)
{
    flow_t f = handshake(TCP_NO_WSCALE, TCP_NO_WSCALE);
    const uint32_t s = S_ISN + 1;
    /* guesses far from the server's sequence numbers, either side */
    CHECK(!step(&f, seg(false, TCP_RST, s + 0x80000000u, 0, 0, 0), false));
    CHECK(!step(&f, seg(false, TCP_RST, 0x12345678u, 0, 0, 0), false));
    CHECK(!step(&f, seg(false, TCP_RST, s + 64240 + 1, 0, 0, 0), false));     /* just past */
    CHECK(!step(&f, seg(false, TCP_RST, s - 65160 - 1, 0, 0, 0), false));     /* just behind */
    CHECK(!step(&f, seg(true, TCP_RST, 0x9abcdef0u, 0, 0, 0), true));
    /* a blind RST|ACK must also get the ack right */
    CHECK(!step(&f, seg(false, TCP_RST | TCP_ACK, s, C_ISN + 5000, 0, 0), false));
    /* the real thing: at the server's next sequence number */
    CHECK(step(&f, seg(false, TCP_RST, s, 0, 0, 0), false));
    CHECK(step(&f, seg(false, TCP_RST | TCP_ACK, s, C_ISN + 1, 0, 0), false));
}

static void test_injected_data_outside_the_window_is_refused(void)
{
    flow_t f = handshake(TCP_NO_WSCALE, TCP_NO_WSCALE);
    const uint32_t c = C_ISN + 1, s = S_ISN + 1;
    /* beyond what the client allowed the server */
    CHECK(!step(&f, seg(false, TCP_ACK | TCP_PSH, s + 64240 + 1, c, 65160, 10), false));
    CHECK(!step(&f, seg(false, TCP_ACK | TCP_PSH, s + 1000000, c, 65160, 10), false));
    /* acking data the client never sent */
    CHECK(!step(&f, seg(false, TCP_ACK | TCP_PSH, s, c + 1, 65160, 10), false));
    /* a zero-window probe at exactly the edge is fine */
    CHECK(step(&f, seg(false, TCP_ACK, s + 64240, c, 65160, 1), false));
    CHECK(f.tw[0].maxwin == 64240);           /* refused segments changed nothing */
}

static void test_retransmissions_and_stale_segments(void)
{
    flow_t f = handshake(TCP_NO_WSCALE, TCP_NO_WSCALE);
    const uint32_t c = C_ISN + 1;
    uint32_t s = S_ISN + 1;
    for (int i = 0; i < 200; i++) {                       /* 200 kB from the server */
        CHECK(step(&f, seg(false, TCP_ACK, s, c, 65160, 1000), false));
        s += 1000;
        CHECK(step(&f, seg(true, TCP_ACK, c, s, 64240, 0), true));
    }
    /* a retransmission from inside the last window passes, and does not move
     * the end back */
    CHECK(step(&f, seg(false, TCP_ACK, s - 10000, c, 65160, 1000), false));
    CHECK(f.tw[1].end == s);
    /* a segment from more than a window (the client's 64240) ago does not */
    CHECK(!step(&f, seg(false, TCP_ACK, s - 70000, c, 65160, 1000), false));
    /* a keepalive (one byte before the end, no data) passes */
    CHECK(step(&f, seg(false, TCP_ACK, s - 1, c, 65160, 0), false));
    /* acks: recent ones pass, one more than 66000 behind does not */
    CHECK(step(&f, seg(true, TCP_ACK, c, s - 60000, 64240, 0), true));
    CHECK(!step(&f, seg(true, TCP_ACK, c, s - 70000, 64240, 0), true));
}

static void test_window_scaling_needs_both_sides(void)
{
    /* both offered: the client's windows are shifted by 7 after the SYNs */
    flow_t f = handshake(7, 7);
    CHECK(f.tw[0].scale == 7 && f.tw[1].scale == 7);
    CHECK(f.tw[0].maxwin == 502u << 7);                    /* the ACK's 502, scaled */
    const uint32_t c = C_ISN + 1, s = S_ISN + 1;
    CHECK(step(&f, seg(true, TCP_ACK, c, s, 1000, 0), true));        /* allows 128000 */
    CHECK(f.tw[1].maxend == s + (1000u << 7));
    CHECK(step(&f, seg(false, TCP_ACK, s + 100000, c, 509, 1000), false));
    CHECK(!step(&f, seg(false, TCP_ACK, s + 128001, c, 509, 1000), false));

    /* only one side offered it: no scaling at all, so the same window allows
     * only 1000 bytes */
    flow_t g = handshake(7, TCP_NO_WSCALE);
    CHECK(g.tw[0].scale == 0 && g.tw[1].scale == 0);
    CHECK(step(&g, seg(true, TCP_ACK, c, s, 1000, 0), true));
    CHECK(!step(&g, seg(false, TCP_ACK, s + 100000, c, 509, 1000), false));
    flow_t h = handshake(TCP_NO_WSCALE, 7);
    CHECK(h.tw[0].scale == 0 && h.tw[1].scale == 0);
}

static void test_sequence_numbers_wrap(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    const uint32_t ci = 0xffffff00u, si = 0xfffffff0u;
    pkt_t syn = seg(true, TCP_SYN, ci, 0, 64240, 0);
    tcpseq_init(&f, &syn);
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, si, ci + 1, 65160, 0), false));
    uint32_t c = ci + 1, s = si + 1;
    CHECK(step(&f, seg(true, TCP_ACK, c, s, 64240, 0), true));
    for (int i = 0; i < 10; i++) {                         /* both cross 2^32 */
        CHECK(step(&f, seg(true, TCP_ACK, c, s, 64240, 500), true));
        c += 500;
        CHECK(step(&f, seg(false, TCP_ACK, s, c, 65160, 500), false));
        s += 500;
    }
    CHECK(c < ci && s < si);                               /* they did wrap */
    CHECK(f.tw[0].end == c && f.tw[1].end == s);
    CHECK(!step(&f, seg(false, TCP_RST, s + 0x40000000u, 0, 0, 0), false));
    CHECK(step(&f, seg(false, TCP_RST, s, 0, 0, 0), false));
}

static void test_the_syn_ack_must_acknowledge_the_syn(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 0, 0);       /* window 0 counts as 1 */
    tcpseq_init(&f, &syn);
    CHECK(f.tw[0].maxwin == 1);
    CHECK(!step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN, 65160, 0), false));
    CHECK(!step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 2, 65160, 0), false));
    CHECK(!f.tw[1].init);
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0), false));
    /* a retransmitted SYN-ACK has the same ISN; a different one is forged */
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0), false));
    CHECK(!step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN + 7, C_ISN + 1, 65160, 0), false));
    /* and the client's SYN again, once answered, must be the same SYN */
    CHECK(step(&f, seg(true, TCP_SYN, C_ISN, 0, 64240, 0), true));
    CHECK(!step(&f, seg(true, TCP_SYN, C_ISN + 99, 0, 64240, 0), true));
}

static void test_before_the_answer(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 0);
    tcpseq_init(&f, &syn);
    /* The server refusing: the RST must acknowledge the SYN (RFC 793). */
    CHECK(!step(&f, seg(false, TCP_RST, 0, 0, 0, 0), false));                   /* no ACK */
    CHECK(!step(&f, seg(false, TCP_RST | TCP_ACK, 0, C_ISN + 2, 0, 0), false));
    CHECK(step(&f, seg(false, TCP_RST | TCP_ACK, 0, C_ISN + 1, 0, 0), false));
    CHECK(!f.tw[1].init);                                    /* an RST sets nothing up */
    /* nothing else may come from the server before its SYN */
    CHECK(!step(&f, seg(false, TCP_ACK, S_ISN, C_ISN + 1, 65160, 10), false));
    /* the client aborting: an RST at its next sequence number */
    CHECK(step(&f, seg(true, TCP_RST, C_ISN + 1, 0, 0, 0), true));
    CHECK(!step(&f, seg(true, TCP_RST, C_ISN + 5000, 0, 0, 0), true));
    CHECK(!step(&f, seg(true, TCP_ACK, C_ISN + 1, S_ISN + 1, 64240, 0), true));
}

static void test_syn_retransmit_with_a_new_isn_starts_over(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 0);
    tcpseq_init(&f, &syn);
    CHECK(step(&f, seg(true, TCP_SYN, 7000, 0, 64240, 0), true));
    CHECK(f.tw[0].isn == 7000 && f.tw[0].end == 7001);
    CHECK(!step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0), false));
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, 7001, 65160, 0), false));
}

static void test_fast_open_syn_data(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 20);   /* 20 bytes of data */
    tcpseq_init(&f, &syn);
    CHECK(f.tw[0].end == C_ISN + 21);
    CHECK(!step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 22, 65160, 0), false));
    /* the server may ack only the SYN (data not accepted)... */
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0), false));
    /* ...and the client then sends the data again */
    CHECK(step(&f, seg(true, TCP_ACK | TCP_PSH, C_ISN + 1, S_ISN + 1, 502, 20), true));
    flow_t g;
    memset(&g, 0, sizeof g);
    tcpseq_init(&g, &syn);
    CHECK(step(&g, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 21, 65160, 0), false));
}

static void test_simultaneous_open(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 0);
    syn.tcp_wscale = 5;
    tcpseq_init(&f, &syn);
    pkt_t other = seg(false, TCP_SYN, S_ISN, 0, 65160, 0);    /* SYN, no ACK */
    other.tcp_wscale = 6;
    CHECK(step(&f, other, false));
    CHECK(f.tw[1].init && f.tw[0].scale == 5 && f.tw[1].scale == 6);
    /* each side then answers with a SYN-ACK that acknowledges the other */
    CHECK(!step(&f, seg(true, TCP_SYN | TCP_ACK, C_ISN, S_ISN + 9, 64240, 0), true));
    CHECK(step(&f, seg(true, TCP_SYN | TCP_ACK, C_ISN, S_ISN + 1, 64240, 0), true));
    CHECK(step(&f, seg(false, TCP_SYN | TCP_ACK, S_ISN, C_ISN + 1, 65160, 0), false));
    CHECK(step(&f, seg(true, TCP_ACK, C_ISN + 1, S_ISN + 1, 100, 10), true));
}

static void test_refused_segments_and_rsts_change_nothing(void)
{
    flow_t f;
    memset(&f, 0, sizeof f);
    pkt_t syn = seg(true, TCP_SYN, C_ISN, 0, 64240, 0);
    tcpseq_init(&f, &syn);
    const flow_t before = f;
    /* updating with an RST before the handshake leaves the windows alone */
    pkt_t rst = seg(false, TCP_RST | TCP_ACK, 0, C_ISN + 1, 0, 0);
    tcpseq_update(&f, &rst, false);
    pkt_t abort = seg(true, TCP_RST, C_ISN + 1, 0, 0, 0);
    tcpseq_update(&f, &abort, true);
    CHECK(memcmp(&before.tw, &f.tw, sizeof f.tw) == 0);
}

int main(void)
{
    RUN(test_handshake_sets_up_both_windows);
    RUN(test_data_both_ways_and_close);
    RUN(test_blind_rst_is_refused_and_an_in_window_rst_accepted);
    RUN(test_injected_data_outside_the_window_is_refused);
    RUN(test_retransmissions_and_stale_segments);
    RUN(test_window_scaling_needs_both_sides);
    RUN(test_sequence_numbers_wrap);
    RUN(test_the_syn_ack_must_acknowledge_the_syn);
    RUN(test_before_the_answer);
    RUN(test_syn_retransmit_with_a_new_isn_starts_over);
    RUN(test_fast_open_syn_data);
    RUN(test_simultaneous_open);
    RUN(test_refused_segments_and_rsts_change_nothing);
    TEST_DONE();
}

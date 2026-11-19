/*=============================================================================
 * File Name:   test_reject.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Unit tests for the reject answers (reject.h). Every answer is
 *              run back through parse_packet(), so a wrong checksum or length
 *              anywhere fails the test the same way it would fail on a host.
 =============================================================================*/

#include <string.h>

#include "engine.h"
#include "parser.h"
#include "pktbuild.h"
#include "reject.h"
#include "testutil.h"

#define CLIENT IP4(10, 0, 1, 2)
#define SERVER IP4(10, 0, 2, 2)

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Build the answer to orig and parse it; the answer must be valid. */
static size_t answer(const uint8_t *orig, size_t n, uint8_t *out, pkt_t *p)
{
    size_t m = reject_build(orig, n, out, REJECT_MAX_LEN);
    CHECK(m > 0);
    if (m == 0) return 0;
    CHECK(parse_packet(out, m, p) == PARSE_OK);   /* every checksum is right */
    CHECK(out[8] == 64);                          /* a fresh TTL */
    return m;
}

static void test_a_syn_gets_a_rst_ack_that_acknowledges_it(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    pkt_t p;
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_SYN, NULL, 0);
    size_t m = answer(b, n, out, &p);
    CHECK(m == 40);
    CHECK(p.proto == FW_PROTO_TCP && p.src_ip == SERVER && p.dst_ip == CLIENT);
    CHECK(p.src_port == 23 && p.dst_port == 40000);
    CHECK(p.tcp_flags == (TCP_RST | TCP_ACK));
    CHECK(rd32(out + 24) == 0);                          /* seq */
    CHECK(rd32(out + 28) == rd32(b + 24) + 1);           /* ack = their seq + SYN */
}

static void test_data_and_fin_count_in_the_acknowledgement(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    pkt_t p;
    struct pb_opts o = { .tcp_opt_len = 12, .ip_opt_len = 8 };   /* options move the headers */
    size_t n = pb_tcp(b, sizeof b, &o, CLIENT, 40000, SERVER, 23, TCP_SYN | TCP_FIN, "hello", 5);
    if (!answer(b, n, out, &p)) return;
    const uint32_t seq = rd32(b + 28 + 4);               /* TCP header after 28 bytes of IP */
    CHECK(rd32(out + 28) == seq + 5 + 1 + 1);
    CHECK(p.tcp_flags == (TCP_RST | TCP_ACK));
}

static void test_a_packet_with_ack_gets_a_bare_rst_at_its_ack(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    pkt_t p;
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_ACK | TCP_PSH, "x", 1);
    if (!answer(b, n, out, &p)) return;
    CHECK(p.tcp_flags == TCP_RST);
    CHECK(rd32(out + 24) == rd32(b + 28));               /* seq = their ack */
}

static void test_a_rst_is_never_answered(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_RST, NULL, 0);
    CHECK(reject_build(b, n, out, sizeof out) == 0);
    n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_RST | TCP_ACK, NULL, 0);
    CHECK(reject_build(b, n, out, sizeof out) == 0);
}

static void test_udp_gets_port_unreachable_quoting_the_datagram(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    pkt_t p, inner;
    struct pb_opts o = { .ip_opt_len = 8 };
    size_t n = pb_udp(b, sizeof b, &o, CLIENT, 5000, SERVER, 69, "tftp read", 9);
    size_t m = answer(b, n, out, &p);
    CHECK(m == 20 + 8 + 28 + 8);                         /* the IP options are quoted too */
    CHECK(p.proto == FW_PROTO_ICMP && p.icmp_type == ICMP_DEST_UNREACH && out[21] == ICMP_CODE_PORT_UNREACH);
    CHECK(p.src_ip == SERVER && p.dst_ip == CLIENT);
    CHECK(parse_icmp_inner(&p, &inner) == PARSE_OK);     /* a host can match it to its socket */
    CHECK(inner.proto == FW_PROTO_UDP && inner.src_ip == CLIENT && inner.dst_ip == SERVER);
    CHECK(inner.src_port == 5000 && inner.dst_port == 69);
}

static void test_an_echo_request_gets_admin_prohibited(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    pkt_t p, inner;
    size_t n = pb_icmp_echo(b, sizeof b, NULL, CLIENT, SERVER, ICMP_ECHO_REQUEST, 77, 1, "ping", 4);
    if (!answer(b, n, out, &p)) return;
    CHECK(p.icmp_type == ICMP_DEST_UNREACH && out[21] == ICMP_CODE_ADMIN_PROHIB);
    CHECK(parse_icmp_inner(&p, &inner) == PARSE_OK);
    CHECK(inner.proto == FW_PROTO_ICMP && inner.src_ip == CLIENT && inner.src_port == 77);
}

static void test_icmp_replies_and_errors_are_never_answered(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN], orig[256];
    size_t n = pb_icmp_echo(b, sizeof b, NULL, CLIENT, SERVER, ICMP_ECHO_REPLY, 77, 1, NULL, 0);
    CHECK(reject_build(b, n, out, sizeof out) == 0);
    size_t on = pb_udp(orig, sizeof orig, NULL, SERVER, 69, CLIENT, 5000, NULL, 0);
    n = pb_icmp_error(b, sizeof b, NULL, CLIENT, SERVER, ICMP_DEST_UNREACH, 3, orig, on);
    CHECK(reject_build(b, n, out, sizeof out) == 0);
}

static void test_bad_input_and_a_small_buffer_give_nothing(void)
{
    uint8_t b[256], out[REJECT_MAX_LEN];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_SYN, NULL, 0);
    CHECK(reject_build(b, n, out, 39) == 0);             /* a RST needs 40 */
    CHECK(reject_build(b, n, out, 40) == 40);
    CHECK(reject_build(b, 30, out, sizeof out) == 0);    /* truncated TCP header */
    CHECK(reject_build(b, 10, out, sizeof out) == 0);    /* not even an IP header */
    CHECK(reject_build(NULL, n, out, sizeof out) == 0);
    b[0] = 0x65;                                         /* IPv6 version nibble */
    CHECK(reject_build(b, n, out, sizeof out) == 0);
    b[0] = 0x44;                                         /* IHL 16 < 20 */
    CHECK(reject_build(b, n, out, sizeof out) == 0);
    n = pb_udp(b, sizeof b, NULL, CLIENT, 5000, SERVER, 69, NULL, 0);
    CHECK(reject_build(b, n, out, 20 + 8 + 27) == 0);    /* the quote needs 28 */
    CHECK(reject_build(b, 27, out, sizeof out) == 0);    /* less than IP + 8 to quote */
    b[9] = 47;                                           /* GRE: not ours to answer */
    CHECK(reject_build(b, n, out, sizeof out) == 0);
    n = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 23, TCP_SYN, NULL, 0);
    b[32] = 0xf0;                                        /* data offset 60 > packet */
    CHECK(reject_build(b, n, out, sizeof out) == 0);
}

int main(void)
{
    RUN(test_a_syn_gets_a_rst_ack_that_acknowledges_it);
    RUN(test_data_and_fin_count_in_the_acknowledgement);
    RUN(test_a_packet_with_ack_gets_a_bare_rst_at_its_ack);
    RUN(test_a_rst_is_never_answered);
    RUN(test_udp_gets_port_unreachable_quoting_the_datagram);
    RUN(test_an_echo_request_gets_admin_prohibited);
    RUN(test_icmp_replies_and_errors_are_never_answered);
    RUN(test_bad_input_and_a_small_buffer_give_nothing);
    TEST_DONE();
}

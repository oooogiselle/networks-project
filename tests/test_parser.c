/*=============================================================================
 * File Name:   test_parser.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Unit tests for the packet parser: valid packets, every kind of
 *              malformed input, checksum errors, and ICMP error inner packets.
 =============================================================================*/

/* test_parser.c - packet parser and checksum tests. */
#include <stdlib.h>
#include <string.h>

#include "engine.h"
#include "parser.h"
#include "pktbuild.h"
#include "rules.h"
#include "testutil.h"

#define CHECK_EQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_run++; if (a_ != b_) { t_fail++; \
    fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld != %lld)\n", \
            __FILE__, __LINE__, #a, #b, a_, b_); } } while (0)

#define CLIENT_A IP4(10, 0, 1, 2)
#define CLIENT_B IP4(10, 0, 1, 3)
#define SERVER   IP4(10, 0, 2, 2)
#define ATTACKER IP4(10, 0, 2, 3)
#define ROUTER   IP4(10, 0, 2, 1)

/*
 * Parse a copy of src[0..n) held in an exact-size heap buffer, so ASan
 * catches any read past the end. Only the return code is meaningful (the
 * payload pointer dangles once the copy is freed).
 */
static parse_result_t parse_exact(const uint8_t *src, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1);
    if (!copy)
        abort();
    if (n)
        memcpy(copy, src, n);
    pkt_t p;
    parse_result_t r = parse_packet(copy, n, &p);
    if (r == PARSE_OK) {
        /* Invariants every successful parse must satisfy. */
        CHECK_EQ(p.ip_len, n);
        if (p.payload) {
            CHECK(p.payload_len > 0);
            CHECK(p.payload >= copy + 28);
            CHECK(p.payload + p.payload_len == copy + n);
        } else {
            CHECK_EQ(p.payload_len, 0);
        }
    }
    free(copy);
    return r;
}

/* ---- checksums ------------------------------------------------------------ */

static void csum_rfc1071_example(void)
{
    /* RFC 1071 section 3: these words sum to 0xddf2, checksum 0x220d. */
    const uint8_t d[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK_EQ(csum_fold(csum_partial(d, sizeof d, 0)), 0x220d);
}

static void csum_odd_length_pads_with_zero(void)
{
    const uint8_t odd[] = {0x12, 0x34, 0x56};
    const uint8_t even[] = {0x12, 0x34, 0x56, 0x00};
    CHECK_EQ(csum_fold(csum_partial(odd, 3, 0)),
             csum_fold(csum_partial(even, 4, 0)));
}

static void csum_large_input_does_not_overflow(void)
{
    static uint8_t big[65535];
    memset(big, 0xff, sizeof big);
    /* 0xffff is -0 in one's complement, so any number of them sums to 0xffff
     * and complements to 0. Odd tail byte 0xff pads to 0xff00. */
    CHECK_EQ(csum_fold(csum_partial(big, 65534, 0)), 0x0000);
    CHECK_EQ(csum_fold(csum_partial(big, 65535, 0)),
             csum_fold(0xffff + 0xff00));
}

/* ---- valid packets ------------------------------------------------------------ */

static void tcp_syn_fields(void)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 40000, SERVER, 80,
                      TCP_SYN, NULL, 0);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.ip_len, 40);
    CHECK_EQ(p.proto, FW_PROTO_TCP);
    CHECK_EQ(p.src_ip, CLIENT_A);
    CHECK_EQ(p.dst_ip, SERVER);
    CHECK_EQ(p.src_port, 40000);
    CHECK_EQ(p.dst_port, 80);
    CHECK_EQ(p.tcp_flags, TCP_SYN);
    CHECK_EQ(p.icmp_type, 0);
    CHECK(p.payload == NULL);
    CHECK_EQ(p.payload_len, 0);
}

static void tcp_with_options_and_payload(void)
{
    uint8_t b[256];
    struct pb_opts o = {.ip_opt_len = 4, .tcp_opt_len = 12};
    const char *body = "GET / HTTP/1.1\r\n\r\n";
    size_t n = pb_tcp(b, sizeof b, &o, CLIENT_A, 40000, SERVER, 443,
                      TCP_ACK | TCP_PSH, body, strlen(body));
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK(p.payload == b + 24 + 32);
    CHECK_EQ(p.payload_len, strlen(body));
    CHECK(memcmp(p.payload, body, p.payload_len) == 0);
    CHECK_EQ(p.tcp_flags, TCP_ACK | TCP_PSH);
}

static void tcp_odd_length_payload(void)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1234, SERVER, 80,
                      TCP_ACK, "abc", 3);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.payload_len, 3);
}

static void udp_fields(void)
{
    uint8_t b[128];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 5353, SERVER, 53,
                      "query", 5);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.proto, FW_PROTO_UDP);
    CHECK_EQ(p.src_port, 5353);
    CHECK_EQ(p.dst_port, 53);
    CHECK_EQ(p.tcp_flags, 0);
    CHECK(p.payload == b + 28);
    CHECK_EQ(p.payload_len, 5);
}

static void udp_zero_checksum_accepted(void)
{
    uint8_t b[128];
    struct pb_opts o = {.udp_no_csum = 1};
    size_t n = pb_udp(b, sizeof b, &o, CLIENT_A, 5353, SERVER, 53, "q", 1);
    CHECK_EQ(b[20 + 6], 0);
    CHECK_EQ(b[20 + 7], 0);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
}

static void udp_empty_payload(void)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK(p.payload == NULL);
    CHECK_EQ(p.payload_len, 0);
}

static void icmp_echo_uses_identifier_as_ports(void)
{
    uint8_t b[128];
    size_t n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER,
                            ICMP_ECHO_REQUEST, 0xbeef, 1, "ping", 4);
    pkt_t p;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.proto, FW_PROTO_ICMP);
    CHECK_EQ(p.icmp_type, ICMP_ECHO_REQUEST);
    CHECK_EQ(p.src_port, 0xbeef);
    CHECK_EQ(p.dst_port, 0xbeef);
    CHECK_EQ(p.payload_len, 4);

    n = pb_icmp_echo(b, sizeof b, NULL, SERVER, CLIENT_A, ICMP_ECHO_REPLY,
                     0xbeef, 1, "ping", 4);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.icmp_type, ICMP_ECHO_REPLY);
    CHECK_EQ(p.src_port, 0xbeef);
}

/* ---- ICMP errors ---------------------------------------------------------- */

static void icmp_time_exceeded_exposes_original_udp(void)
{
    uint8_t orig[128], b[256];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 33434, SERVER, 33435,
           "traceroute", 10);
    /* RFC 792 minimum: original IP header + 8 bytes. */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_TIME_EXCEEDED, 0, orig, 28);

    pkt_t p, in;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(p.icmp_type, ICMP_TIME_EXCEEDED);
    CHECK(icmp_is_error(p.icmp_type));
    CHECK_EQ(p.src_port, 0);
    CHECK_EQ(p.dst_port, 0);
    CHECK(p.payload == b + 28);
    CHECK_EQ(p.payload_len, 28);

    CHECK_EQ(parse_icmp_inner(&p, &in), PARSE_OK);
    CHECK_EQ(in.proto, FW_PROTO_UDP);
    CHECK_EQ(in.src_ip, CLIENT_A);
    CHECK_EQ(in.dst_ip, SERVER);
    CHECK_EQ(in.src_port, 33434);
    CHECK_EQ(in.dst_port, 33435);
    CHECK(in.payload == NULL);
}

static void icmp_unreachable_with_full_tcp_original(void)
{
    uint8_t orig[128], b[256];
    size_t on = pb_tcp(orig, sizeof orig, NULL, CLIENT_A, 40000, SERVER, 81,
                       TCP_SYN, NULL, 0);
    size_t n = pb_icmp_error(b, sizeof b, NULL, SERVER, CLIENT_A,
                             ICMP_DEST_UNREACH, 3, orig, on);
    pkt_t p, in;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(parse_icmp_inner(&p, &in), PARSE_OK);
    CHECK_EQ(in.proto, FW_PROTO_TCP);
    CHECK_EQ(in.src_port, 40000);
    CHECK_EQ(in.dst_port, 81);
    CHECK_EQ(in.tcp_flags, 0);
}

static void icmp_error_about_echo(void)
{
    uint8_t orig[64], b[128];
    pb_icmp_echo(orig, sizeof orig, NULL, CLIENT_A, SERVER,
                 ICMP_ECHO_REQUEST, 77, 1, NULL, 0);
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_TIME_EXCEEDED, 0, orig, 28);
    pkt_t p, in;
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(parse_icmp_inner(&p, &in), PARSE_OK);
    CHECK_EQ(in.proto, FW_PROTO_ICMP);
    CHECK_EQ(in.icmp_type, ICMP_ECHO_REQUEST);
    CHECK_EQ(in.src_port, 77);
}

static void icmp_error_inner_too_short(void)
{
    uint8_t orig[64], b[128];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);
    for (size_t embed = 0; embed < 28; embed++) {
        size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                                 ICMP_DEST_UNREACH, 1, orig, embed);
        CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    }
}

static void icmp_error_inner_bad_header(void)
{
    uint8_t orig[64], b[128], bad[64];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);

    memcpy(bad, orig, 28);
    bad[0] = 0x65; /* version 6 */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);

    memcpy(bad, orig, 28);
    bad[0] = 0x44; /* IHL 16 bytes */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);

    memcpy(bad, orig, 28);
    bad[0] = 0x46; /* IHL 24: needs 32 embedded bytes, only 28 present */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
}

static void icmp_error_inner_fragment_and_unsupported(void)
{
    uint8_t orig[64], b[128], bad[64];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);

    memcpy(bad, orig, 28);
    pb_wr16(bad + 6, 0x0010); /* non-first fragment */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_FRAGMENT);

    memcpy(bad, orig, 28);
    bad[9] = 47; /* GRE */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);

    /* An error about an error is never valid. */
    uint8_t err[64];
    pb_icmp_error(err, sizeof err, NULL, SERVER, CLIENT_A,
                  ICMP_DEST_UNREACH, 1, orig, 28);
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_TIME_EXCEEDED, 0, err, 28);
    CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);
}

static void parse_inner_rejects_non_error(void)
{
    uint8_t b[64];
    pkt_t p, in;

    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "xxxxxxxx", 8);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(parse_icmp_inner(&p, &in), PARSE_MALFORMED);

    n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST,
                     1, 1, NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(parse_icmp_inner(&p, &in), PARSE_MALFORMED);
    CHECK_EQ(parse_icmp_inner(NULL, &in), PARSE_MALFORMED);
}

static void icmp_unsupported_types(void)
{
    const uint8_t types[] = {4, 5, 9, 10, 13, 14, 17, 18, 42, 255};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof types; i++) {
        size_t n = pb_icmp_echo(b, sizeof b, NULL, SERVER, CLIENT_A,
                                types[i], 1, 1, NULL, 0);
        CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);
    }
}

/* ---- IP layer defects ----------------------------------------------------- */

static void empty_null_and_ipv6(void)
{
    pkt_t p;
    uint8_t one = 0x45;
    CHECK_EQ(parse_packet(NULL, 40, &p), PARSE_MALFORMED);
    CHECK_EQ(parse_packet(&one, 0, &p), PARSE_MALFORMED);
    CHECK_EQ(parse_exact(&one, 1), PARSE_MALFORMED);

    uint8_t v6[40] = {0x60};
    CHECK_EQ(parse_exact(v6, sizeof v6), PARSE_UNSUPPORTED);
    uint8_t v0[40] = {0x05};
    CHECK_EQ(parse_exact(v0, sizeof v0), PARSE_UNSUPPORTED);
}

/* Every strict prefix of a valid packet must be rejected without overreads. */
static void check_all_truncations(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        CHECK(parse_exact(b, i) != PARSE_OK);
    CHECK_EQ(parse_exact(b, n), PARSE_OK);
}

static void truncated_packets_rejected(void)
{
    uint8_t b[256], orig[64];
    size_t n;
    struct pb_opts o = {.ip_opt_len = 8, .tcp_opt_len = 8};

    n = pb_tcp(b, sizeof b, &o, CLIENT_A, 1, SERVER, 2, TCP_SYN, "xy", 2);
    check_all_truncations(b, n);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "hello", 5);
    check_all_truncations(b, n);
    n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER,
                     ICMP_ECHO_REQUEST, 1, 1, "abc", 3);
    check_all_truncations(b, n);
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_TIME_EXCEEDED, 0, orig, 28);
    check_all_truncations(b, n);
}

static void trailing_bytes_rejected(void)
{
    uint8_t b[128] = {0};
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "x", 1);
    CHECK_EQ(parse_exact(b, n + 1), PARSE_MALFORMED);
    CHECK_EQ(parse_exact(b, n + 10), PARSE_MALFORMED);
}

static void oversized_buffer_rejected(void)
{
    static uint8_t big[70000];
    size_t n = pb_udp(big, sizeof big, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    CHECK(n > 0);
    CHECK_EQ(parse_exact(big, sizeof big), PARSE_MALFORMED);

    /* Largest legal packet still parses. */
    static uint8_t pl[65535 - 28];
    n = pb_udp(big, sizeof big, NULL, CLIENT_A, 1, SERVER, 2, pl, sizeof pl);
    CHECK_EQ(n, 65535);
    CHECK_EQ(parse_exact(big, n), PARSE_OK);
}

static void bad_ihl(void)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    for (uint8_t ihl = 0; ihl < 5; ihl++) {
        b[0] = (uint8_t)(0x40 | ihl);
        CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    }
    /* IHL claims 60 bytes but total length is 40. */
    b[0] = 0x4f;
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
}

static void bad_total_length(void)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    pb_wr16(b + 2, (uint16_t)(n + 1));
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    pb_wr16(b + 2, (uint16_t)(n - 1));
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    pb_wr16(b + 2, 19);
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
}

static void bad_checksums(void)
{
    uint8_t b[128];
    size_t n;

    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN, NULL, 0);
    b[10] ^= 0x01; /* IP header checksum */
    CHECK_EQ(parse_exact(b, n), PARSE_BAD_CSUM);

    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_ACK, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), PARSE_BAD_CSUM);

    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), PARSE_BAD_CSUM);

    n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST,
                     1, 1, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), PARSE_BAD_CSUM);
}

static void pseudo_header_covers_addresses(void)
{
    /* Rewriting the source address and fixing only the IP checksum must
     * break the TCP checksum (it covers the pseudo-header). */
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    pb_wr32(b + 12, CLIENT_B);
    pb_wr16(b + 10, 0);
    pb_wr16(b + 10, csum_fold(csum_partial(b, 20, 0)));
    CHECK_EQ(parse_exact(b, n), PARSE_BAD_CSUM);
}

static void fragments_rejected(void)
{
    uint8_t b[128];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "x", 1);

    pb_wr16(b + 6, 0x2000); /* MF */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_FRAGMENT);

    pb_wr16(b + 6, 0x0001); /* offset 8 bytes */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_FRAGMENT);

    pb_wr16(b + 6, 0x8000); /* reserved ("evil") bit */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);

    pb_wr16(b + 6, 0x0000); /* DF clear, unfragmented: fine */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_OK);
}

static void martian_addresses(void)
{
    const uint32_t bad_src[] = {IP4(0, 0, 0, 0), IP4(127, 0, 0, 1),
                                IP4(224, 0, 0, 1), IP4(240, 0, 0, 1),
                                IP4(255, 255, 255, 255)};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof bad_src / sizeof bad_src[0]; i++) {
        size_t n = pb_udp(b, sizeof b, NULL, bad_src[i], 1, SERVER, 2,
                          NULL, 0);
        CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    }

    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(0, 0, 0, 0), 2,
                      NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(127, 0, 0, 1), 2, NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(224, 0, 0, 251), 5353,
               NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 68, IP4(255, 255, 255, 255), 67,
               NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);
}

static void unknown_protocol(void)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    const uint8_t protos[] = {0, 2, 41, 47, 50, 58, 132, 255};
    for (size_t i = 0; i < sizeof protos; i++) {
        b[9] = protos[i];
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), PARSE_UNSUPPORTED);
    }
}

/* ---- L4 defects ------------------------------------------------------------ */

static void tcp_bad_data_offset(void)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    for (uint8_t doff = 0; doff < 5; doff++) {
        b[20 + 12] = (uint8_t)(doff << 4);
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    }
    b[20 + 12] = 6 << 4; /* claims 24 bytes, segment is 20 */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
}

static void udp_length_mismatch(void)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "abcd", 4);
    const uint16_t lens[] = {0, 7, 11, 13, 0xffff};
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        pb_wr16(b + 20 + 4, lens[i]);
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    }
}

static void port_zero_rejected(void)
{
    uint8_t b[64];
    size_t n;
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 0, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 0, TCP_SYN, NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 0, SERVER, 53, NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 0, NULL, 0);
    CHECK_EQ(parse_exact(b, n), PARSE_MALFORMED);
}

static void tcp_flag_combinations_are_parsed_not_judged(void)
{
    /* Scan-style flag combinations are structurally valid; the TCP state
     * machine (not the parser) rejects them. */
    const uint8_t combos[] = {0, TCP_SYN | TCP_FIN, TCP_FIN | TCP_PSH | TCP_URG,
                              0xff};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof combos; i++) {
        size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2,
                          combos[i], NULL, 0);
        pkt_t p;
        CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
        CHECK_EQ(p.tcp_flags, combos[i]);
    }
}

/* ---- contract with the engine --------------------------------------------- */

static engine_t *engine_from(const char *text)
{
    char err[128];
    rules_t *r = rules_parse_string(text, err, sizeof err);
    CHECK(r != NULL);
    return r ? engine_create_with_rules(r) : NULL;
}

/* Real wire packets, parsed and then decided, behave like the spec examples. */
static void parsed_packets_drive_engine(void)
{
    engine_t *e = engine_from("allow out tcp from 10.0.1.0/24 to any port 80\n"
                              "allow in  tcp from any to 10.0.1.3 port 22\n");
    CHECK(e != NULL);
    if (!e)
        return;
    uint8_t b[128];
    pkt_t p;
    drop_reason_t why;
    size_t n;

    /* Client A -> web server: SYN out, SYN-ACK back, ACK out. */
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_IN, SEC, &why), VERDICT_ALLOW);
    n = pb_tcp(b, sizeof b, NULL, SERVER, 80, CLIENT_A, 50000,
               TCP_SYN | TCP_ACK, NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_OUT, SEC + 1, &why), VERDICT_ALLOW);
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 80, TCP_ACK, NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_IN, SEC + 2, &why), VERDICT_ALLOW);

    /* Attacker -> client B:3389 is dropped; client B:22 is exposed. */
    n = pb_tcp(b, sizeof b, NULL, ATTACKER, 4444, CLIENT_B, 3389, TCP_SYN,
               NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_OUT, SEC, &why), VERDICT_DROP);
    CHECK_EQ(why, DROP_NO_RULE);
    n = pb_tcp(b, sizeof b, NULL, ATTACKER, 4444, CLIENT_B, 22, TCP_SYN,
               NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_OUT, SEC, &why), VERDICT_ALLOW);

    /* An ACK scan from outside finds no flow. */
    n = pb_tcp(b, sizeof b, NULL, ATTACKER, 4445, CLIENT_A, 80, TCP_ACK,
               NULL, 0);
    CHECK_EQ(parse_packet(b, n, &p), PARSE_OK);
    CHECK_EQ(engine_decide(e, &p, DIR_OUT, SEC, &why), VERDICT_DROP);
    CHECK_EQ(why, DROP_NOT_SYN);

    engine_destroy(e);
}

/* ---- robustness ------------------------------------------------------------ */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint32_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static void random_buffers_never_crash(void)
{
    static const uint8_t protos[] = {1, 6, 17};
    uint8_t b[256];
    for (int i = 0; i < 20000; i++) {
        size_t n = rng() % sizeof b;
        for (size_t j = 0; j < n; j++)
            b[j] = (uint8_t)rng();
        if (n && (i & 1)) {
            /* Make half of them look like plausible IPv4 so parsing gets
             * past the first checks. */
            b[0] = (uint8_t)(0x45 + (rng() % 11));
            if (n >= 4)
                pb_wr16(b + 2, (uint16_t)n);
            if (n >= 20) {
                b[9] = protos[rng() % 3];
                pb_fix_csums(b, n);
            }
        }
        (void)parse_exact(b, n);
    }
    CHECK(1);
}

static void mutated_valid_packets_never_crash(void)
{
    uint8_t base[3][256], b[256], orig[64];
    size_t len[3];
    len[0] = pb_tcp(base[0], 256, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                    "abcdef", 6);
    len[1] = pb_udp(base[1], 256, NULL, CLIENT_A, 1, SERVER, 2, "abc", 3);
    pb_tcp(orig, sizeof orig, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN, NULL, 0);
    len[2] = pb_icmp_error(base[2], 256, NULL, ROUTER, CLIENT_A,
                           ICMP_DEST_UNREACH, 1, orig, 40);

    for (int i = 0; i < 30000; i++) {
        int k = (int)(rng() % 3);
        size_t n = len[k];
        memcpy(b, base[k], n);
        int flips = 1 + (int)(rng() % 4);
        for (int f = 0; f < flips; f++)
            b[rng() % n] ^= (uint8_t)(1u << (rng() % 8));
        if (rng() & 1)
            pb_fix_csums(b, n);
        (void)parse_exact(b, n);
    }
    CHECK(1);
}

int main(void)
{
    RUN(csum_rfc1071_example);
    RUN(csum_odd_length_pads_with_zero);
    RUN(csum_large_input_does_not_overflow);
    RUN(tcp_syn_fields);
    RUN(tcp_with_options_and_payload);
    RUN(tcp_odd_length_payload);
    RUN(udp_fields);
    RUN(udp_zero_checksum_accepted);
    RUN(udp_empty_payload);
    RUN(icmp_echo_uses_identifier_as_ports);
    RUN(icmp_time_exceeded_exposes_original_udp);
    RUN(icmp_unreachable_with_full_tcp_original);
    RUN(icmp_error_about_echo);
    RUN(icmp_error_inner_too_short);
    RUN(icmp_error_inner_bad_header);
    RUN(icmp_error_inner_fragment_and_unsupported);
    RUN(parse_inner_rejects_non_error);
    RUN(icmp_unsupported_types);
    RUN(empty_null_and_ipv6);
    RUN(truncated_packets_rejected);
    RUN(trailing_bytes_rejected);
    RUN(oversized_buffer_rejected);
    RUN(bad_ihl);
    RUN(bad_total_length);
    RUN(bad_checksums);
    RUN(pseudo_header_covers_addresses);
    RUN(fragments_rejected);
    RUN(martian_addresses);
    RUN(unknown_protocol);
    RUN(tcp_bad_data_offset);
    RUN(udp_length_mismatch);
    RUN(port_zero_rejected);
    RUN(tcp_flag_combinations_are_parsed_not_judged);
    RUN(parsed_packets_drive_engine);
    RUN(random_buffers_never_crash);
    RUN(mutated_valid_packets_never_crash);
    TEST_DONE();
}

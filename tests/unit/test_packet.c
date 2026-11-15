/* test_packet.c - parser and checksum tests. */
#include <stdlib.h>
#include <string.h>

#include "../../src/packet.h"
#include "../pktbuild.h"
#include "suites.h"
#include "test.h"

#define CLIENT_A IP4(10, 0, 1, 2)
#define SERVER   IP4(10, 0, 2, 2)
#define ROUTER   IP4(10, 0, 2, 1)

/*
 * Parse a copy of src[0..n) held in an exact-size heap buffer, so ASan
 * catches any read past the end. Only the return code is meaningful (the
 * pointers in *out dangle once the copy is freed).
 */
static enum reason parse_exact(const uint8_t *src, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1);
    if (!copy)
        abort();
    if (n)
        memcpy(copy, src, n);
    struct pkt p;
    enum reason r = pkt_parse(copy, n, &p);
    if (r == R_OK) {
        /* Invariants every successful parse must satisfy. */
        CHECK_EQ(p.len, n);
        CHECK_EQ((size_t)p.l4_off + p.l4_len, n);
        if (p.inner) {
            CHECK(p.inner >= copy + p.l4_off);
            CHECK(p.inner + p.inner_len == copy + n);
        }
    }
    free(copy);
    return r;
}

/* ---- checksums ------------------------------------------------------------ */

TEST(csum_rfc1071_example)
{
    /* RFC 1071 section 3: these words sum to 0xddf2, checksum 0x220d. */
    const uint8_t d[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK_EQ(csum_fold(csum_partial(d, sizeof d, 0)), 0x220d);
}

TEST(csum_odd_length_pads_with_zero)
{
    const uint8_t odd[] = {0x12, 0x34, 0x56};
    const uint8_t even[] = {0x12, 0x34, 0x56, 0x00};
    CHECK_EQ(csum_fold(csum_partial(odd, 3, 0)),
             csum_fold(csum_partial(even, 4, 0)));
}

TEST(csum_large_input_does_not_overflow)
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

TEST(tcp_syn_fields)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 40000, SERVER, 80,
                      TCP_SYN, NULL, 0);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK(p.buf == b);
    CHECK_EQ(p.len, 40);
    CHECK_EQ(p.l4_off, 20);
    CHECK_EQ(p.l4_len, 20);
    CHECK_EQ(p.proto, PROTO_TCP);
    CHECK_EQ(p.ttl, 64);
    CHECK_EQ(p.src, CLIENT_A);
    CHECK_EQ(p.dst, SERVER);
    CHECK_EQ(p.sport, 40000);
    CHECK_EQ(p.dport, 80);
    CHECK_EQ(p.tcp_flags, TCP_SYN);
    CHECK(p.inner == NULL);
}

TEST(tcp_with_options_and_payload)
{
    uint8_t b[256];
    struct pb_opts o = {.ip_opt_len = 4, .tcp_opt_len = 12, .ttl = 7};
    const char *body = "GET / HTTP/1.1\r\n\r\n";
    size_t n = pb_tcp(b, sizeof b, &o, CLIENT_A, 40000, SERVER, 443,
                      TCP_ACK | TCP_PSH, body, strlen(body));
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.l4_off, 24);
    CHECK_EQ(p.l4_len, 32 + strlen(body));
    CHECK_EQ(p.ttl, 7);
    CHECK_EQ(p.tcp_flags, TCP_ACK | TCP_PSH);
}

TEST(tcp_odd_length_payload)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1234, SERVER, 80,
                      TCP_ACK, "abc", 3);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
}

TEST(udp_fields)
{
    uint8_t b[128];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 5353, SERVER, 53,
                      "query", 5);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.proto, PROTO_UDP);
    CHECK_EQ(p.sport, 5353);
    CHECK_EQ(p.dport, 53);
    CHECK_EQ(p.l4_len, 13);
}

TEST(udp_zero_checksum_accepted)
{
    uint8_t b[128];
    struct pb_opts o = {.udp_no_csum = 1};
    size_t n = pb_udp(b, sizeof b, &o, CLIENT_A, 5353, SERVER, 53, "q", 1);
    CHECK_EQ(b[20 + 6], 0);
    CHECK_EQ(b[20 + 7], 0);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
}

TEST(udp_empty_payload)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.l4_len, 8);
}

TEST(icmp_echo_uses_identifier_as_ports)
{
    uint8_t b[128];
    size_t n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER,
                            ICMP_ECHO_REQUEST, 0xbeef, 1, "ping", 4);
    struct pkt p;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.proto, PROTO_ICMP);
    CHECK_EQ(p.icmp_type, ICMP_ECHO_REQUEST);
    CHECK_EQ(p.icmp_code, 0);
    CHECK_EQ(p.sport, 0xbeef);
    CHECK_EQ(p.dport, 0xbeef);
    CHECK(p.inner == NULL);

    n = pb_icmp_echo(b, sizeof b, NULL, SERVER, CLIENT_A, ICMP_ECHO_REPLY,
                     0xbeef, 1, "ping", 4);
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.icmp_type, ICMP_ECHO_REPLY);
    CHECK_EQ(p.sport, 0xbeef);
}

/* ---- ICMP errors ---------------------------------------------------------- */

TEST(icmp_time_exceeded_exposes_original_udp)
{
    uint8_t orig[128], b[256];
    size_t on = pb_udp(orig, sizeof orig, NULL, CLIENT_A, 33434, SERVER,
                       33435, "traceroute", 10);
    /* RFC 792 minimum: original IP header + 8 bytes. */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_TIME_EXCEEDED, 0, orig, 28);
    (void)on;

    struct pkt p, in;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.icmp_type, ICMP_TIME_EXCEEDED);
    CHECK(p.inner == b + 28);
    CHECK_EQ(p.inner_len, 28);

    CHECK_EQ(pkt_parse_inner(&p, &in), R_OK);
    CHECK_EQ(in.proto, PROTO_UDP);
    CHECK_EQ(in.src, CLIENT_A);
    CHECK_EQ(in.dst, SERVER);
    CHECK_EQ(in.sport, 33434);
    CHECK_EQ(in.dport, 33435);
    CHECK(in.inner == NULL);
}

TEST(icmp_unreachable_with_full_tcp_original)
{
    uint8_t orig[128], b[256];
    size_t on = pb_tcp(orig, sizeof orig, NULL, CLIENT_A, 40000, SERVER, 81,
                       TCP_SYN, NULL, 0);
    size_t n = pb_icmp_error(b, sizeof b, NULL, SERVER, CLIENT_A,
                             ICMP_DEST_UNREACH, 3, orig, on);
    struct pkt p, in;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(p.icmp_code, 3);
    CHECK_EQ(pkt_parse_inner(&p, &in), R_OK);
    CHECK_EQ(in.proto, PROTO_TCP);
    CHECK_EQ(in.sport, 40000);
    CHECK_EQ(in.dport, 81);
    CHECK_EQ(in.tcp_flags, 0);
}

TEST(icmp_error_about_echo)
{
    uint8_t orig[64], b[128];
    pb_icmp_echo(orig, sizeof orig, NULL, CLIENT_A, SERVER,
                 ICMP_ECHO_REQUEST, 77, 1, NULL, 0);
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_TIME_EXCEEDED, 0, orig, 28);
    struct pkt p, in;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(pkt_parse_inner(&p, &in), R_OK);
    CHECK_EQ(in.proto, PROTO_ICMP);
    CHECK_EQ(in.icmp_type, ICMP_ECHO_REQUEST);
    CHECK_EQ(in.sport, 77);
}

TEST(icmp_error_inner_too_short)
{
    uint8_t orig[64], b[128];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);
    for (size_t embed = 0; embed < 28; embed++) {
        size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                                 ICMP_DEST_UNREACH, 1, orig, embed);
        CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    }
}

TEST(icmp_error_inner_bad_header)
{
    uint8_t orig[64], b[128];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);

    uint8_t bad[64];
    memcpy(bad, orig, 28);
    bad[0] = 0x65; /* version 6 */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);

    memcpy(bad, orig, 28);
    bad[0] = 0x44; /* IHL 16 bytes */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);

    memcpy(bad, orig, 28);
    bad[0] = 0x46; /* IHL 24: needs 32 embedded bytes, only 28 present */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
}

TEST(icmp_error_inner_fragment_and_unsupported)
{
    uint8_t orig[64], b[128];
    pb_udp(orig, sizeof orig, NULL, CLIENT_A, 1000, SERVER, 53, NULL, 0);

    uint8_t bad[64];
    memcpy(bad, orig, 28);
    pb_wr16(bad + 6, 0x0010); /* non-first fragment */
    size_t n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                             ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), R_FRAGMENT);

    memcpy(bad, orig, 28);
    bad[9] = 47; /* GRE */
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_DEST_UNREACH, 1, bad, 28);
    CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);

    /* An error about an error is never valid. */
    uint8_t err[64];
    pb_icmp_error(err, sizeof err, NULL, SERVER, CLIENT_A,
                  ICMP_DEST_UNREACH, 1, orig, 28);
    n = pb_icmp_error(b, sizeof b, NULL, ROUTER, CLIENT_A,
                      ICMP_TIME_EXCEEDED, 0, err, 28);
    CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);
}

TEST(parse_inner_rejects_non_error)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    struct pkt p, in;
    CHECK_EQ(pkt_parse(b, n, &p), R_OK);
    CHECK_EQ(pkt_parse_inner(&p, &in), R_MALFORMED);
    CHECK_EQ(pkt_parse_inner(NULL, &in), R_MALFORMED);
}

TEST(icmp_unsupported_types)
{
    const uint8_t types[] = {4, 5, 9, 10, 13, 14, 17, 18, 42, 255};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof types; i++) {
        size_t n = pb_icmp_echo(b, sizeof b, NULL, SERVER, CLIENT_A,
                                types[i], 1, 1, NULL, 0);
        CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);
    }
}

/* ---- IP layer defects ----------------------------------------------------- */

TEST(empty_null_and_ipv6)
{
    struct pkt p;
    uint8_t one = 0x45;
    CHECK_EQ(pkt_parse(NULL, 40, &p), R_MALFORMED);
    CHECK_EQ(pkt_parse(&one, 0, &p), R_MALFORMED);
    CHECK_EQ(parse_exact(&one, 1), R_MALFORMED);

    uint8_t v6[40] = {0x60};
    CHECK_EQ(parse_exact(v6, sizeof v6), R_UNSUPPORTED);
    uint8_t v0[40] = {0x05};
    CHECK_EQ(parse_exact(v0, sizeof v0), R_UNSUPPORTED);
}

/* Every strict prefix of a valid packet must be rejected without overreads. */
static void check_all_truncations(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        CHECK(parse_exact(b, i) != R_OK);
    CHECK_EQ(parse_exact(b, n), R_OK);
}

TEST(truncated_packets_rejected)
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

TEST(trailing_bytes_rejected)
{
    uint8_t b[128];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "x", 1);
    b[n] = 0;
    CHECK_EQ(parse_exact(b, n + 1), R_MALFORMED);
    CHECK_EQ(parse_exact(b, n + 10), R_MALFORMED);
}

TEST(oversized_buffer_rejected)
{
    static uint8_t big[70000];
    size_t n = pb_udp(big, sizeof big, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    CHECK(n > 0);
    CHECK_EQ(parse_exact(big, sizeof big), R_MALFORMED);

    /* Largest legal packet still parses. */
    static uint8_t pl[65535 - 28];
    n = pb_udp(big, sizeof big, NULL, CLIENT_A, 1, SERVER, 2, pl, sizeof pl);
    CHECK_EQ(n, 65535);
    CHECK_EQ(parse_exact(big, n), R_OK);
}

TEST(bad_ihl)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    for (uint8_t ihl = 0; ihl < 5; ihl++) {
        b[0] = (uint8_t)(0x40 | ihl);
        CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    }
    /* IHL claims 60 bytes but total length is 40. */
    b[0] = 0x4f;
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
}

TEST(bad_total_length)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    pb_wr16(b + 2, (uint16_t)(n + 1));
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    pb_wr16(b + 2, (uint16_t)(n - 1));
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    pb_wr16(b + 2, 19);
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
}

TEST(bad_checksums)
{
    uint8_t b[128];
    size_t n;

    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN, NULL, 0);
    b[10] ^= 0x01; /* IP header checksum */
    CHECK_EQ(parse_exact(b, n), R_BAD_CSUM);

    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_ACK, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), R_BAD_CSUM);

    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), R_BAD_CSUM);

    n = pb_icmp_echo(b, sizeof b, NULL, CLIENT_A, SERVER, ICMP_ECHO_REQUEST,
                     1, 1, "data", 4);
    b[n - 1] ^= 0x01;
    CHECK_EQ(parse_exact(b, n), R_BAD_CSUM);
}

TEST(pseudo_header_covers_addresses)
{
    /* Rewriting the source address and fixing only the IP checksum must
     * break the TCP checksum (it covers the pseudo-header). */
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    pb_wr32(b + 12, IP4(10, 0, 1, 3));
    pb_wr16(b + 10, 0);
    pb_wr16(b + 10, csum_fold(csum_partial(b, 20, 0)));
    CHECK_EQ(parse_exact(b, n), R_BAD_CSUM);
}

TEST(fragments_rejected)
{
    uint8_t b[128];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "x", 1);

    pb_wr16(b + 6, 0x2000); /* MF */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_FRAGMENT);

    pb_wr16(b + 6, 0x0001); /* offset 8 bytes */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_FRAGMENT);

    pb_wr16(b + 6, 0x8000); /* reserved ("evil") bit */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);

    pb_wr16(b + 6, 0x0000); /* DF clear, unfragmented: fine */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_OK);
}

TEST(martian_addresses)
{
    const uint32_t bad_src[] = {IP4(0, 0, 0, 0), IP4(127, 0, 0, 1),
                                IP4(224, 0, 0, 1), IP4(240, 0, 0, 1),
                                IP4(255, 255, 255, 255)};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof bad_src / sizeof bad_src[0]; i++) {
        size_t n = pb_udp(b, sizeof b, NULL, bad_src[i], 1, SERVER, 2,
                          NULL, 0);
        CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    }

    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(0, 0, 0, 0), 2,
                      NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(127, 0, 0, 1), 2, NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, IP4(224, 0, 0, 251), 5353,
               NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 68, IP4(255, 255, 255, 255), 67,
               NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);
}

TEST(unknown_protocol)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, NULL, 0);
    const uint8_t protos[] = {0, 2, 41, 47, 50, 58, 132, 255};
    for (size_t i = 0; i < sizeof protos; i++) {
        b[9] = protos[i];
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), R_UNSUPPORTED);
    }
}

/* ---- L4 defects ------------------------------------------------------------ */

TEST(tcp_bad_data_offset)
{
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, TCP_SYN,
                      NULL, 0);
    for (uint8_t doff = 0; doff < 5; doff++) {
        b[20 + 12] = (uint8_t)(doff << 4);
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    }
    b[20 + 12] = 6 << 4; /* claims 24 bytes, segment is 20 */
    pb_fix_csums(b, n);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
}

TEST(udp_length_mismatch)
{
    uint8_t b[64];
    size_t n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2, "abcd", 4);
    const uint16_t lens[] = {0, 7, 11, 13, 0xffff};
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        pb_wr16(b + 20 + 4, lens[i]);
        pb_fix_csums(b, n);
        CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    }
}

TEST(port_zero_rejected)
{
    uint8_t b[64];
    size_t n;
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 0, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 0, TCP_SYN, NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 0, SERVER, 53, NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
    n = pb_udp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 0, NULL, 0);
    CHECK_EQ(parse_exact(b, n), R_MALFORMED);
}

TEST(tcp_flag_combinations_are_parsed_not_judged)
{
    /* Scan-style flag combinations are structurally valid; the TCP state
     * machine (not the parser) rejects them. */
    const uint8_t combos[] = {0, TCP_SYN | TCP_FIN, TCP_FIN | TCP_PSH | TCP_URG,
                              0xff};
    uint8_t b[64];
    for (size_t i = 0; i < sizeof combos; i++) {
        size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 1, SERVER, 2,
                          combos[i], NULL, 0);
        struct pkt p;
        CHECK_EQ(pkt_parse(b, n, &p), R_OK);
        CHECK_EQ(p.tcp_flags, combos[i]);
    }
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

TEST(random_buffers_never_crash)
{
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
                b[9] = (const uint8_t[]){1, 6, 17}[rng() % 3];
                pb_fix_csums(b, n);
            }
        }
        (void)parse_exact(b, n);
    }
    CHECK(1);
}

TEST(mutated_valid_packets_never_crash)
{
    uint8_t base[3][256], b[256];
    size_t len[3];
    uint8_t orig[64];
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

void suite_packet(void)
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
    RUN(random_buffers_never_crash);
    RUN(mutated_valid_packets_never_crash);
}

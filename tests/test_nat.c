/*=============================================================================
 * File Name:   test_nat.c
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Unit tests for source NAT and port forwarding. The strongest check used here:
 *              a translated packet must be byte-for-byte identical to the
 *              same packet built from scratch (by tests/pktbuild.c, which
 *              computes every checksum in full) with the translated
 *              addresses. That proves the incremental (RFC 1624) checksum
 *              updates are exactly right, and parse_packet() must accept it.
 =============================================================================*/

#include <stdlib.h>
#include <string.h>

#include "fwalloc.h"
#include "nat.h"
#include "parser.h"
#include "pktbuild.h"
#include "testutil.h"

#define CLIENT   IP4(10, 0, 1, 2)
#define CLIENT_B IP4(10, 0, 1, 3)
#define SERVER   IP4(10, 0, 2, 2)
#define OTHER    IP4(10, 0, 2, 3)
#define ROUTER   IP4(10, 0, 2, 9)
#define NATIP    IP4(10, 0, 2, 254)

static pkt_t parsed(const uint8_t *b, size_t n)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    CHECK(parse_packet(b, n, &p) == PARSE_OK);
    return p;
}

static nat_t *mk_nat(void)
{
    nat_t *n = nat_create(NATIP, NAT_PORT_LO_DEFAULT, NAT_PORT_HI_DEFAULT);
    CHECK(n != NULL);
    return n;
}

/* Send b out through the NAT; returns the NAT port it was given (0 if not
 * translated). */
static uint16_t out(nat_t *n, uint8_t *b, size_t len)
{
    pkt_t p = parsed(b, len);
    if (nat_outbound(n, b, &p, true, 0) != NAT_TRANSLATED) return 0;
    pkt_t q = parsed(b, len);
    CHECK(q.src_ip == NATIP);
    return q.src_port;
}

static void test_checksum_adjust_matches_a_full_recompute(void)
{
    /* Change one word of a random buffer; the adjusted checksum must equal
     * the checksum computed from scratch over the new buffer. */
    srand(7);
    for (int round = 0; round < 2000; round++) {
        uint8_t buf[40];
        for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)rand();
        const uint16_t before = csum_fold(csum_partial(buf, sizeof buf, 0));
        const size_t at = (size_t)(rand() % 20) * 2;
        const uint16_t old_w = (uint16_t)(buf[at] << 8 | buf[at + 1]);
        const uint16_t new_w = (uint16_t)rand();
        buf[at] = (uint8_t)(new_w >> 8); buf[at + 1] = (uint8_t)new_w;
        const uint16_t want = csum_fold(csum_partial(buf, sizeof buf, 0));
        const uint16_t got = nat_csum_adjust16(before, old_w, new_w);
        /* 0x0000 and 0xffff are the same number in one's complement */
        CHECK(got == want || (got == 0xffff && want == 0) || (got == 0 && want == 0xffff));
    }
}

static void test_tcp_is_translated_both_ways_byte_for_byte(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256], want[256];
    const char data[] = "GET / HTTP/1.1\r\n\r\n";

    size_t len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    const uint16_t port = out(n, b, len);
    CHECK(port >= NAT_PORT_LO_DEFAULT && port <= NAT_PORT_HI_DEFAULT);
    CHECK(pb_tcp(want, sizeof want, NULL, NATIP, port, SERVER, 80, TCP_SYN, NULL, 0) == len);
    CHECK(memcmp(b, want, len) == 0);

    /* the server's answer comes back to the inside host */
    len = pb_tcp(b, sizeof b, NULL, SERVER, 80, NATIP, port, TCP_SYN | TCP_ACK, NULL, 0);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    pb_tcp(want, sizeof want, NULL, SERVER, 80, CLIENT, 40000, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(memcmp(b, want, len) == 0);
    parsed(b, len);

    /* later packets with a payload reuse the same port */
    len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 80, TCP_ACK | TCP_PSH, data, sizeof data - 1);
    CHECK(out(n, b, len) == port);
    pb_tcp(want, sizeof want, NULL, NATIP, port, SERVER, 80, TCP_ACK | TCP_PSH, data, sizeof data - 1);
    CHECK(memcmp(b, want, len) == 0);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 1 && st.mappings_created == 1);
    CHECK(st.translated_out == 2 && st.translated_in == 1);
    nat_destroy(n);
}

static void test_udp_with_and_without_a_checksum(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256], want[256];
    const char q[] = "dns query";

    size_t len = pb_udp(b, sizeof b, NULL, CLIENT, 5353, SERVER, 53, q, sizeof q);
    const uint16_t port = out(n, b, len);
    CHECK(port != 0);
    pb_udp(want, sizeof want, NULL, NATIP, port, SERVER, 53, q, sizeof q);
    CHECK(memcmp(b, want, len) == 0);

    len = pb_udp(b, sizeof b, NULL, SERVER, 53, NATIP, port, q, sizeof q);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    pb_udp(want, sizeof want, NULL, SERVER, 53, CLIENT, 5353, q, sizeof q);
    CHECK(memcmp(b, want, len) == 0);

    /* checksum 0 means "none": it must stay 0, not become a wrong value */
    struct pb_opts nocs = { .udp_no_csum = 1 };
    len = pb_udp(b, sizeof b, &nocs, CLIENT, 6000, SERVER, 53, q, sizeof q);
    const uint16_t port2 = out(n, b, len);
    CHECK(port2 != 0 && port2 != port);
    pb_udp(want, sizeof want, &nocs, NATIP, port2, SERVER, 53, q, sizeof q);
    CHECK(memcmp(b, want, len) == 0);
    CHECK(b[20 + 6] == 0 && b[20 + 7] == 0);
    nat_destroy(n);
}

static void test_ping_translates_the_echo_identifier(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256], want[256];
    size_t len = pb_icmp_echo(b, sizeof b, NULL, CLIENT, SERVER, ICMP_ECHO_REQUEST, 77, 1, "ping", 4);
    const uint16_t id = out(n, b, len);
    CHECK(id != 0);
    pb_icmp_echo(want, sizeof want, NULL, NATIP, SERVER, ICMP_ECHO_REQUEST, id, 1, "ping", 4);
    CHECK(memcmp(b, want, len) == 0);

    len = pb_icmp_echo(b, sizeof b, NULL, SERVER, NATIP, ICMP_ECHO_REPLY, id, 1, "ping", 4);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    pb_icmp_echo(want, sizeof want, NULL, SERVER, CLIENT, ICMP_ECHO_REPLY, 77, 1, "ping", 4);
    CHECK(memcmp(b, want, len) == 0);
    nat_destroy(n);
}

static void test_each_connection_gets_its_own_port(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256];
    /* two inside hosts using the same source port, and one host talking to
     * two servers: three connections, three different NAT ports */
    size_t len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    const uint16_t a = out(n, b, len);
    len = pb_tcp(b, sizeof b, NULL, CLIENT_B, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    const uint16_t c = out(n, b, len);
    len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, OTHER, 80, TCP_SYN, NULL, 0);
    const uint16_t d = out(n, b, len);
    CHECK(a && c && d && a != c && a != d && c != d);

    /* each reply reaches the right inside host */
    len = pb_tcp(b, sizeof b, NULL, SERVER, 80, NATIP, c, TCP_SYN | TCP_ACK, NULL, 0);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    p = parsed(b, len);
    CHECK(p.dst_ip == CLIENT_B && p.dst_port == 40000);
    nat_destroy(n);
}

static void test_unsolicited_inbound_is_refused(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256], copy[256];
    size_t len = pb_udp(b, sizeof b, NULL, CLIENT, 5353, SERVER, 53, "q", 1);
    const uint16_t port = out(n, b, len);

    /* a port nobody holds, the right port from another host, the right
     * port from the right host but another source port */
    const struct { uint32_t src; uint16_t sport, dport; } bad[] = {
        { SERVER, 53, (uint16_t)(port + 1) },
        { OTHER, 53, port },
        { SERVER, 54, port },
        { SERVER, 53, 1000 },                 /* outside the NAT port range */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        len = pb_udp(b, sizeof b, NULL, bad[i].src, bad[i].sport, NATIP, bad[i].dport, "x", 1);
        memcpy(copy, b, len);
        pkt_t p = parsed(b, len);
        CHECK(nat_inbound(n, b, &p, 0) == NAT_NO_MAPPING);
        CHECK(memcmp(b, copy, len) == 0);    /* untouched */
    }
    /* an inbound TCP SYN to the NAT address: nothing to map it to */
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 22, TCP_SYN, NULL, 0);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_NO_MAPPING);

    /* traffic not addressed to the NAT address is none of its business */
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, CLIENT_B, 22, TCP_SYN, NULL, 0);
    memcpy(copy, b, len);
    p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_PASS);
    CHECK(memcmp(b, copy, len) == 0);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.drop_no_mapping == 5);
    nat_destroy(n);
}

static void test_no_mapping_is_made_unless_allowed(void)
{
    /* A reply from an exposed inside service (a connection the outside
     * started) leaves untranslated: the caller says may_create = false. */
    nat_t *n = mk_nat();
    uint8_t b[256], copy[256];
    size_t len = pb_tcp(b, sizeof b, NULL, CLIENT_B, 22, OTHER, 5555, TCP_SYN | TCP_ACK, NULL, 0);
    memcpy(copy, b, len);
    pkt_t p = parsed(b, len);
    CHECK(nat_outbound(n, b, &p, false, 0) == NAT_PASS);
    CHECK(memcmp(b, copy, len) == 0);
    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.mappings_created == 0);
    nat_destroy(n);
}

static bool all_dead(void *ud, const pkt_t *t) { (void)ud; (void)t; return false; }

static void test_running_out_of_ports(void)
{
    nat_t *n = nat_create(NATIP, 30000, 30002);       /* three ports */
    CHECK(n != NULL);
    uint8_t b[256];
    for (uint16_t i = 0; i < 3; i++) {
        size_t len = pb_tcp(b, sizeof b, NULL, CLIENT, (uint16_t)(40000 + i), SERVER, 80, TCP_SYN, NULL, 0);
        CHECK(out(n, b, len) == 30000 + i);
    }
    size_t len = pb_tcp(b, sizeof b, NULL, CLIENT, 40003, SERVER, 80, TCP_SYN, NULL, 0);
    pkt_t p = parsed(b, len);
    CHECK(nat_outbound(n, b, &p, true, 0) == NAT_FULL);
    /* each protocol has its own ports */
    len = pb_udp(b, sizeof b, NULL, CLIENT, 40003, SERVER, 53, "q", 1);
    CHECK(out(n, b, len) == 30000);
    /* once the connections are over, their ports come back */
    CHECK(nat_sweep(n, all_dead, NULL) == 4);
    len = pb_tcp(b, sizeof b, NULL, CLIENT, 40003, SERVER, 80, TCP_SYN, NULL, 0);
    CHECK(out(n, b, len) != 0);
    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.drop_full == 1 && st.mappings_active == 1 && st.mappings_freed == 4);
    nat_destroy(n);
}

static void test_icmp_error_from_the_outside_is_translated_inside(void)
{
    /* The client's UDP datagram leaves as NATIP:port; a router answers with
     * port unreachable to NATIP, embedding the datagram as it saw it. The
     * client must get the error as if there were no NAT: addressed to it,
     * embedding its own original datagram. */
    nat_t *n = mk_nat();
    uint8_t orig[256], b[512], want[512];
    const size_t olen = pb_udp(orig, sizeof orig, NULL, CLIENT, 5353, SERVER, 53, "query", 5);
    uint8_t sent[256];
    memcpy(sent, orig, olen);
    const uint16_t port = out(n, sent, olen);

    for (int embed_all = 0; embed_all < 2; embed_all++) {
        const size_t emb = embed_all ? olen : 28;     /* truncated: IP header + 8 bytes */
        size_t len = pb_icmp_error(b, sizeof b, NULL, ROUTER, NATIP, ICMP_DEST_UNREACH, 3, sent, emb);
        pkt_t p = parsed(b, len);
        CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
        CHECK(pb_icmp_error(want, sizeof want, NULL, ROUTER, CLIENT, ICMP_DEST_UNREACH, 3, orig, emb) == len);
        CHECK(memcmp(b, want, len) == 0);
        parsed(b, len);
    }

    /* the same for a TCP connection, embedded truncated (no TCP checksum) and
     * whole, and for a ping (time exceeded, as traceroute -I sees) */
    const size_t tlen = pb_tcp(orig, sizeof orig, NULL, CLIENT, 41000, SERVER, 443, TCP_SYN, NULL, 0);
    memcpy(sent, orig, tlen);
    out(n, sent, tlen);
    for (int embed_all = 0; embed_all < 2; embed_all++) {
        const size_t emb = embed_all ? tlen : 28;
        size_t len = pb_icmp_error(b, sizeof b, NULL, ROUTER, NATIP, ICMP_TIME_EXCEEDED, 0, sent, emb);
        pkt_t p = parsed(b, len);
        CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
        pb_icmp_error(want, sizeof want, NULL, ROUTER, CLIENT, ICMP_TIME_EXCEEDED, 0, orig, emb);
        CHECK(memcmp(b, want, len) == 0);
    }
    const size_t elen = pb_icmp_echo(orig, sizeof orig, NULL, CLIENT, SERVER, ICMP_ECHO_REQUEST, 9, 1, "abcd", 4);
    memcpy(sent, orig, elen);
    out(n, sent, elen);
    size_t len = pb_icmp_error(b, sizeof b, NULL, ROUTER, NATIP, ICMP_TIME_EXCEEDED, 0, sent, elen);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    pb_icmp_error(want, sizeof want, NULL, ROUTER, CLIENT, ICMP_TIME_EXCEEDED, 0, orig, elen);
    CHECK(memcmp(b, want, len) == 0);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.icmp_errors_translated == 5);
    (void)port;
    nat_destroy(n);
}

static void test_icmp_error_about_no_connection_is_refused(void)
{
    nat_t *n = mk_nat();
    uint8_t orig[256], b[512];
    /* an error claiming to be about a datagram we never sent */
    const size_t olen = pb_udp(orig, sizeof orig, NULL, NATIP, 20500, SERVER, 53, "q", 1);
    size_t len = pb_icmp_error(b, sizeof b, NULL, ROUTER, NATIP, ICMP_DEST_UNREACH, 3, orig, olen);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_NO_MAPPING);

    /* about a real connection, but naming a different remote host */
    uint8_t sent[256];
    const size_t slen = pb_udp(sent, sizeof sent, NULL, CLIENT, 5353, SERVER, 53, "q", 1);
    const uint16_t port = out(n, sent, slen);
    const size_t flen = pb_udp(orig, sizeof orig, NULL, NATIP, port, OTHER, 53, "q", 1);
    len = pb_icmp_error(b, sizeof b, NULL, ROUTER, NATIP, ICMP_DEST_UNREACH, 3, orig, flen);
    p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_NO_MAPPING);
    nat_destroy(n);
}

static void test_icmp_error_from_the_inside_is_translated_outside(void)
{
    /* The server's reply reaches the client translated; the client answers
     * with port unreachable. The server must see the error come from NATIP,
     * embedding the reply exactly as the server sent it. */
    nat_t *n = mk_nat();
    uint8_t b[512], want[512], reply_at_server[256], reply_at_client[256];
    size_t len = pb_udp(b, sizeof b, NULL, CLIENT, 5353, SERVER, 53, "q", 1);
    const uint16_t port = out(n, b, len);

    const size_t rlen = pb_udp(reply_at_server, sizeof reply_at_server, NULL, SERVER, 53, NATIP, port, "answer", 6);
    memcpy(reply_at_client, reply_at_server, rlen);
    pkt_t p = parsed(reply_at_client, rlen);
    CHECK(nat_inbound(n, reply_at_client, &p, 0) == NAT_TRANSLATED);

    len = pb_icmp_error(b, sizeof b, NULL, CLIENT, SERVER, ICMP_DEST_UNREACH, 3, reply_at_client, rlen);
    p = parsed(b, len);
    CHECK(nat_outbound(n, b, &p, false, 0) == NAT_TRANSLATED);
    pb_icmp_error(want, sizeof want, NULL, NATIP, SERVER, ICMP_DEST_UNREACH, 3, reply_at_server, rlen);
    CHECK(memcmp(b, want, len) == 0);

    /* an inside error about something that was never translated passes */
    uint8_t other[256], copy[512];
    const size_t olen = pb_udp(other, sizeof other, NULL, OTHER, 99, CLIENT_B, 9999, "x", 1);
    len = pb_icmp_error(b, sizeof b, NULL, CLIENT_B, OTHER, ICMP_DEST_UNREACH, 3, other, olen);
    memcpy(copy, b, len);
    p = parsed(b, len);
    CHECK(nat_outbound(n, b, &p, false, 0) == NAT_PASS);
    CHECK(memcmp(b, copy, len) == 0);
    nat_destroy(n);
}

struct sweep_ctx { pkt_t keep; int asked; };

static bool keep_one(void *ud, const pkt_t *t)
{
    struct sweep_ctx *c = ud;
    c->asked++;
    return t->proto == c->keep.proto && t->src_ip == c->keep.src_ip &&
           t->src_port == c->keep.src_port && t->dst_ip == c->keep.dst_ip &&
           t->dst_port == c->keep.dst_port;
}

static void test_sweep_asks_about_each_connection_by_its_inside_tuple(void)
{
    nat_t *n = mk_nat();
    uint8_t b[256];
    size_t len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    const uint16_t port = out(n, b, len);
    len = pb_udp(b, sizeof b, NULL, CLIENT_B, 5353, SERVER, 53, "q", 1);
    const uint16_t uport = out(n, b, len);

    struct sweep_ctx c = { .keep = mk_tcp(CLIENT, 40000, SERVER, 80, 0) };
    CHECK(nat_sweep(n, keep_one, &c) == 1);
    CHECK(c.asked == 2);

    /* the TCP connection still works, the UDP one is gone */
    len = pb_tcp(b, sizeof b, NULL, SERVER, 80, NATIP, port, TCP_SYN | TCP_ACK, NULL, 0);
    pkt_t p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_TRANSLATED);
    len = pb_udp(b, sizeof b, NULL, SERVER, 53, NATIP, uport, "a", 1);
    p = parsed(b, len);
    CHECK(nat_inbound(n, b, &p, 0) == NAT_NO_MAPPING);
    nat_destroy(n);
}

static void test_create_checks_arguments_and_survives_oom(void)
{
    CHECK(nat_create(0, 20000, 20010) == NULL);
    CHECK(nat_create(NATIP, 0, 20010) == NULL);
    CHECK(nat_create(NATIP, 20010, 20000) == NULL);
    nat_t *one = nat_create(NATIP, 20000, 20000);       /* a single port is fine */
    CHECK(one != NULL && nat_addr(one) == NATIP);
    nat_destroy(one);
    nat_destroy(NULL);

    /* every allocation nat_create makes can fail without leaking (ASan) */
    for (long k = 1; k < 20; k++) {
        fw_alloc_fail_nth(k);
        nat_t *n = nat_create(NATIP, 20000, 20100);
        const bool fired = fw_alloc_failure_fired();
        fw_alloc_fail_nth(0);
        if (!fired) { CHECK(n != NULL); nat_destroy(n); break; }
        CHECK(n == NULL);
    }
}

static void test_stats_line(void)
{
    nat_t *n = mk_nat();
    char out_buf[512] = { 0 };
    FILE *f = tmpfile();
    CHECK(f != NULL);
    if (!f) { nat_destroy(n); return; }
    nat_stats_print(n, f);
    rewind(f);
    CHECK(fgets(out_buf, sizeof out_buf, f) != NULL);
    CHECK(strstr(out_buf, "nat:") == out_buf);
    CHECK(strstr(out_buf, "addr=10.0.2.254") != NULL);
    fclose(f);
    nat_destroy(n);
}

/* ---- port forwarding ----------------------------------------------------- */

#define WEB IP4(10, 0, 1, 3)

static const forward_t FWDS[] = {
    { FW_PROTO_TCP, 8080, WEB, 80, 1 },
    { FW_PROTO_UDP, 5300, WEB, 53, 2 },
};

static nat_t *mk_fwd_nat(void)
{
    nat_t *n = mk_nat();
    CHECK(nat_check_forwards(n, FWDS, 2, NULL, 0));
    nat_set_forwards(n, FWDS, 2);
    return n;
}

/* A packet arriving from the outside. */
static nat_result_t in(nat_t *n, uint8_t *b, size_t len)
{
    pkt_t p = parsed(b, len);
    return nat_inbound(n, b, &p, 0);
}

/* A reply leaving from the inside: never allowed to create a mapping, as the
 * forwarder passes may_create = false for connections the outside started. */
static nat_result_t reply_out(nat_t *n, uint8_t *b, size_t len)
{
    pkt_t p = parsed(b, len);
    return nat_outbound(n, b, &p, false, 0);
}

static void test_a_forwarded_port_reaches_the_inside_server_byte_for_byte(void)
{
    nat_t *n = mk_fwd_nat();
    uint8_t b[256], want[256];
    const char data[] = "GET / HTTP/1.1\r\n\r\n";

    /* the outside client's SYN to NATIP:8080 is sent to WEB:80, keeping the
     * client's own address (the server sees who connected) */
    size_t len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    pb_tcp(want, sizeof want, NULL, OTHER, 5555, WEB, 80, TCP_SYN, NULL, 0);
    CHECK(memcmp(b, want, len) == 0);

    /* the server's answer leaves from NATIP:8080, as the client expects */
    len = pb_tcp(b, sizeof b, NULL, WEB, 80, OTHER, 5555, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(reply_out(n, b, len) == NAT_TRANSLATED);
    pb_tcp(want, sizeof want, NULL, NATIP, 8080, OTHER, 5555, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(memcmp(b, want, len) == 0);

    /* later packets of the connection use the same mapping */
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK | TCP_PSH, data, sizeof data - 1);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    pb_tcp(want, sizeof want, NULL, OTHER, 5555, WEB, 80, TCP_ACK | TCP_PSH, data, sizeof data - 1);
    CHECK(memcmp(b, want, len) == 0);
    parsed(b, len);

    /* a second client shares port 8080 but gets its own connection */
    len = pb_tcp(b, sizeof b, NULL, SERVER, 6000, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    len = pb_tcp(b, sizeof b, NULL, WEB, 80, SERVER, 6000, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(reply_out(n, b, len) == NAT_TRANSLATED);
    pb_tcp(want, sizeof want, NULL, NATIP, 8080, SERVER, 6000, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(memcmp(b, want, len) == 0);

    /* UDP works the same way */
    len = pb_udp(b, sizeof b, NULL, OTHER, 7000, NATIP, 5300, "query", 5);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    pb_udp(want, sizeof want, NULL, OTHER, 7000, WEB, 53, "query", 5);
    CHECK(memcmp(b, want, len) == 0);
    len = pb_udp(b, sizeof b, NULL, WEB, 53, OTHER, 7000, "answer", 6);
    CHECK(reply_out(n, b, len) == NAT_TRANSLATED);
    pb_udp(want, sizeof want, NULL, NATIP, 5300, OTHER, 7000, "answer", 6);
    CHECK(memcmp(b, want, len) == 0);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.forwarded == 3 && st.mappings_active == 3);
    CHECK(st.translated_in == 4 && st.translated_out == 3);
    nat_destroy(n);
}

static void test_only_a_first_packet_opens_a_forwarded_connection(void)
{
    nat_t *n = mk_fwd_nat();
    uint8_t b[256];
    /* an ACK scan, a SYN-ACK, a port nobody forwards, a TCP SYN to the UDP
     * forward's port, and a ping: none of them opens anything */
    size_t len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8081, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 5300, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    len = pb_icmp_echo(b, sizeof b, NULL, OTHER, NATIP, ICMP_ECHO_REQUEST, 9, 1, "abcd", 4);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    /* and the inside server can't answer a connection that does not exist */
    len = pb_tcp(b, sizeof b, NULL, WEB, 80, OTHER, 5555, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(reply_out(n, b, len) == NAT_PASS);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.forwarded == 0 && st.mappings_active == 0 && st.drop_no_mapping == 5);
    nat_destroy(n);
}

static void test_undo_forgets_only_a_connection_the_last_packet_opened(void)
{
    nat_t *n = mk_fwd_nat();
    uint8_t b[256];
    nat_stats_t st;

    /* the engine refused the SYN: undo leaves nothing behind */
    size_t len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    nat_undo_inbound(n);
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 0 && st.forwarded == 0);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);
    nat_undo_inbound(n);                         /* nothing to undo: harmless */

    /* a packet of an existing connection is not undone */
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    nat_undo_inbound(n);
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 1 && st.forwarded == 1);

    /* nor is one after a source-NAT packet (nothing was opened inbound) */
    len = pb_tcp(b, sizeof b, NULL, CLIENT, 40000, SERVER, 80, TCP_SYN, NULL, 0);
    const uint16_t port = out(n, b, len);
    len = pb_tcp(b, sizeof b, NULL, SERVER, 80, NATIP, port, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    nat_undo_inbound(n);
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 2);
    nat_destroy(n);
}

static void test_icmp_errors_about_a_forwarded_connection_are_translated(void)
{
    nat_t *n = mk_fwd_nat();
    uint8_t q[256], a[256], b[512], want[512];

    /* OTHER:7000 -> NATIP:5300 is forwarded to WEB:53 */
    const size_t qlen = pb_udp(q, sizeof q, NULL, OTHER, 7000, NATIP, 5300, "query", 5);
    uint8_t q_in[256];
    memcpy(q_in, q, qlen);
    CHECK(in(n, q_in, qlen) == NAT_TRANSLATED);        /* now OTHER:7000 -> WEB:53 */

    /* WEB says port unreachable about the query as it got it: the error
     * leaves from NATIP and embeds the query as the client sent it */
    size_t len = pb_icmp_error(b, sizeof b, NULL, WEB, OTHER, ICMP_DEST_UNREACH, 3, q_in, qlen);
    CHECK(reply_out(n, b, len) == NAT_TRANSLATED);
    CHECK(pb_icmp_error(want, sizeof want, NULL, NATIP, OTHER, ICMP_DEST_UNREACH, 3, q, qlen) == len);
    CHECK(memcmp(b, want, len) == 0);

    /* the server's answer leaves as NATIP:5300; if the client reports an
     * error about it, the error reaches WEB about the answer WEB sent */
    const size_t alen = pb_udp(a, sizeof a, NULL, WEB, 53, OTHER, 7000, "answer", 6);
    uint8_t a_out[256];
    memcpy(a_out, a, alen);
    CHECK(reply_out(n, a_out, alen) == NAT_TRANSLATED);
    for (int embed_all = 0; embed_all < 2; embed_all++) {
        const size_t emb = embed_all ? alen : 28;
        len = pb_icmp_error(b, sizeof b, NULL, OTHER, NATIP, ICMP_DEST_UNREACH, 3, a_out, emb);
        CHECK(in(n, b, len) == NAT_TRANSLATED);
        CHECK(pb_icmp_error(want, sizeof want, NULL, OTHER, WEB, ICMP_DEST_UNREACH, 3, a, emb) == len);
        CHECK(memcmp(b, want, len) == 0);
        parsed(b, len);
    }

    /* an error about a forwarded port with no such connection is refused */
    const size_t xlen = pb_udp(a, sizeof a, NULL, NATIP, 5300, SERVER, 9999, "x", 1);
    len = pb_icmp_error(b, sizeof b, NULL, SERVER, NATIP, ICMP_DEST_UNREACH, 3, a, xlen);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);

    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.icmp_errors_translated == 3);
    nat_destroy(n);
}

static void test_forward_ports_must_stay_out_of_the_nat_port_range(void)
{
    nat_t *n = mk_nat();
    const forward_t bad[] = {
        { FW_PROTO_TCP, 8080, WEB, 80, 2 },
        { FW_PROTO_TCP, 30000, WEB, 22, 3 },
    };
    char err[160] = "";
    CHECK(!nat_check_forwards(n, bad, 2, err, sizeof err));
    CHECK(strstr(err, "line 3") != NULL && strstr(err, "30000") != NULL);
    CHECK(nat_check_forwards(n, bad, 1, err, sizeof err));
    CHECK(!nat_check_forwards(n, bad + 1, 1, NULL, 0));      /* err may be NULL */
    CHECK(nat_check_forwards(n, NULL, 0, NULL, 0));
    nat_destroy(n);
}

static void test_forwards_change_on_reload_and_mappings_follow_their_flows(void)
{
    nat_t *n = mk_fwd_nat();
    uint8_t b[256];

    size_t len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);

    /* the forward is removed (a reload): the open connection keeps working
     * both ways, a new one is refused */
    nat_set_forwards(n, NULL, 0);
    len = pb_tcp(b, sizeof b, NULL, WEB, 80, OTHER, 5555, TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(reply_out(n, b, len) == NAT_TRANSLATED);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    pkt_t p = parsed(b, len);
    CHECK(p.dst_ip == WEB && p.dst_port == 80);
    len = pb_tcp(b, sizeof b, NULL, SERVER, 6000, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);

    /* the sweep asks about the connection by its inside tuple, and frees the
     * mapping once its flow is gone */
    struct sweep_ctx c = { .keep = mk_tcp(WEB, 80, OTHER, 5555, 0) };
    CHECK(nat_sweep(n, keep_one, &c) == 0 && c.asked == 1);
    c.keep = mk_tcp(CLIENT, 1, SERVER, 1, 0);
    CHECK(nat_sweep(n, keep_one, &c) == 1);
    nat_stats_t st;
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 0);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_NO_MAPPING);           /* gone from both hashes */

    /* an open connection, then the forward moves to another inside port (a
     * reload): the open connection stays on the old port, new ones use the new */
    nat_set_forwards(n, FWDS, 2);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    const forward_t moved[] = { { FW_PROTO_TCP, 8080, WEB, 8000, 1 } };
    nat_set_forwards(n, moved, 1);
    len = pb_tcp(b, sizeof b, NULL, OTHER, 5555, NATIP, 8080, TCP_ACK, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    p = parsed(b, len);
    CHECK(p.dst_ip == WEB && p.dst_port == 80);
    len = pb_tcp(b, sizeof b, NULL, SERVER, 6000, NATIP, 8080, TCP_SYN, NULL, 0);
    CHECK(in(n, b, len) == NAT_TRANSLATED);
    p = parsed(b, len);
    CHECK(p.dst_ip == WEB && p.dst_port == 8000);
    nat_get_stats(n, &st);
    CHECK(st.mappings_active == 2);
    nat_destroy(n);
}

int main(void)
{
    RUN(test_checksum_adjust_matches_a_full_recompute);
    RUN(test_tcp_is_translated_both_ways_byte_for_byte);
    RUN(test_udp_with_and_without_a_checksum);
    RUN(test_ping_translates_the_echo_identifier);
    RUN(test_each_connection_gets_its_own_port);
    RUN(test_unsolicited_inbound_is_refused);
    RUN(test_no_mapping_is_made_unless_allowed);
    RUN(test_running_out_of_ports);
    RUN(test_icmp_error_from_the_outside_is_translated_inside);
    RUN(test_icmp_error_about_no_connection_is_refused);
    RUN(test_icmp_error_from_the_inside_is_translated_outside);
    RUN(test_sweep_asks_about_each_connection_by_its_inside_tuple);
    RUN(test_create_checks_arguments_and_survives_oom);
    RUN(test_stats_line);
    RUN(test_a_forwarded_port_reaches_the_inside_server_byte_for_byte);
    RUN(test_only_a_first_packet_opens_a_forwarded_connection);
    RUN(test_undo_forgets_only_a_connection_the_last_packet_opened);
    RUN(test_icmp_errors_about_a_forwarded_connection_are_translated);
    RUN(test_forward_ports_must_stay_out_of_the_nat_port_range);
    RUN(test_forwards_change_on_reload_and_mappings_follow_their_flows);
    TEST_DONE();
}

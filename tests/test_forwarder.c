/*=============================================================================
 * File Name:   test_forwarder.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Tests for the packet loop using unix datagram socket pairs in
 *              place of tun devices (each datagram is one packet, like a tun
 *              read). No root needed. Covers forwarding both ways, dropping,
 *              parse failures, bursts, write and read failures, expiry timing,
 *              and allocation failure.
 =============================================================================*/

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "engine.h"
#include "forwarder.h"
#include "fwalloc.h"
#include "parser.h"
#include "pktbuild.h"
#include "rules.h"
#include "testutil.h"

#define CLIENT IP4(10, 0, 1, 2)
#define SERVER IP4(10, 0, 2, 2)
#define ATTACKER IP4(10, 0, 2, 3)

static const char *RULES =
    "inside 10.0.1.0/24\n"
    "allow out tcp 10.0.1.0/24 any 80,443\n"
    "allow out udp 10.0.1.0/24 any 53\n"
    "allow in tcp any 10.0.1.3 22\n";

/* A forwarder wired to two socket pairs. The test talks on in_t / out_t, the
 * forwarder on the other end of each pair. */
struct rig {
    engine_t *e;
    forwarder_t *f;
    int in_t, out_t;          /* test side */
    int in_f, out_f;          /* forwarder side */
};

static uint64_t fake_now;
static uint64_t fake_clock(void) { return fake_now; }

static int rig_up(struct rig *r, const char *rules)
{
    int a[2], b[2];
    char err[128];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, a) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, b) == 0);
    r->in_f = a[0]; r->in_t = a[1];
    r->out_f = b[0]; r->out_t = b[1];
    fcntl(r->in_t, F_SETFL, O_NONBLOCK);
    fcntl(r->out_t, F_SETFL, O_NONBLOCK);
    r->e = engine_create_with_rules(rules_parse_string(rules, err, sizeof err));
    r->f = r->e ? fwd_create(r->e, r->in_f, r->out_f) : NULL;
    CHECK(r->e != NULL && r->f != NULL);
    fake_now = SEC;
    if (r->f) fwd_set_clock(r->f, fake_clock);
    return r->f != NULL;
}

static void rig_down(struct rig *r)
{
    fwd_destroy(r->f);
    engine_destroy(r->e);
    close(r->in_t); close(r->out_t); close(r->in_f); close(r->out_f);
}

static void send_pkt(int fd, const uint8_t *p, size_t n)
{
    CHECK(send(fd, p, n, 0) == (ssize_t)n);
}

/* Receive one packet if any is waiting; returns its length or -1. */
static ssize_t recv_pkt(int fd, uint8_t *buf, size_t cap)
{
    return recv(fd, buf, cap, 0);
}

static size_t syn(uint8_t *b, uint32_t s, uint16_t sp, uint32_t d, uint16_t dp, uint8_t flags)
{
    return pb_tcp(b, 256, NULL, s, sp, d, dp, flags, NULL, 0);
}

static void test_allowed_packets_cross_unchanged_in_both_directions(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256], got[256];
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    ssize_t g = recv_pkt(r.out_t, got, sizeof got);
    CHECK(g == (ssize_t)n && memcmp(got, p, n) == 0);          /* byte for byte */

    n = syn(p, SERVER, 80, CLIENT, 40000, TCP_SYN | TCP_ACK);   /* the reply */
    send_pkt(r.out_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    g = recv_pkt(r.in_t, got, sizeof got);
    CHECK(g == (ssize_t)n && memcmp(got, p, n) == 0);

    fwd_counters_t c;
    fwd_get_counters(r.f, &c);
    CHECK(c.rx[DIR_IN] == 1 && c.rx[DIR_OUT] == 1);
    CHECK(c.forwarded[DIR_IN] == 1 && c.forwarded[DIR_OUT] == 1);
    CHECK(c.write_errors == 0);
    rig_down(&r);
}

static void test_denied_packets_are_not_forwarded(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256], got[256];
    /* unsolicited inbound SYN to a port with no rule */
    size_t n = syn(p, ATTACKER, 4444, IP4(10, 0, 1, 3), 3389, TCP_SYN);
    send_pkt(r.out_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.in_t, got, sizeof got) < 0 && errno == EAGAIN);
    /* an exposed port is let through */
    n = syn(p, ATTACKER, 4445, IP4(10, 0, 1, 3), 22, TCP_SYN);
    send_pkt(r.out_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.in_t, got, sizeof got) == (ssize_t)n);

    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.pkts_total == 2 && s.pkts_allowed == 1 && s.drops[DROP_NO_RULE] == 1);
    fwd_counters_t c;
    fwd_get_counters(r.f, &c);
    CHECK(c.rx[DIR_OUT] == 2 && c.forwarded[DIR_OUT] == 1);
    rig_down(&r);
}

static void test_unparsable_packets_are_dropped_and_counted(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256], got[256];
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);

    send_pkt(r.in_t, p, n - 5);                    /* truncated */
    uint8_t bad[256]; memcpy(bad, p, n); bad[n - 1] ^= 0xff;
    send_pkt(r.in_t, bad, n);                      /* bad TCP checksum */
    uint8_t junk[40]; memset(junk, 0xA5, sizeof junk);
    send_pkt(r.in_t, junk, sizeof junk);           /* not IP at all */
    send_pkt(r.in_t, p, 0);                        /* empty datagram */
    CHECK(fwd_step(r.f, 100) == 0);

    CHECK(recv_pkt(r.out_t, got, sizeof got) < 0 && errno == EAGAIN);
    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.pkts_total == 4 && s.pkts_dropped == 4 && s.pkts_allowed == 0);
    unsigned long fails = 0;
    for (int i = 1; i < ENGINE_PARSE_KINDS; i++) fails += s.parse_fail[i];
    CHECK(fails == 4);
    rig_down(&r);
}

static void test_a_burst_is_bounded_and_keeps_order(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\n")) return;
    uint8_t p[256], got[256];
    const int total = 100;
    for (int i = 0; i < total; i++) {
        size_t n = pb_udp(p, sizeof p, NULL, CLIENT, (uint16_t)(1000 + i), SERVER, 53, NULL, 0);
        send_pkt(r.in_t, p, n);
    }
    CHECK(fwd_step(r.f, 0) == 0);
    int first = 0;
    while (recv_pkt(r.out_t, got, sizeof got) > 0) first++;
    CHECK(first == FWD_BURST);                      /* one wakeup does not starve the other side */
    CHECK(fwd_step(r.f, 0) == 0);
    int second = 0, last_port = -1;
    ssize_t g;
    while ((g = recv_pkt(r.out_t, got, sizeof got)) > 0) {
        second++;
        pkt_t pk;
        CHECK(parse_packet(got, (size_t)g, &pk) == PARSE_OK);
        CHECK((int)pk.src_port > last_port);        /* order preserved */
        last_port = pk.src_port;
    }
    CHECK(first + second == total);
    CHECK(last_port == 1000 + total - 1);
    rig_down(&r);
}

static void test_the_other_side_refusing_a_write_is_counted_not_fatal(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256];
    close(r.out_t);                                 /* nobody is listening outside */
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);                 /* keeps running */
    fwd_counters_t c;
    fwd_get_counters(r.f, &c);
    CHECK(c.rx[DIR_IN] == 1 && c.forwarded[DIR_IN] == 0);
    CHECK(c.write_errors == 1 && c.last_write_errno != 0);
    r.out_t = open("/dev/null", O_RDONLY);          /* so rig_down can close it */
    rig_down(&r);
}

static void test_a_failed_descriptor_stops_the_loop(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    close(r.in_f);                                  /* descriptor dies under us */
    CHECK(fwd_step(r.f, 100) == -1);
    r.in_f = open("/dev/null", O_RDONLY);
    rig_down(&r);
}

static void test_a_read_error_stops_the_loop(void)
{
    /* A descriptor that polls readable but whose read() fails with something
     * other than "try again" (here EISDIR) is a real failure, not a quiet
     * moment: the loop must report it so the program can stop. */
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    int dirfd = open("/", O_RDONLY);
    CHECK(dirfd >= 0);
    forwarder_t *f = fwd_create(r.e, dirfd, r.out_f);
    CHECK(f != NULL);
    if (f) {
        CHECK(fwd_step(f, 100) == -1);
        fwd_destroy(f);
    }
    close(dirfd);
    rig_down(&r);
}

static void test_idle_wait_times_out_quietly(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    CHECK(fwd_step(r.f, 10) == 0);
    fwd_counters_t c;
    fwd_get_counters(r.f, &c);
    CHECK(c.rx[0] == 0 && c.rx[1] == 0);
    rig_down(&r);
}

static void test_expired_flows_are_swept_about_once_a_second(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\n")) return;
    uint8_t p[256];
    const uint64_t MS = SEC / 1000;
    engine_stats_t s;

    /* The UDP flow is created at 1 s and times out at 31 s. */
    size_t n = pb_udp(p, sizeof p, NULL, CLIENT, 5000, SERVER, 53, NULL, 0);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 0) == 0);
    engine_get_stats(r.e, &s);
    CHECK(s.flows_active == 1 && s.flows_expired == 0);

    fake_now = 30 * SEC + 500 * MS;              /* sweeps, flow not idle long enough yet */
    CHECK(fwd_step(r.f, 0) == 0);
    engine_get_stats(r.e, &s);
    CHECK(s.flows_active == 1 && s.flows_expired == 0);

    fake_now = 31 * SEC + 200 * MS;              /* flow is now expired, but the last sweep was */
    CHECK(fwd_step(r.f, 0) == 0);                /* only 0.7 s ago, so no sweep yet */
    engine_get_stats(r.e, &s);
    CHECK(s.flows_active == 1 && s.flows_expired == 0);

    fake_now = 31 * SEC + 600 * MS;              /* over a second since the last sweep: it goes */
    CHECK(fwd_step(r.f, 0) == 0);
    engine_get_stats(r.e, &s);
    CHECK(s.flows_active == 0 && s.flows_expired == 1);
    rig_down(&r);
}

static void test_stats_report_includes_io_counters(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256];
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);
    send_pkt(r.in_t, p, n);
    fwd_step(r.f, 100);
    FILE *f = tmpfile();
    fwd_print_stats(r.f, f);
    rewind(f);
    char text[2048];
    size_t got = fread(text, 1, sizeof text - 1, f);
    text[got] = '\0';
    CHECK(strstr(text, "packets: total=1 allowed=1 dropped=0") != NULL);
    CHECK(strstr(text, "io:") != NULL && strstr(text, "write-errors=0") != NULL);
    fclose(f);
    rig_down(&r);
}

static void test_create_rejects_bad_arguments_and_survives_oom(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    CHECK(fwd_create(NULL, r.in_f, r.out_f) == NULL);
    CHECK(fwd_create(r.e, -1, r.out_f) == NULL);
    CHECK(fwd_create(r.e, r.in_f, -1) == NULL);
    int failures = 0;
    for (long k = 1; k < 8; k++) {
        fw_alloc_fail_nth(k);
        forwarder_t *f = fwd_create(r.e, r.in_f, r.out_f);
        if (!fw_alloc_failure_fired()) { fwd_destroy(f); break; }
        failures++;
        CHECK(f == NULL);
    }
    fw_alloc_fail_nth(0);
    CHECK(failures == 2);                           /* the struct, then the packet buffer */
    fwd_destroy(NULL);                              /* harmless */
    rig_down(&r);
}

int main(void)
{
    RUN(test_allowed_packets_cross_unchanged_in_both_directions);
    RUN(test_denied_packets_are_not_forwarded);
    RUN(test_unparsable_packets_are_dropped_and_counted);
    RUN(test_a_burst_is_bounded_and_keeps_order);
    RUN(test_the_other_side_refusing_a_write_is_counted_not_fatal);
    RUN(test_a_failed_descriptor_stops_the_loop);
    RUN(test_a_read_error_stops_the_loop);
    RUN(test_idle_wait_times_out_quietly);
    RUN(test_expired_flows_are_swept_about_once_a_second);
    RUN(test_stats_report_includes_io_counters);
    RUN(test_create_rejects_bad_arguments_and_survives_oom);
    TEST_DONE();
}

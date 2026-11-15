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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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

/* Identical except for the TTL byte and the IP header checksum it changes. */
static bool same_but_ttl(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i] && i != 8 && i != 10 && i != 11) return false;
    return true;
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
    CHECK(g == (ssize_t)n && same_but_ttl(got, p, n));         /* byte for byte */

    n = syn(p, SERVER, 80, CLIENT, 40000, TCP_SYN | TCP_ACK);   /* the reply */
    send_pkt(r.out_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    g = recv_pkt(r.in_t, got, sizeof got);
    CHECK(g == (ssize_t)n && same_but_ttl(got, p, n));

    fwd_counters_t c;
    fwd_get_counters(r.f, &c);
    CHECK(c.rx[DIR_IN] == 1 && c.rx[DIR_OUT] == 1);
    CHECK(c.forwarded[DIR_IN] == 1 && c.forwarded[DIR_OUT] == 1);
    CHECK(c.write_errors == 0);
    rig_down(&r);
}

static void test_ttl_is_given_back_so_the_firewall_counts_as_one_hop(void)
{
    /* The kernel takes 1 off the TTL when it routes a packet into the tun
     * device and another when it routes it out: two hops. The forwarder adds 1
     * so the firewall is one hop, as traceroute and TTL-limited probes expect. */
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    uint8_t p[256], got[256];
    const uint8_t ttls[] = { 1, 2, 63, 64, 128, 254 };
    for (size_t i = 0; i < sizeof ttls; i++) {
        struct pb_opts o = { .ttl = ttls[i] };
        size_t n = pb_tcp(p, sizeof p, &o, CLIENT, (uint16_t)(40000 + i), SERVER, 80, TCP_SYN, NULL, 0);
        send_pkt(r.in_t, p, n);
        CHECK(fwd_step(r.f, 100) == 0);
        CHECK(recv_pkt(r.out_t, got, sizeof got) == (ssize_t)n);
        CHECK(got[8] == ttls[i] + 1);
        pkt_t pk;
        CHECK(parse_packet(got, n, &pk) == PARSE_OK);       /* header checksum still valid */
        CHECK(same_but_ttl(got, p, n));
    }
    /* a TTL of 255 cannot go up: the packet is forwarded unchanged */
    struct pb_opts o = { .ttl = 255 };
    size_t n = pb_tcp(p, sizeof p, &o, CLIENT, 41000, SERVER, 80, TCP_SYN, NULL, 0);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.out_t, got, sizeof got) == (ssize_t)n && memcmp(got, p, n) == 0);
    /* the same holds for the reply direction and for UDP / ICMP */
    n = pb_tcp(p, sizeof p, NULL, SERVER, 80, CLIENT, 40000, TCP_SYN | TCP_ACK, NULL, 0);
    send_pkt(r.out_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.in_t, got, sizeof got) == (ssize_t)n && got[8] == 65);
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
    CHECK(fwd_step(r.f, 100) == 0);

    CHECK(recv_pkt(r.out_t, got, sizeof got) < 0 && errno == EAGAIN);
    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.pkts_total == 3 && s.pkts_dropped == 3 && s.pkts_allowed == 0);
    unsigned long fails = 0;
    for (int i = 1; i < ENGINE_PARSE_KINDS; i++) fails += s.parse_fail[i];
    CHECK(fails == 3);
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
    /* nobody saw the SYN, so no flow may be left behind for it */
    engine_stats_t st;
    engine_get_stats(r.e, &st);
    CHECK(st.flows_active == 0 && st.flows_created == 0);
    CHECK(st.pkts_allowed == 0 && st.drops[DROP_WRITE_FAILED] == 1);
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

static void test_end_of_file_and_hangup_are_failures_with_a_reason(void)
{
    /* A closed stream reads 0 forever: that is EOF, not an empty packet. */
    int st[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, st) == 0);
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    forwarder_t *f = fwd_create(r.e, st[0], r.out_f);
    close(st[1]);
    errno = 0;
    CHECK(fwd_step(f, 100) == -1 && errno == EPIPE);
    fwd_counters_t c;
    fwd_get_counters(f, &c);
    CHECK(c.rx[DIR_IN] == 0);                       /* no phantom packets */
    fwd_destroy(f);
    close(st[0]);

    /* a pipe whose writer went away: hang-up with nothing to read */
    int pp[2];
    CHECK(pipe(pp) == 0);
    f = fwd_create(r.e, pp[0], r.out_f);
    close(pp[1]);
    errno = 0;
    CHECK(fwd_step(f, 100) == -1 && errno == EIO);
    fwd_destroy(f);
    close(pp[0]);

    /* a packet followed by hang-up: the packet is still forwarded, then it fails */
    CHECK(pipe(pp) == 0);
    f = fwd_create(r.e, pp[0], r.out_f);
    uint8_t p[256], got[256];
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);
    CHECK(write(pp[1], p, n) == (ssize_t)n);
    close(pp[1]);
    CHECK(fwd_step(f, 100) == -1);
    CHECK(recv_pkt(r.out_t, got, sizeof got) == (ssize_t)n);
    fwd_destroy(f);
    close(pp[0]);
    rig_down(&r);
}

static void test_packets_over_the_ip_size_limit_are_never_forwarded(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\n")) return;
    static uint8_t big[70000], got[70000];
    /* a 70000-byte datagram: more than any IPv4 packet; its header lies */
    size_t n = pb_udp(big, 65535, NULL, CLIENT, 5000, SERVER, 53, NULL, 0);
    memset(big + n, 0xAB, 70000 - n);
    send_pkt(r.in_t, big, 70000);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.out_t, got, sizeof got) < 0 && errno == EAGAIN);
    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.pkts_total == 1 && s.pkts_dropped == 1 && s.parse_fail[PARSE_MALFORMED] == 1);

    /* but a maximum-size packet (65535 bytes) is fine, and arrives byte for byte */
    static uint8_t payload[65507];
    memset(payload, 0x5A, sizeof payload);
    n = pb_udp(big, sizeof big, NULL, CLIENT, 5001, SERVER, 53, payload, sizeof payload);
    CHECK(n == 65535);
    send_pkt(r.in_t, big, n);
    CHECK(fwd_step(r.f, 100) == 0);
    ssize_t g = recv_pkt(r.out_t, got, sizeof got);
    CHECK(g == 65535 && same_but_ttl(got, big, n));
    rig_down(&r);
}

static void test_both_sides_are_served_in_the_same_wakeup(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\nallow in udp any 10.0.1.2 53\n")) return;
    uint8_t p[256], got[256];
    for (int i = 0; i < 100; i++) {
        size_t n = pb_udp(p, sizeof p, NULL, CLIENT, (uint16_t)(1000 + i), SERVER, 53, NULL, 0);
        send_pkt(r.in_t, p, n);
        n = pb_udp(p, sizeof p, NULL, ATTACKER, (uint16_t)(2000 + i), CLIENT, 53, NULL, 0);
        send_pkt(r.out_t, p, n);
    }
    CHECK(fwd_step(r.f, 0) == 0);
    int to_out = 0, to_in = 0;
    while (recv_pkt(r.out_t, got, sizeof got) > 0) to_out++;
    while (recv_pkt(r.in_t, got, sizeof got) > 0) to_in++;
    CHECK(to_out == FWD_BURST && to_in == FWD_BURST);   /* neither side waits for the other */
    rig_down(&r);
}

static void test_expiry_runs_even_while_traffic_never_stops(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\n")) return;
    uint8_t p[256];
    size_t n = pb_udp(p, sizeof p, NULL, CLIENT, 5000, SERVER, 53, NULL, 0);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 0) == 0);
    /* every step has a new packet waiting, so poll() is always ready; the
     * clock moves 10 s per step; the first flow must still be swept */
    for (int i = 1; i <= 6; i++) {
        n = pb_udp(p, sizeof p, NULL, CLIENT, (uint16_t)(6000 + i), SERVER, 53, NULL, 0);
        send_pkt(r.in_t, p, n);
        fake_now += 10 * SEC;
        CHECK(fwd_step(r.f, 0) == 0);
    }
    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.flows_expired >= 1);
    rig_down(&r);
}

static void test_the_sweep_runs_at_exactly_one_second(void)
{
    struct rig r;
    if (!rig_up(&r, "inside 10.0.1.0/24\nallow out udp 10.0.1.0/24 any 53\n")) return;
    uint8_t p[256];
    size_t n = pb_udp(p, sizeof p, NULL, CLIENT, 5000, SERVER, 53, NULL, 0);
    send_pkt(r.in_t, p, n);                      /* created at 1 s, expires at 31 s */
    CHECK(fwd_step(r.f, 0) == 0);
    fake_now = 30 * SEC;
    CHECK(fwd_step(r.f, 0) == 0);                /* sweep at 30 s: still alive */
    fake_now = 31 * SEC - 1;
    CHECK(fwd_step(r.f, 0) == 0);                /* 1 ns short of a second: no sweep */
    engine_stats_t s;
    engine_get_stats(r.e, &s);
    CHECK(s.flows_expired == 0 && s.flows_active == 1);
    fake_now = 31 * SEC;                         /* exactly one second since the last sweep */
    CHECK(fwd_step(r.f, 0) == 0);
    engine_get_stats(r.e, &s);
    CHECK(s.flows_expired == 1 && s.flows_active == 0);
    rig_down(&r);
}

static void on_alarm(int sig) { (void)sig; }

static void test_an_interrupted_wait_returns_quietly_and_ppoll_works(void)
{
    struct rig r;
    if (!rig_up(&r, RULES)) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;                    /* no SA_RESTART: poll sees EINTR */
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = { {0, 0}, {0, 30000} };
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK(fwd_step(r.f, 2000) == 0);             /* EINTR is not a failure */

    /* with a signal mask installed (ppoll) it still works and still sees EINTR */
    sigset_t mask;
    sigemptyset(&mask);
    fwd_set_sigmask(r.f, &mask);
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK(fwd_step(r.f, 2000) == 0);
    uint8_t p[256], got[256];
    size_t n = syn(p, CLIENT, 40000, SERVER, 80, TCP_SYN);
    send_pkt(r.in_t, p, n);
    CHECK(fwd_step(r.f, 100) == 0);
    CHECK(recv_pkt(r.out_t, got, sizeof got) == (ssize_t)n);
    fwd_set_sigmask(r.f, NULL);                  /* back to plain poll */
    CHECK(fwd_step(r.f, 10) == 0);
    signal(SIGALRM, SIG_DFL);
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

static uint32_t g_rng = 0x2545F491u;
static uint32_t rng(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }

static void test_random_packets_through_the_forwarder_match_a_shadow_engine(void)
{
    /* Thousands of random and corrupted packets go through the real forwarder
     * while an identical engine, fed the same bytes, decides on its own. The
     * forwarder must pass on exactly what the engine allows, on the other
     * side, unchanged except for the TTL, and nothing else. */
    const char *policy = "inside 10.0.1.0/24\nallow out tcp 10.0.1.0/24 any 80,443\n"
                         "allow out udp 10.0.1.0/24 any 53\nallow out icmp 10.0.1.0/24 any echo\n"
                         "allow in tcp any 10.0.1.3 22\n";
    struct rig r;
    if (!rig_up(&r, policy)) return;
    char err[128];
    engine_t *shadow = engine_create_with_rules(rules_parse_string(policy, err, sizeof err));
    CHECK(shadow != NULL);
    if (!shadow) { rig_down(&r); return; }

    const uint32_t hosts[] = { IP4(10,0,1,2), IP4(10,0,1,3), IP4(10,0,2,2), IP4(10,0,2,3),
                               IP4(8,8,8,8), IP4(127,0,0,1), IP4(0,0,0,0), IP4(224,0,0,1) };
    const uint16_t ports[] = { 0, 22, 53, 80, 443, 3389, 40000 };
    const uint8_t flagsets[] = { TCP_SYN, TCP_SYN | TCP_ACK, TCP_ACK, TCP_ACK | TCP_PSH,
                                 TCP_FIN | TCP_ACK, TCP_RST, 0, TCP_SYN | TCP_FIN, 0x3f };
    uint8_t p[2048], got[2048];
    unsigned long forwarded = 0, expected_fwd = 0;
    for (int i = 0; i < 20000; i++) {
        const dir_t dir = rng() & 1 ? DIR_IN : DIR_OUT;
        const uint32_t src = hosts[rng() % 8], dst = hosts[rng() % 8];
        struct pb_opts o = { .ttl = (uint8_t)(rng() % 8 ? 64 : rng()) };
        size_t n;
        switch (rng() % 3) {
        case 0:  n = pb_tcp(p, sizeof p, &o, src, ports[rng() % 7], dst, ports[rng() % 7],
                            flagsets[rng() % 9], NULL, 0); break;
        case 1:  n = pb_udp(p, sizeof p, &o, src, ports[rng() % 7], dst, ports[rng() % 7], NULL, 0); break;
        default: n = pb_icmp_echo(p, sizeof p, &o, src, dst, rng() & 1 ? ICMP_ECHO_REQUEST : ICMP_ECHO_REPLY,
                                  (uint16_t)(rng() % 4), 1, NULL, 0); break;
        }
        if (n == 0) continue;
        if (rng() % 7 == 0) p[rng() % n] ^= (uint8_t)(1 + rng() % 255);      /* corrupt a byte */
        if (rng() % 11 == 0) n = 1 + rng() % n;                               /* truncate (never to 0: a tun never delivers an empty packet) */

        /* the shadow engine decides on the same bytes */
        pkt_t pk;
        bool allowed = false;
        if (parse_packet(p, n, &pk) == PARSE_OK)
            allowed = engine_decide(shadow, &pk, dir, fake_now, NULL) == VERDICT_ALLOW;
        else
            engine_parse_failed(shadow, PARSE_MALFORMED, dir, n, fake_now);

        send_pkt(dir == DIR_IN ? r.in_t : r.out_t, p, n);
        CHECK(fwd_step(r.f, 0) == 0);
        const int to = dir == DIR_IN ? r.out_t : r.in_t, back = dir == DIR_IN ? r.in_t : r.out_t;
        const ssize_t g = recv_pkt(to, got, sizeof got);
        if (allowed) {
            expected_fwd++;
            if (!(g == (ssize_t)n && same_but_ttl(got, p, n))) CHECK(false);
            else forwarded++;
        } else if (g >= 0) {
            CHECK(false);                       /* forwarded what the engine refused */
        }
        CHECK(recv_pkt(back, got, sizeof got) < 0);   /* never echoed back to the sender's side */
    }
    CHECK(forwarded == expected_fwd);
    CHECK(forwarded > 100);                     /* the run really did forward traffic */
    engine_stats_t a, b;
    engine_get_stats(r.e, &a);
    engine_get_stats(shadow, &b);
    CHECK(a.pkts_total == b.pkts_total && a.pkts_allowed == b.pkts_allowed &&
          a.pkts_dropped == b.pkts_dropped && a.flows_created == b.flows_created);
    engine_destroy(shadow);
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
    RUN(test_ttl_is_given_back_so_the_firewall_counts_as_one_hop);
    RUN(test_denied_packets_are_not_forwarded);
    RUN(test_unparsable_packets_are_dropped_and_counted);
    RUN(test_a_burst_is_bounded_and_keeps_order);
    RUN(test_the_other_side_refusing_a_write_is_counted_not_fatal);
    RUN(test_a_failed_descriptor_stops_the_loop);
    RUN(test_a_read_error_stops_the_loop);
    RUN(test_end_of_file_and_hangup_are_failures_with_a_reason);
    RUN(test_packets_over_the_ip_size_limit_are_never_forwarded);
    RUN(test_both_sides_are_served_in_the_same_wakeup);
    RUN(test_expiry_runs_even_while_traffic_never_stops);
    RUN(test_the_sweep_runs_at_exactly_one_second);
    RUN(test_an_interrupted_wait_returns_quietly_and_ppoll_works);
    RUN(test_idle_wait_times_out_quietly);
    RUN(test_random_packets_through_the_forwarder_match_a_shadow_engine);
    RUN(test_expired_flows_are_swept_about_once_a_second);
    RUN(test_stats_report_includes_io_counters);
    RUN(test_create_rejects_bad_arguments_and_survives_oom);
    TEST_DONE();
}

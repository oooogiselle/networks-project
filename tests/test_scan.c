/*=============================================================================
 * File Name:   test_scan.c
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Unit tests for port-scan detection (scandetect.c): the
 *              threshold, the sliding window, blocking and unblocking, and the
 *              fixed-size table.
 =============================================================================*/

#include "scandetect.h"
#include "testutil.h"

#define SCANNER IP(198,51,100,66)
#define OTHER   IP(203,0,113,9)
#define MS      1000000ull

static const scan_cfg_t CFG = { 20, 5, 60 };

/* Hit `n` distinct TCP ports starting at `first`, `step_ns` apart from t0.
 * Returns how many hits reported a new block. */
static int sweep(scan_t *s, uint32_t ip, uint16_t first, int n, uint64_t t0,
                 uint64_t step_ns)
{
    int blocks = 0;
    for (int i = 0; i < n; i++)
        blocks += scan_hit(s, ip, FW_PROTO_TCP, (uint16_t)(first + i),
                           t0 + (uint64_t)i * step_ns, NULL);
    return blocks;
}

static void test_threshold_exact(void)
{
    scan_t *s = scan_create(&CFG);
    CHECK(sweep(s, SCANNER, 1, 19, SEC, MS) == 0);
    CHECK(!scan_blocked(s, SCANNER, SEC + 19 * MS));
    CHECK(scan_nblocked(s) == 0);
    uint64_t span = 0;
    CHECK(scan_hit(s, SCANNER, FW_PROTO_TCP, 20, SEC + 19 * MS, &span));
    CHECK(span == 19 * MS);
    CHECK(scan_nblocked(s) == 1);
    CHECK(scan_blocked(s, SCANNER, SEC + 20 * MS));
    CHECK(!scan_blocked(s, OTHER, SEC + 20 * MS));
    /* Further hits while blocked don't start a second block. */
    CHECK(!scan_hit(s, SCANNER, FW_PROTO_TCP, 21, SEC + 21 * MS, NULL));
    CHECK(scan_nblocked(s) == 1);
    scan_destroy(s);
}

static void test_same_port_counts_once(void)
{
    scan_t *s = scan_create(&CFG);
    int blocks = 0;
    for (int i = 0; i < 100; i++)
        blocks += scan_hit(s, SCANNER, FW_PROTO_TCP, 3389, SEC + i * MS, NULL);
    CHECK(blocks == 0);
    CHECK(!scan_blocked(s, SCANNER, SEC + 100 * MS));
    scan_destroy(s);
}

static void test_tcp_and_udp_ports_distinct(void)
{
    scan_t *s = scan_create(&(scan_cfg_t){ 2, 5, 60 });
    CHECK(!scan_hit(s, SCANNER, FW_PROTO_TCP, 80, SEC, NULL));
    CHECK(scan_hit(s, SCANNER, FW_PROTO_UDP, 80, SEC, NULL));
    scan_destroy(s);
}

static void test_sliding_window(void)
{
    /* 20 ports 0.3 s apart span 5.7 s: never 20 inside any 5 s window. */
    scan_t *s = scan_create(&CFG);
    CHECK(sweep(s, SCANNER, 1, 20, SEC, 300 * MS) == 0);
    CHECK(!scan_blocked(s, SCANNER, SEC + 6 * SEC));
    scan_destroy(s);

    /* 20 ports 0.25 s apart span 4.75 s: blocked. */
    s = scan_create(&CFG);
    CHECK(sweep(s, SCANNER, 1, 20, SEC, 250 * MS) == 1);
    CHECK(scan_blocked(s, SCANNER, 6 * SEC));
    scan_destroy(s);

    /* First and 20th hit exactly 5 s apart: the first has aged out. */
    s = scan_create(&CFG);
    CHECK(sweep(s, SCANNER, 1, 19, SEC, 100 * MS) == 0);
    CHECK(!scan_hit(s, SCANNER, FW_PROTO_TCP, 100, SEC + 5 * SEC, NULL));
    scan_destroy(s);

    /* A scan straddling where a fixed window (started by the first hit at
     * 1 s, reset at 6 s) would split it: 1 port at 1 s, 18 at 5.9 s, 2 at
     * 6.1 s. The last 20 hits are within 5 s, so it is caught. */
    s = scan_create(&CFG);
    CHECK(sweep(s, SCANNER, 1, 1, SEC, 0) == 0);
    CHECK(sweep(s, SCANNER, 2, 18, 5900 * MS, 0) == 0);
    CHECK(sweep(s, SCANNER, 20, 2, 6100 * MS, 0) == 1);
    scan_destroy(s);
}

static int unblocked;
static uint32_t unblocked_ip;
static uint64_t unblocked_drops;
static void on_unblock(uint32_t ip, uint64_t dropped, void *ud)
{
    (void)ud;
    unblocked++;
    unblocked_ip = ip;
    unblocked_drops = dropped;
}

static void test_block_expires(void)
{
    scan_t *s = scan_create(&CFG);
    const uint64_t t = 10 * SEC;
    CHECK(sweep(s, SCANNER, 1, 20, t, 0) == 1);
    CHECK(scan_blocked(s, SCANNER, t + 1));
    CHECK(scan_blocked(s, SCANNER, t + 60 * SEC - 1));
    CHECK(!scan_blocked(s, SCANNER, t + 60 * SEC));    /* lazily over */

    unblocked = 0;
    CHECK(scan_expire(s, t + 59 * SEC, on_unblock, NULL) == 0);
    CHECK(unblocked == 0);
    CHECK(scan_expire(s, t + 60 * SEC, on_unblock, NULL) == 1);
    CHECK(unblocked == 1);
    CHECK(unblocked_ip == SCANNER);
    CHECK(unblocked_drops == 2);                       /* the two blocked checks */
    CHECK(scan_nblocked(s) == 0);
    CHECK(scan_expire(s, t + 61 * SEC, on_unblock, NULL) == 0);
    CHECK(unblocked == 1);

    /* Tracking starts from zero afterwards. */
    CHECK(sweep(s, SCANNER, 1, 19, t + 70 * SEC, 0) == 0);
    CHECK(sweep(s, SCANNER, 20, 1, t + 70 * SEC, 0) == 1);
    scan_destroy(s);
}

/*
 * The block ends lazily at t+60 s, but scan_expire() only runs once a
 * second. A new scan in that gap starts a fresh block in the same slot:
 * it is reported, nblocked isn't double counted, and the sweep in the gap
 * doesn't clear the new block.
 */
static void test_rescan_before_sweep(void)
{
    scan_t *s = scan_create(&CFG);
    const uint64_t t = 10 * SEC, end = t + 60 * SEC;
    CHECK(sweep(s, SCANNER, 1, 20, t, 0) == 1);
    CHECK(scan_blocked(s, SCANNER, t + SEC));                 /* 1 drop */
    CHECK(!scan_blocked(s, SCANNER, end + 100 * MS));         /* over, unswept */
    CHECK(scan_nblocked(s) == 1);

    uint64_t span = 0;
    CHECK(sweep(s, SCANNER, 100, 19, end + 200 * MS, 0) == 0);
    CHECK(scan_hit(s, SCANNER, FW_PROTO_TCP, 200, end + 300 * MS, &span));
    CHECK(span == 100 * MS);
    CHECK(scan_nblocked(s) == 1);
    CHECK(scan_blocked(s, SCANNER, end + 400 * MS));          /* 2nd drop */

    unblocked = 0;
    CHECK(scan_expire(s, end + SEC, on_unblock, NULL) == 0);  /* new block stays */
    CHECK(scan_blocked(s, SCANNER, end + SEC));               /* 3rd drop */
    CHECK(scan_expire(s, end + 300 * MS + 60 * SEC, on_unblock, NULL) == 1);
    CHECK(unblocked == 1);
    CHECK(unblocked_drops == 3);       /* one UNBLOCK covering both blocks */
    CHECK(scan_nblocked(s) == 0);
    CHECK(!scan_blocked(s, SCANNER, end + 61 * SEC));
    scan_destroy(s);
}

static void test_capacity_bounded(void)
{
    /* One set of SCAN_WAYS slots: every source shares it. */
    scan_t *s = scan_create_n(&(scan_cfg_t){ 2, 5, 60 }, 1);
    for (uint32_t i = 0; i < SCAN_WAYS; i++)
        CHECK(sweep(s, IP(10,9,9,1) + i, 1, 2, SEC, 0) == 1);
    CHECK(scan_nblocked(s) == SCAN_WAYS);

    /* Set full of blocked hosts: a new scanner isn't tracked, blocks stay. */
    CHECK(sweep(s, SCANNER, 1, 2, SEC, 0) == 0);
    CHECK(!scan_blocked(s, SCANNER, SEC));
    for (uint32_t i = 0; i < SCAN_WAYS; i++)
        CHECK(scan_blocked(s, IP(10,9,9,1) + i, SEC));

    /* Once the blocks are swept, the slots are reused. */
    CHECK(scan_expire(s, 61 * SEC, NULL, NULL) == SCAN_WAYS);
    CHECK(sweep(s, SCANNER, 1, 2, 62 * SEC, 0) == 1);
    scan_destroy(s);

    /* Unblocked sources are evicted least-recently-seen first. */
    s = scan_create_n(&(scan_cfg_t){ 3, 5, 60 }, 1);
    for (uint32_t i = 0; i < SCAN_WAYS; i++)
        sweep(s, IP(10,9,9,1) + i, 1, 1, SEC + i, 0);   /* 1 port each */
    sweep(s, SCANNER, 1, 1, 2 * SEC, 0);                /* evicts 10.9.9.1 */
    CHECK(sweep(s, IP(10,9,9,2), 2, 2, 2 * SEC, 0) == 1); /* kept its 1st port */
    CHECK(sweep(s, IP(10,9,9,1), 2, 2, 2 * SEC, 0) == 0); /* started over */
    scan_destroy(s);
}

static void test_invalid_config(void)
{
    CHECK(scan_create(&(scan_cfg_t){ 0, 5, 60 }) == NULL);
    CHECK(scan_create(&(scan_cfg_t){ SCAN_MAX_PORTS + 1, 5, 60 }) == NULL);
    CHECK(scan_create(&(scan_cfg_t){ 20, 0, 60 }) == NULL);
    CHECK(scan_create(&(scan_cfg_t){ 20, 5, 0 }) == NULL);
    scan_t *s = scan_create(&(scan_cfg_t){ SCAN_MAX_PORTS, 5, 60 });
    CHECK(s != NULL);
    CHECK(sweep(s, SCANNER, 1, SCAN_MAX_PORTS, SEC, 0) == 1);
    scan_destroy(s);
}

int main(void)
{
    RUN(test_threshold_exact);
    RUN(test_same_port_counts_once);
    RUN(test_tcp_and_udp_ports_distinct);
    RUN(test_sliding_window);
    RUN(test_block_expires);
    RUN(test_rescan_before_sweep);
    RUN(test_capacity_bounded);
    RUN(test_invalid_config);
    TEST_DONE();
}

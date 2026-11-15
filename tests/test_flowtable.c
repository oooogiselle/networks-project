/*=============================================================================
 * File Name:   test_flowtable.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Unit tests for the flow table: lookup in both directions,
 *              expiry, capacity limits, and slot reuse.
 =============================================================================*/

#include "flowtable.h"
#include "siphash.h"
#include "testutil.h"

static flow_key_t K(uint32_t s, uint16_t sp, uint32_t d, uint16_t dp)
{
    flow_key_t k = { s, d, sp, dp, FW_PROTO_TCP };
    return k;
}

static void test_insert_and_lookup_both_directions(void)
{
    flowtable_t *ft = ft_create(64, 100);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 80);
    flow_t *f = ft_insert(ft, &k, DIR_IN, 0);
    f->expires_ns = 10 * SEC;

    bool reply = true;
    CHECK(ft_lookup(ft, &k, SEC, &reply) == f);
    CHECK(!reply);

    flow_key_t rev = ft_reverse(&k);
    CHECK(ft_lookup(ft, &rev, SEC, &reply) == f);
    CHECK(reply);

    flow_key_t other = K(IP(10,0,0,2), 5001, IP(1,2,3,4), 80);
    CHECK(ft_lookup(ft, &other, SEC, &reply) == NULL);
    ft_destroy(ft);
}

static void test_protocol_is_part_of_key(void)
{
    flowtable_t *ft = ft_create(64, 100);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 53);
    ft_insert(ft, &k, DIR_IN, 0)->expires_ns = 10 * SEC;
    k.proto = FW_PROTO_UDP;
    bool r;
    CHECK(ft_lookup(ft, &k, SEC, &r) == NULL);
    ft_destroy(ft);
}

static void hook_counter(const flow_t *f, void *ud)
{
    int *n = ud;
    (*n)++;
    *n += (f->key.dst_port == 80) ? 0 : 100;     /* wrong flow reported */
}

static void test_lazy_expiry_calls_the_hook_once(void)
{
    flowtable_t *ft = ft_create(64, 100);
    int calls = 0;
    ft_set_expire_hook(ft, hook_counter, &calls);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 80);
    ft_insert(ft, &k, DIR_IN, 0)->expires_ns = 5 * SEC;
    bool r;
    CHECK(ft_lookup(ft, &k, 4 * SEC, &r) != NULL);
    CHECK(calls == 0);                                /* alive: no report */
    CHECK(ft_lookup(ft, &k, 5 * SEC, &r) == NULL);
    CHECK(calls == 1);                                /* removed on touch: reported */
    CHECK(ft_lookup(ft, &k, 6 * SEC, &r) == NULL);
    CHECK(calls == 1);                                /* gone: not reported again */
    ft_destroy(ft);
}

static void test_sweep_removes_a_flow_exactly_at_its_expiry(void)
{
    /* Lookup treats now == expires_ns as expired; the sweep must agree, or a
     * flow could survive a sweep and then vanish on its next packet. */
    flowtable_t *ft = ft_create(64, 100);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 80);
    ft_insert(ft, &k, DIR_IN, 0)->expires_ns = 5 * SEC;
    CHECK(ft_expire(ft, 5 * SEC - 1, NULL, NULL) == 0);      /* 1 ns early: stays */
    CHECK(ft_count(ft) == 1);
    CHECK(ft_expire(ft, 5 * SEC, NULL, NULL) == 1);          /* exactly due: goes */
    CHECK(ft_count(ft) == 0);
    ft_destroy(ft);
}

/* ---- keyed hash: an attacker must not be able to pick colliding flows ---- */

static void test_siphash_matches_the_published_vectors(void)
{
    /* SipHash-2-4 reference vectors: key 00 01 .. 0f, input 00 01 .. (len-1) */
    uint8_t key[16], in[16];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)i; in[i] = (uint8_t)i; }
    CHECK(fw_siphash24(key, in, 0)  == 0x726fdb47dd0e0e31ull);
    CHECK(fw_siphash24(key, in, 8)  == 0x93f5f5799a932462ull);
    CHECK(fw_siphash24(key, in, 15) == 0xa129ca6149be45e5ull);
}

static void fill_key(uint8_t key[16], uint8_t seed)
{
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(seed * 31 + i * 7 + 1);
}

static void test_precomputed_collisions_do_not_survive_a_different_key(void)
{
    /* The attack on an unkeyed hash: find many flows in one bucket offline,
     * then send them. Find 300 that collide under key A, and check they
     * spread out under key B (while still colliding under A). */
    enum { NB = 1024, WANT = 300 };
    uint8_t ka[16], kb[16];
    fill_key(ka, 1); fill_key(kb, 2);
    flowtable_t *a = ft_create_keyed(NB, 16, ka);
    flowtable_t *b = ft_create_keyed(NB, 16, kb);
    CHECK(a && b);
    if (!a || !b) { ft_destroy(a); ft_destroy(b); return; }

    flow_key_t found[WANT];
    int n = 0;
    for (uint32_t i = 0; n < WANT && i < 4000000; i++) {
        flow_key_t k = { IP(198,51,100,7), IP(10,0,1,3), (uint16_t)(1024 + i % 60000),
                         22, FW_PROTO_TCP };
        k.src_ip += i / 60000;
        if (ft_bucket_of(a, &k) == 0) found[n++] = k;
    }
    CHECK(n == WANT);

    unsigned load[NB] = {0}, worst = 0;
    for (int i = 0; i < n; i++) {
        CHECK(ft_bucket_of(a, &found[i]) == 0);          /* same key: still colliding */
        unsigned l = ++load[ft_bucket_of(b, &found[i])];
        if (l > worst) worst = l;
    }
    CHECK(worst <= 8);                  /* a fair spread of 300 over 1024 */
    ft_destroy(a);
    ft_destroy(b);
}

static void test_each_table_gets_its_own_random_key(void)
{
    flowtable_t *a = ft_create(1024, 16), *b = ft_create(1024, 16);
    CHECK(a && b);
    if (!a || !b) { ft_destroy(a); ft_destroy(b); return; }
    int differ = 0;
    for (uint16_t p = 1; p <= 64; p++) {
        flow_key_t k = K(IP(10,0,0,2), p, IP(1,2,3,4), 80);
        if (ft_bucket_of(a, &k) != ft_bucket_of(b, &k)) differ++;
    }
    CHECK(differ > 0);                  /* equal keys would map all 64 identically */
    ft_destroy(a);
    ft_destroy(b);
}

static void test_absurd_sizes_are_refused_not_looped_on(void)
{
    CHECK(ft_create((size_t)-1, 16) == NULL);          /* used to loop forever */
    CHECK(ft_create(64, (size_t)-1) == NULL);
    CHECK(ft_create(FT_MAX_BUCKETS + 1, 16) == NULL);
    CHECK(ft_create(64, FT_MAX_FLOWS + 1) == NULL);
}

static void test_lazy_expiry(void)
{
    flowtable_t *ft = ft_create(64, 100);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 80);
    ft_insert(ft, &k, DIR_IN, 0)->expires_ns = 5 * SEC;
    bool r;
    CHECK(ft_lookup(ft, &k, 4 * SEC, &r) != NULL);
    CHECK(ft_lookup(ft, &k, 5 * SEC, &r) == NULL);   /* expired on touch */
    CHECK(ft_count(ft) == 0);
    CHECK(ft_expired_total(ft) == 1);
    ft_destroy(ft);
}

static int cb_count;
static void cb(const flow_t *f, void *ud) { (void)f; (void)ud; cb_count++; }

static void test_sweep_removes_only_expired(void)
{
    flowtable_t *ft = ft_create(8, 1000);   /* few buckets => chains */
    for (int i = 0; i < 100; i++) {
        flow_key_t k = K(IP(10,0,0,2), 1000 + i, IP(1,2,3,4), 80);
        ft_insert(ft, &k, DIR_IN, 0)->expires_ns = (i % 2 ? 5 : 50) * SEC;
    }
    CHECK(ft_count(ft) == 100);
    cb_count = 0;
    CHECK(ft_expire(ft, 10 * SEC, cb, NULL) == 50);
    CHECK(cb_count == 50);
    CHECK(ft_count(ft) == 50);
    CHECK(ft_expire(ft, 100 * SEC, NULL, NULL) == 50);
    CHECK(ft_count(ft) == 0);
    ft_destroy(ft);
}

static void test_capacity_limit(void)
{
    flowtable_t *ft = ft_create(16, 3);
    for (int i = 0; i < 3; i++) {
        flow_key_t k = K(IP(10,0,0,2), 1000 + i, IP(1,2,3,4), 80);
        CHECK(ft_insert(ft, &k, DIR_IN, 0) != NULL);
    }
    flow_key_t k = K(IP(10,0,0,2), 2000, IP(1,2,3,4), 80);
    CHECK(ft_insert(ft, &k, DIR_IN, 0) == NULL);
    ft_destroy(ft);
}

static void test_remove(void)
{
    flowtable_t *ft = ft_create(8, 100);
    flow_key_t a = K(IP(10,0,0,2), 1, IP(1,1,1,1), 80);
    flow_key_t b = K(IP(10,0,0,2), 2, IP(1,1,1,1), 80);
    ft_insert(ft, &a, DIR_IN, 0)->expires_ns = 99 * SEC;
    flow_t *fb = ft_insert(ft, &b, DIR_IN, 0);
    fb->expires_ns = 99 * SEC;
    ft_remove(ft, fb);
    bool r;
    CHECK(ft_lookup(ft, &b, SEC, &r) == NULL);
    CHECK(ft_lookup(ft, &a, SEC, &r) != NULL);
    CHECK(ft_count(ft) == 1);
    ft_destroy(ft);
}

static void test_slots_are_reused_not_reallocated(void)
{
    flowtable_t *ft = ft_create(8, 4);
    flow_t *slots[4];
    for (int i = 0; i < 4; i++) {
        flow_key_t k = K(IP(10,0,0,2), 1000 + i, IP(1,2,3,4), 80);
        slots[i] = ft_insert(ft, &k, DIR_IN, 0);
        CHECK(slots[i] != NULL);
    }
    flow_key_t extra = K(IP(10,0,0,2), 2000, IP(1,2,3,4), 80);
    CHECK(ft_insert(ft, &extra, DIR_IN, 0) == NULL);        /* full */

    /* dirty a flow, free it, and the slot comes back clean */
    slots[1]->pkts[0] = 99;
    slots[1]->tcp_state = TCPS_ESTABLISHED;
    slots[1]->seen_reply = true;
    slots[1]->rule_line = 7;
    ft_remove(ft, slots[1]);
    CHECK(ft_count(ft) == 3);
    flow_t *again = ft_insert(ft, &extra, DIR_OUT, 5 * SEC);
    CHECK(again == slots[1]);                               /* same memory */
    CHECK(again->pkts[0] == 0 && again->tcp_state == TCPS_NONE &&
          !again->seen_reply && again->rule_line == 0);
    CHECK(again->orig_dir == DIR_OUT && again->created_ns == 5 * SEC);
    CHECK(again->key.src_port == 2000);
    ft_destroy(ft);
}

static void test_churn_never_exceeds_capacity(void)
{
    /* insert/expire far more flows than there are slots, in waves */
    flowtable_t *ft = ft_create(16, 32);
    uint64_t t = 0;
    for (int wave = 0; wave < 200; wave++) {
        for (int i = 0; i < 32; i++) {
            flow_key_t k = K(IP(10,0,0,2), 1000 + i, IP(1,2,3,4), 80 + wave);
            flow_t *f = ft_insert(ft, &k, DIR_IN, t);
            CHECK(f != NULL);
            if (f) f->expires_ns = t + 10;
        }
        flow_key_t k = K(IP(9,9,9,9), 1, IP(1,2,3,4), 1);
        CHECK(ft_insert(ft, &k, DIR_IN, t) == NULL);        /* still full */
        t += 100;
        CHECK(ft_expire(ft, t, NULL, NULL) == 32);
        CHECK(ft_count(ft) == 0);
    }
    ft_destroy(ft);
}

static void test_zero_capacity_table_refuses_everything(void)
{
    flowtable_t *ft = ft_create(8, 0);
    flow_key_t k = K(IP(10,0,0,2), 1, IP(1,2,3,4), 80);
    CHECK(ft != NULL && ft_insert(ft, &k, DIR_IN, 0) == NULL);
    ft_destroy(ft);
}

int main(void)
{
    RUN(test_insert_and_lookup_both_directions);
    RUN(test_protocol_is_part_of_key);
    RUN(test_siphash_matches_the_published_vectors);
    RUN(test_precomputed_collisions_do_not_survive_a_different_key);
    RUN(test_each_table_gets_its_own_random_key);
    RUN(test_absurd_sizes_are_refused_not_looped_on);
    RUN(test_sweep_removes_a_flow_exactly_at_its_expiry);
    RUN(test_lazy_expiry);
    RUN(test_lazy_expiry_calls_the_hook_once);
    RUN(test_sweep_removes_only_expired);
    RUN(test_capacity_limit);
    RUN(test_remove);
    RUN(test_slots_are_reused_not_reallocated);
    RUN(test_churn_never_exceeds_capacity);
    RUN(test_zero_capacity_table_refuses_everything);
    TEST_DONE();
}

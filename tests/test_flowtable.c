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

#include <stdio.h>

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

/* Find a key that differs from base ONLY in the field `which`, yet lands in the
 * same bucket, so a lookup has to rely on the key comparison itself (not on a
 * lucky difference in the hash) to tell the two apart. */
static bool colliding_variant(const flowtable_t *ft, const flow_key_t *base, int which, flow_key_t *out)
{
    for (uint32_t v = 1; v < 5000; v++) {
        flow_key_t k = *base;
        switch (which) {
        case 0: k.src_ip   = base->src_ip + v; break;
        case 1: k.dst_ip   = base->dst_ip + v; break;
        case 2: k.src_port = (uint16_t)(base->src_port + v); break;
        case 3: k.dst_port = (uint16_t)(base->dst_port + v); break;
        default: k.proto   = (uint8_t)(base->proto + v); break;
        }
        if (v >= 250 && which == 4) return false;                  /* proto is 8 bits */
        if (ft_bucket_of(ft, &k) == ft_bucket_of(ft, base)) { *out = k; return true; }
    }
    return false;
}

static void test_every_field_is_part_of_the_key(void)
{
    /* A 16-bucket table makes same-bucket variants easy to find; each field
     * must then be compared, or a flow would answer for a different one. */
    uint8_t hk[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    const char *names[] = { "src ip", "dst ip", "src port", "dst port", "protocol" };
    for (int which = 0; which < 5; which++) {
        flowtable_t *ft = ft_create_keyed(16, 100, hk);
        flow_key_t base = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 53), other;
        ft_insert(ft, &base, DIR_IN, 0)->expires_ns = 10 * SEC;
        const bool found = colliding_variant(ft, &base, which, &other);
        CHECK(found);
        if (found) {
            bool r;
            if (!(ft_lookup(ft, &other, SEC, &r) == NULL))
                fprintf(stderr, "  the %s is not compared\n", names[which]);
            CHECK(ft_lookup(ft, &other, SEC, &r) == NULL);
            /* and the real flow is still found */
            CHECK(ft_lookup(ft, &base, SEC, &r) != NULL && !r);
        }
        ft_destroy(ft);
    }
}

static void test_removing_a_flow_twice_does_nothing_the_second_time(void)
{
    flowtable_t *ft = ft_create(16, 4);
    flow_key_t k = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 53);
    flow_t *f = ft_insert(ft, &k, DIR_IN, 0);
    ft_remove(ft, f);
    CHECK(ft_count(ft) == 0);
    ft_remove(ft, f);                                  /* already gone: no effect */
    CHECK(ft_count(ft) == 0);
    for (int i = 0; i < 4; i++) {                      /* the free list is intact: exactly 4 slots */
        flow_key_t n = K(IP(10,0,0,2), (uint16_t)(6000 + i), IP(1,2,3,4), 53);
        CHECK(ft_insert(ft, &n, DIR_IN, 0) != NULL);
    }
    flow_key_t extra = K(IP(10,0,0,2), 7000, IP(1,2,3,4), 53);
    CHECK(ft_insert(ft, &extra, DIR_IN, 0) == NULL);
    ft_destroy(ft);
}

static void test_both_directions_can_be_stored_as_separate_flows(void)
{
    flowtable_t *ft = ft_create(64, 10);
    flow_key_t ab = K(IP(10,0,0,2), 5000, IP(1,2,3,4), 80);
    flow_key_t ba = ft_reverse(&ab);
    flow_t *f1 = ft_insert(ft, &ab, DIR_IN, 0), *f2 = ft_insert(ft, &ba, DIR_OUT, 0);
    f1->expires_ns = f2->expires_ns = 10 * SEC;
    bool r = true;
    CHECK(ft_lookup(ft, &ab, SEC, &r) == f1 && !r);     /* an exact match wins ... */
    CHECK(ft_lookup(ft, &ba, SEC, &r) == f2 && !r);     /* ... in both directions */
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

/* ---- limits: no single party may starve the rest ------------------------ */

static flow_key_t from_src(uint32_t src, uint16_t sport)
{
    return K(src, sport, IP(10,0,2,2), 80);
}

static void test_outside_started_flows_have_a_quota(void)
{
    flowtable_t *ft = ft_create(64, 100);
    CHECK(ft_set_limits(ft, 0, 3));
    ft_status_t st;
    flow_t *out[3];
    for (int i = 0; i < 3; i++) {
        flow_key_t k = from_src(IP(198,51,100,i + 1), 1000);
        out[i] = ft_insert_ex(ft, &k, DIR_OUT, 0, &st);
        CHECK(out[i] != NULL && st == FT_OK);
    }
    flow_key_t k4 = from_src(IP(198,51,100,9), 1000);
    CHECK(ft_insert_ex(ft, &k4, DIR_OUT, 0, &st) == NULL && st == FT_OUTSIDE_QUOTA);
    CHECK(ft_insert(ft, &k4, DIR_OUT, 0) == NULL);             /* plain form: just NULL */
    /* flows started from the inside are not affected by the outside quota */
    for (int i = 0; i < 10; i++) {
        flow_key_t k = from_src(IP(10,0,1,i + 1), 2000);
        CHECK(ft_insert_ex(ft, &k, DIR_IN, 0, &st) != NULL && st == FT_OK);
    }
    /* a freed outside slot can be used again */
    ft_remove(ft, out[1]);
    CHECK(ft_insert_ex(ft, &k4, DIR_OUT, 0, &st) != NULL && st == FT_OK);
    CHECK(ft_insert_ex(ft, &k4, DIR_OUT, 0, &st) == NULL && st == FT_OUTSIDE_QUOTA);
    /* expiry frees quota too */
    CHECK(ft_expire(ft, 1, NULL, NULL) == 13);
    for (int i = 0; i < 3; i++) {
        flow_key_t k = from_src(IP(198,51,100,i + 20), 1000);
        CHECK(ft_insert_ex(ft, &k, DIR_OUT, 5, &st) != NULL);
    }
    ft_destroy(ft);
}

static void test_one_source_cannot_hold_more_than_its_share(void)
{
    flowtable_t *ft = ft_create(64, 100);
    CHECK(ft_set_limits(ft, 2, 0));
    ft_status_t st;
    const uint32_t a = IP(203,0,113,5), b = IP(203,0,113,6);
    flow_key_t a1 = from_src(a, 1), a2 = from_src(a, 2), a3 = from_src(a, 3);
    flow_t *f1 = ft_insert_ex(ft, &a1, DIR_OUT, 0, &st);
    CHECK(f1 && st == FT_OK);
    CHECK(ft_insert_ex(ft, &a2, DIR_OUT, 0, &st) && st == FT_OK);
    CHECK(ft_insert_ex(ft, &a3, DIR_OUT, 0, &st) == NULL && st == FT_SRC_LIMIT);
    flow_key_t b1 = from_src(b, 1);                              /* others unaffected */
    CHECK(ft_insert_ex(ft, &b1, DIR_OUT, 0, &st) && st == FT_OK);
    ft_remove(ft, f1);                                           /* a slot frees up */
    CHECK(ft_insert_ex(ft, &a3, DIR_OUT, 0, &st) && st == FT_OK);
    CHECK(ft_insert_ex(ft, &a1, DIR_OUT, 0, &st) == NULL && st == FT_SRC_LIMIT);
    /* the source is whoever STARTED the flow, not the replying side */
    flow_key_t reply_view = K(IP(10,0,2,2), 80, a, 1);
    CHECK(ft_insert_ex(ft, &reply_view, DIR_IN, 0, &st) && st == FT_OK);
    /* a full table reports FT_FULL, not a limit */
    ft_set_limits(ft, 0, 0);
    flowtable_t *tiny = ft_create(16, 1);
    flow_key_t t1 = from_src(a, 7), t2 = from_src(b, 7);
    CHECK(ft_insert(tiny, &t1, DIR_IN, 0));
    CHECK(ft_insert_ex(tiny, &t2, DIR_IN, 0, &st) == NULL && st == FT_FULL);
    ft_destroy(tiny);
    /* limits can be turned off again */
    CHECK(ft_set_limits(ft, 0, 0));
    for (int i = 10; i < 20; i++) {
        flow_key_t k = from_src(a, (uint16_t)i);
        CHECK(ft_insert(ft, &k, DIR_OUT, 0) != NULL);
    }
    ft_destroy(ft);
}

static void test_per_source_counters_stay_exact_under_churn(void)
{
    /* Randomly add and remove one flow per source against a model. A wrong
     * count (a lost entry after a backward shift, a leaked slot) shows up as
     * a source that is wrongly refused or wrongly admitted. */
    enum { SOURCES = 60, OPS = 30000 };
    uint8_t key[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
    flowtable_t *ft = ft_create_keyed(16, 64, key);              /* tiny: long probe runs */
    CHECK(ft_set_limits(ft, 1, 0));
    flow_t *live[SOURCES] = {0};
    unsigned seed = 12345;
    for (int i = 0; i < OPS; i++) {
        seed = seed * 1103515245u + 12345u;
        const int s = (int)((seed >> 8) % SOURCES);
        flow_key_t k = from_src(IP(100,64,s / 250, s % 250 + 1), 4000);
        ft_status_t st;
        if (live[s]) {
            CHECK(ft_insert_ex(ft, &k, DIR_OUT, 0, &st) == NULL && st == FT_SRC_LIMIT);
            if ((seed >> 20) & 1) { ft_remove(ft, live[s]); live[s] = NULL; }
        } else {
            live[s] = ft_insert_ex(ft, &k, DIR_OUT, 0, &st);
            CHECK(live[s] != NULL && st == FT_OK);
        }
    }
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
    RUN(test_every_field_is_part_of_the_key);
    RUN(test_removing_a_flow_twice_does_nothing_the_second_time);
    RUN(test_both_directions_can_be_stored_as_separate_flows);
    RUN(test_siphash_matches_the_published_vectors);
    RUN(test_precomputed_collisions_do_not_survive_a_different_key);
    RUN(test_each_table_gets_its_own_random_key);
    RUN(test_absurd_sizes_are_refused_not_looped_on);
    RUN(test_outside_started_flows_have_a_quota);
    RUN(test_one_source_cannot_hold_more_than_its_share);
    RUN(test_per_source_counters_stay_exact_under_churn);
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

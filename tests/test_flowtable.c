#include "flowtable.h"
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

int main(void)
{
    RUN(test_insert_and_lookup_both_directions);
    RUN(test_protocol_is_part_of_key);
    RUN(test_lazy_expiry);
    RUN(test_sweep_removes_only_expired);
    RUN(test_capacity_limit);
    RUN(test_remove);
    TEST_DONE();
}

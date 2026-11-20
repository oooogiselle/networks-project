/*=============================================================================
 * File Name:   test_ratelimit.c
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Unit tests for per-rule connection rate limits (ratelimit.c):
 *              the burst, the refill, independence of sources and rules,
 *              refunds, once-per-episode refusal reports, and the fixed table.
 =============================================================================*/

#include "ratelimit.h"
#include "testutil.h"

#define ATTACKER IP(198,51,100,66)
#define OTHER    IP(203,0,113,9)
#define MIN      (60 * SEC)

/* How many of `tries` connections at time t are admitted (5/min, rule 0). */
static int admitted(rl_t *rl, uint32_t ip, int tries, uint64_t t)
{
    int ok = 0;
    for (int i = 0; i < tries; i++)
        ok += rl_admit(rl, 0, ip, 5, MIN, t, NULL);
    return ok;
}

static void test_burst_of_n_then_refused(void)
{
    rl_t *rl = rl_create();
    CHECK(admitted(rl, ATTACKER, 5, SEC) == 5);
    CHECK(!rl_admit(rl, 0, ATTACKER, 5, MIN, SEC, NULL));
    CHECK(admitted(rl, ATTACKER, 100, SEC) == 0);     /* refusals cost nothing, */
    CHECK(admitted(rl, ATTACKER, 1, SEC + 12 * SEC) == 1);   /* so 12 s later: one */
    rl_destroy(rl);
}

static void test_one_more_every_period_over_n(void)
{
    rl_t *rl = rl_create();
    const uint64_t t0 = 100 * SEC, step = MIN / 5;    /* 12 s */
    CHECK(admitted(rl, ATTACKER, 5, t0) == 5);
    CHECK(admitted(rl, ATTACKER, 1, t0 + step - 1) == 0);     /* not a ns early */
    CHECK(admitted(rl, ATTACKER, 2, t0 + step) == 1);         /* exactly one */
    CHECK(admitted(rl, ATTACKER, 1, t0 + 2 * step - 1) == 0);
    CHECK(admitted(rl, ATTACKER, 1, t0 + 2 * step) == 1);
    /* Idle for a long time: the bucket is full again, but never more than N. */
    CHECK(admitted(rl, ATTACKER, 10, t0 + 10 * MIN) == 5);
    rl_destroy(rl);
}

static void test_steady_rate_is_never_refused(void)
{
    /* A client at exactly the limit (one per 12 s) always gets in. */
    rl_t *rl = rl_create();
    for (int i = 0; i < 50; i++)
        CHECK(rl_admit(rl, 0, ATTACKER, 5, MIN, SEC + (uint64_t)i * 12 * SEC, NULL));
    rl_destroy(rl);
}

static void test_sources_and_rules_are_independent(void)
{
    rl_t *rl = rl_create();
    CHECK(admitted(rl, ATTACKER, 6, SEC) == 5);
    CHECK(admitted(rl, OTHER, 6, SEC) == 5);           /* another source */
    CHECK(rl_admit(rl, 1, ATTACKER, 5, MIN, SEC, NULL));     /* another rule */
    CHECK(rl_admit(rl, 7, ATTACKER, 1, 3600 * SEC, SEC, NULL));
    CHECK(!rl_admit(rl, 7, ATTACKER, 1, 3600 * SEC, 1800 * SEC, NULL));
    CHECK(rl_admit(rl, 7, ATTACKER, 1, 3600 * SEC, 3601 * SEC, NULL));
    rl_destroy(rl);
}

static void test_refund_gives_back_exactly_one(void)
{
    rl_t *rl = rl_create();
    CHECK(admitted(rl, ATTACKER, 5, SEC) == 5);
    rl_refund(rl, 0, ATTACKER, 5, MIN);
    CHECK(admitted(rl, ATTACKER, 3, SEC) == 1);
    /* A refund for a pair that isn't tracked does nothing. */
    rl_refund(rl, 0, OTHER, 5, MIN);
    rl_refund(rl, 3, ATTACKER, 5, MIN);
    CHECK(admitted(rl, OTHER, 6, SEC) == 5);
    /* Refunding a fresh admission at time 0 does not wrap around. */
    rl_t *z = rl_create();
    CHECK(rl_admit(z, 0, ATTACKER, 1, MIN, 0, NULL));
    rl_refund(z, 0, ATTACKER, 1, MIN);
    rl_refund(z, 0, ATTACKER, 1, MIN);
    CHECK(rl_admit(z, 0, ATTACKER, 1, MIN, 0, NULL));
    CHECK(!rl_admit(z, 0, ATTACKER, 1, MIN, 0, NULL));
    rl_destroy(z);
    rl_destroy(rl);
}

static void test_first_refusal_is_reported_once_per_episode(void)
{
    rl_t *rl = rl_create();
    bool first = true;
    CHECK(rl_admit(rl, 0, ATTACKER, 1, MIN, SEC, &first) && !first);
    CHECK(!rl_admit(rl, 0, ATTACKER, 1, MIN, 2 * SEC, &first) && first);
    CHECK(!rl_admit(rl, 0, ATTACKER, 1, MIN, 3 * SEC, &first) && !first);
    CHECK(!rl_admit(rl, 0, ATTACKER, 1, MIN, 4 * SEC, &first) && !first);
    /* Admitted again: the next refusal starts a new episode. */
    CHECK(rl_admit(rl, 0, ATTACKER, 1, MIN, 61 * SEC, &first) && !first);
    CHECK(!rl_admit(rl, 0, ATTACKER, 1, MIN, 62 * SEC, &first) && first);
    rl_destroy(rl);
}

static void test_full_set_evicts_the_fullest_bucket(void)
{
    rl_t *rl = rl_create_n(1);           /* one set of RL_WAYS entries */
    const uint32_t a = IP(198,51,100,1);
    for (uint32_t i = 0; i < RL_WAYS; i++)      /* 1/min each, all used up */
        CHECK(rl_admit(rl, 0, a + i, 1, MIN, (1 + i) * SEC, NULL));
    for (uint32_t i = 0; i < RL_WAYS; i++)
        CHECK(!rl_admit(rl, 0, a + i, 1, MIN, 5 * SEC, NULL));
    /* A new source takes the entry of a, the oldest (smallest tat)... */
    CHECK(rl_admit(rl, 0, OTHER, 1, MIN, 6 * SEC, NULL));
    CHECK(!rl_admit(rl, 0, a + 1, 1, MIN, 7 * SEC, NULL));   /* still tracked */
    /* ...so a is forgotten: a fresh bucket (evicting a + 1 this time). */
    CHECK(rl_admit(rl, 0, a, 1, MIN, 8 * SEC, NULL));
    CHECK(rl_admit(rl, 0, a + 1, 1, MIN, 9 * SEC, NULL));
    rl_destroy(rl);

    rl_t *r3 = rl_create_n(3);           /* rounded up to 4 sets */
    CHECK(r3 != NULL);
    rl_destroy(r3);
    rl_destroy(NULL);
}

static void test_clear_forgets_everything(void)
{
    rl_t *rl = rl_create();
    CHECK(admitted(rl, ATTACKER, 6, SEC) == 5);
    rl_clear(rl);
    CHECK(admitted(rl, ATTACKER, 6, SEC) == 5);
    rl_destroy(rl);
}

int main(void)
{
    RUN(test_burst_of_n_then_refused);
    RUN(test_one_more_every_period_over_n);
    RUN(test_steady_rate_is_never_refused);
    RUN(test_sources_and_rules_are_independent);
    RUN(test_refund_gives_back_exactly_one);
    RUN(test_first_refusal_is_reported_once_per_episode);
    RUN(test_full_set_evicts_the_fullest_bucket);
    RUN(test_clear_forgets_everything);
    TEST_DONE();
}

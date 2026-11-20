/*=============================================================================
 * File Name:   ratelimit.c
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Per-rule connection rate limits: a GCRA (token bucket) per
 *              (rule, source address) in a fixed table. See ratelimit.h.
 =============================================================================*/

#include "ratelimit.h"

#include <stdlib.h>
#include <string.h>

#include "fwalloc.h"
#include "siphash.h"

typedef struct {
    uint64_t tat;              /* theoretical arrival time; <= now = full bucket */
    uint32_t ip;
    uint32_t rule;
    bool     used;
    bool     refused_logged;   /* a refusal was reported since the last admission */
} rl_entry_t;

struct ratelimit {
    size_t      set_mask;      /* nsets - 1 */
    uint8_t     hash_key[16];  /* secret: attackers cannot aim at one set */
    rl_entry_t *slots;         /* nsets * RL_WAYS */
};

rl_t *rl_create_n(size_t nsets)
{
    size_t n = 1;
    while (n < nsets) n <<= 1;

    rl_t *rl = fw_calloc(1, sizeof *rl);
    if (!rl) return NULL;
    rl->slots = fw_calloc(n * RL_WAYS, sizeof *rl->slots);
    if (!rl->slots || !fw_random(rl->hash_key, sizeof rl->hash_key)) {
        rl_destroy(rl);
        return NULL;
    }
    rl->set_mask = n - 1;
    return rl;
}

rl_t *rl_create(void)
{
    return rl_create_n(RL_DEFAULT_SETS);
}

void rl_destroy(rl_t *rl)
{
    if (!rl) return;
    free(rl->slots);
    free(rl);
}

void rl_clear(rl_t *rl)
{
    memset(rl->slots, 0, (rl->set_mask + 1) * RL_WAYS * sizeof *rl->slots);
}

static rl_entry_t *set_of(const rl_t *rl, uint32_t rule, uint32_t ip)
{
    const uint8_t b[8] = { rule >> 24, rule >> 16, rule >> 8, rule,
                           ip >> 24, ip >> 16, ip >> 8, ip };
    const size_t h = (size_t)fw_siphash24(rl->hash_key, b, sizeof b);
    return rl->slots + (h & rl->set_mask) * RL_WAYS;
}

static rl_entry_t *find(const rl_t *rl, uint32_t rule, uint32_t ip)
{
    rl_entry_t *set = set_of(rl, rule, ip);
    for (int w = 0; w < RL_WAYS; w++)
        if (set[w].used && set[w].ip == ip && set[w].rule == rule)
            return &set[w];
    return NULL;
}

/* An entry for a new (rule, source): a free one, else the one with the
 * smallest tat (the fullest bucket). Never fails. */
static rl_entry_t *claim(rl_t *rl, uint32_t rule, uint32_t ip)
{
    rl_entry_t *set = set_of(rl, rule, ip), *victim = &set[0];
    for (int w = 0; w < RL_WAYS; w++) {
        if (!set[w].used) { victim = &set[w]; break; }
        if (set[w].tat < victim->tat) victim = &set[w];
    }
    *victim = (rl_entry_t){ .tat = 0, .ip = ip, .rule = rule, .used = true };
    return victim;
}

bool rl_admit(rl_t *rl, uint32_t rule_idx, uint32_t ip, uint32_t n,
              uint64_t period_ns, uint64_t now_ns, bool *first_refusal)
{
    const uint64_t t = period_ns / n;          /* one connection's worth */
    const uint64_t tau = period_ns - t;        /* burst tolerance: n - 1 more */
    rl_entry_t *e = find(rl, rule_idx, ip);
    if (!e) e = claim(rl, rule_idx, ip);

    if (first_refusal) *first_refusal = false;
    if (now_ns + tau < e->tat) {               /* bucket empty */
        if (first_refusal) *first_refusal = !e->refused_logged;
        e->refused_logged = true;
        return false;
    }
    e->tat = (e->tat > now_ns ? e->tat : now_ns) + t;
    e->refused_logged = false;
    return true;
}

void rl_refund(rl_t *rl, uint32_t rule_idx, uint32_t ip, uint32_t n,
               uint64_t period_ns)
{
    const uint64_t t = period_ns / n;
    rl_entry_t *e = find(rl, rule_idx, ip);
    if (e) e->tat = e->tat > t ? e->tat - t : 0;
}

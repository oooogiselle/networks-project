/*=============================================================================
 * File Name:   ratelimit.h
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Per-rule connection rate limits (`limit N/min` on an allow
 *              rule): how many new connections each source address may open
 *              through that rule.
 =============================================================================*/

/*
 * ratelimit.h - per-(rule, source) connection rate limiting.
 *
 * A rule with `limit N/PERIOD` admits, for each source address, a burst of N
 * new connections and then one more every PERIOD/N: a token bucket of size N
 * that refills N tokens per PERIOD (as iptables' hashlimit does). It is
 * implemented as GCRA (the generic cell rate algorithm), which needs just one
 * number per (rule, source): the "theoretical arrival time" tat. With
 * T = PERIOD/N and tau = PERIOD - T, a connection at time now is admitted if
 * now + tau >= tat, and then tat = max(tat, now) + T. All integer
 * nanoseconds, no floating point.
 *
 * Only admitted connections use up the limit: a refused one costs nothing,
 * and rl_refund() gives an admission back if the connection could not be
 * set up after all.
 *
 * Memory is fixed at creation: a set-associative table (nsets x RL_WAYS
 * entries). No allocation per packet, so spoofed source addresses cannot grow
 * it. Sets are chosen with a keyed hash (SipHash, random key, as in the flow
 * table and scandetect), so forged addresses cannot be aimed at one set. When
 * a set is full, the entry with the smallest tat gives way: it is the one
 * closest to (or already back at) a full bucket, so evicting it forgives the
 * least.
 *
 * Pure logic, no I/O. Not thread safe (single I/O thread, like engine_t).
 */
#ifndef FW_RATELIMIT_H
#define FW_RATELIMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RL_WAYS          4
#define RL_DEFAULT_SETS  1024     /* x 4 ways = 4096 (rule, source) pairs */

typedef struct ratelimit rl_t;

/* NULL if out of memory (three allocations: fw_calloc x2, fw_random). */
rl_t *rl_create(void);
/* Same, with nsets sets (rounded up to a power of two). For tests. */
rl_t *rl_create_n(size_t nsets);
void  rl_destroy(rl_t *rl);

/* Forget every source (the rules were replaced, so rule indices changed). */
void  rl_clear(rl_t *rl);

/*
 * May ip open one more connection through rule number rule_idx, whose limit
 * is n per period_ns (n >= 1, period_ns >= n)? If so, it is counted and true
 * is returned. If not, false, and *first_refusal (if non-NULL) is true when
 * this is the first refusal since ip's last admission on that rule, so the
 * caller can log one line per episode instead of one per packet.
 */
bool  rl_admit(rl_t *rl, uint32_t rule_idx, uint32_t ip, uint32_t n,
               uint64_t period_ns, uint64_t now_ns, bool *first_refusal);

/* Give back one admission rl_admit() just counted (same arguments). */
void  rl_refund(rl_t *rl, uint32_t rule_idx, uint32_t ip, uint32_t n,
                uint64_t period_ns);

#endif

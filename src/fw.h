/*
 * fw.h - the decision engine.
 *
 * fw_decide() is pure: it never performs I/O or reads the clock. The caller
 * passes the current monotonic time in milliseconds. That makes every
 * behaviour unit-testable with a fake clock and fuzzable end to end.
 */
#ifndef TUNWALL_FW_H
#define TUNWALL_FW_H

#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "packet.h"

struct fw;      /* opaque: rules, flow table, stats */
struct ruleset; /* opaque: see rules.h */

struct fw_config {
    uint32_t inside_net;   /* host order, e.g. 10.0.1.0 */
    uint32_t inside_mask;  /* host order, e.g. 0xffffff00 */
    uint32_t max_flows;    /* default 65536 */
    uint32_t timeout_scale_pct; /* 100 = spec timeouts; tests shrink it */
};

/* Per-reason drop counters plus flow totals, printed on SIGUSR1 / exit. */
struct fw_stats {
    uint64_t allowed_pkts, allowed_bytes;
    uint64_t dropped[R__COUNT];
    uint64_t flows_opened, flows_closed, flows_active;
};

/* Allocates everything up front; returns NULL on allocation failure.
 * Takes ownership of `rules`. */
struct fw *fw_create(const struct fw_config *cfg, struct ruleset *rules);
void fw_destroy(struct fw *fw);

/* Decide one already-parsed packet. On V_DROP, *why is set. */
enum verdict fw_decide(struct fw *fw, const struct pkt *p, enum dir d,
                       uint64_t now_ms, enum reason *why);

/* Expire idle flows (cost proportional to the number expired). */
void fw_sweep(struct fw *fw, uint64_t now_ms);

const struct fw_stats *fw_get_stats(const struct fw *fw);

#endif /* TUNWALL_FW_H */

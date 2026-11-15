/*=============================================================================
 * File Name:   forwarder.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: The packet loop. Reads raw IPv4 packets from the "inside" and
 *              "outside" file descriptors (tun devices in production, socket
 *              pairs in the unit tests), runs each through the parser and the
 *              decision engine, and writes the allowed ones to the opposite
 *              descriptor. Also runs the once-a-second flow expiry sweep.
 *              Single-threaded; nothing is allocated per packet.
 =============================================================================*/

#ifndef FW_FORWARDER_H
#define FW_FORWARDER_H

#include <stdint.h>
#include <stdio.h>

#include "engine.h"

#define FWD_MAX_PACKET        65535                 /* largest IPv4 packet */
#define FWD_BURST             64                    /* packets per fd per wakeup */
#define FWD_EXPIRE_INTERVAL_NS 1000000000ull        /* sweep expired flows ~1 s */

typedef struct forwarder forwarder_t;

/* Monotonic nanosecond clock; replaceable so tests can control time. */
typedef uint64_t (*fwd_clock_fn)(void);

typedef struct fwd_counters {
    uint64_t rx[2];            /* packets read, indexed by the dir_t they arrived on */
    uint64_t forwarded[2];     /* of those, written to the other side              */
    uint64_t write_errors;     /* allowed packets the other side refused           */
    int      last_write_errno; /* errno of the most recent refusal                 */
} fwd_counters_t;

/*
 * fd_in carries packets that arrive from the trusted side (DIR_IN), fd_out
 * those from the untrusted side (DIR_OUT). Both are switched to non-blocking.
 * The forwarder does not own e or the descriptors. NULL on bad arguments or
 * allocation failure.
 */
forwarder_t *fwd_create(engine_t *e, int fd_in, int fd_out);
void         fwd_destroy(forwarder_t *f);

void fwd_set_clock(forwarder_t *f, fwd_clock_fn clock);

/*
 * One loop iteration: wait up to timeout_ms for packets, forward up to
 * FWD_BURST from each side, then sweep expired flows if a second has passed.
 * Returns 0 normally (including timeouts and signals), -1 if a descriptor has
 * failed (closed, or a read error), in which case the caller should stop.
 */
int fwd_step(forwarder_t *f, int timeout_ms);

void fwd_get_counters(const forwarder_t *f, fwd_counters_t *out);

/* Engine counters and drop reasons, then one "io:" line with the I/O counters. */
void fwd_print_stats(const forwarder_t *f, FILE *out);

#endif

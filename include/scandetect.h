/*=============================================================================
 * File Name:   scandetect.h
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Port-scan detection: count the distinct ports each outside
 *              host is dropped on, and block a host that crosses the
 *              threshold for a while.
 =============================================================================*/

/*
 * scandetect.h - port-scan detection and temporary blocking of the scanner.
 *
 * The engine reports every policy drop of an outside TCP/UDP packet here
 * (scan_hit). For each source address we remember the distinct (proto, port)
 * pairs it was dropped on, each with the time of its last hit. Entries older
 * than the window are forgotten (a sliding window), so "N distinct ports in
 * W seconds" means exactly that. When a source reaches N, it is blocked for
 * B seconds: the engine drops everything it sends.
 *
 * Memory is fixed at creation: a set-associative table (nsets x SCAN_WAYS
 * slots, each with room for N ports). No allocation per packet, so spoofed
 * source addresses cannot grow it. Sets are chosen with a keyed hash
 * (SipHash, random key, as in the flow table), so an attacker cannot pick
 * forged addresses that all land in one set. When a set is full, the least recently
 * seen source that isn't blocked is evicted; if every slot in the set is
 * blocked, the new source is simply not tracked (default deny still drops
 * its packets).
 *
 * Pure logic, no I/O. Not thread safe (single I/O thread, like engine_t).
 */
#ifndef FW_SCANDETECT_H
#define FW_SCANDETECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "engine.h"

#define SCAN_WAYS         4
#define SCAN_DEFAULT_SETS 1024   /* x 4 ways = 4096 tracked sources */

typedef struct scan scan_t;

/*
 * Returns NULL if cfg is invalid (ports outside 1..SCAN_MAX_PORTS, window_s
 * or block_s 0) or out of memory (four allocations: fw_calloc x3, fw_random). ports == 0 also returns NULL: the caller
 * treats a NULL scan_t as "detection off".
 */
scan_t *scan_create(const scan_cfg_t *cfg);
/* Same, with nsets sets (rounded up to a power of two). For tests. */
scan_t *scan_create_n(const scan_cfg_t *cfg, size_t nsets);
void    scan_destroy(scan_t *s);

/*
 * Record that ip was dropped on (proto, port) at now_ns. Returns true if
 * this hit pushed ip over the threshold and started a block; then *span_ns
 * (if non-NULL) is the time between the oldest remembered hit and this one.
 */
bool scan_hit(scan_t *s, uint32_t ip, uint8_t proto, uint16_t port,
              uint64_t now_ns, uint64_t *span_ns);

/*
 * Is ip blocked at now_ns? If so, also counts one dropped packet for the
 * UNBLOCK log line.
 */
bool scan_blocked(scan_t *s, uint32_t ip, uint64_t now_ns);

/* Blocks started and not yet cleared by scan_expire() (0 = nobody blocked). */
size_t scan_nblocked(const scan_t *s);

/* Clear every block that has ended; cb (optional) sees each one first. */
typedef void (*scan_unblock_cb)(uint32_t ip, uint64_t dropped, void *ud);
size_t scan_expire(scan_t *s, uint64_t now_ns, scan_unblock_cb cb, void *ud);

#endif

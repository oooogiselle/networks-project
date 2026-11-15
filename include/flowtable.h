/*=============================================================================
 * File Name:   flowtable.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Flow table interface: connections keyed by 5-tuple, matched in
 *              both directions, with expiry.
 =============================================================================*/

/*
 * flowtable.h - hash table of tracked flows, keyed by 5-tuple.
 *
 * A flow is stored once, under the key as seen from its ORIGINATOR (the side
 * whose first packet created it). Lookup tries the packet's key and then its
 * reverse, so reply traffic finds the same entry.
 */
#ifndef FW_FLOWTABLE_H
#define FW_FLOWTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "engine.h"

typedef struct flow_key {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
} flow_key_t;

typedef enum {
    TCPS_NONE = 0,     /* non-TCP flow */
    TCPS_SYN_SENT,     /* originator SYN seen            */
    TCPS_SYN_RECV,     /* reply SYN-ACK seen             */
    TCPS_ESTABLISHED,
    TCPS_FIN_WAIT,     /* one FIN seen                   */
    TCPS_TIME_WAIT,    /* both FINs seen                 */
    TCPS_CLOSED        /* RST seen                       */
} tcp_state_t;

const char *tcp_state_str(tcp_state_t s);

typedef struct flow {
    flow_key_t  key;            /* originator -> responder */
    dir_t       orig_dir;       /* interface the originator's packets arrive on */
    tcp_state_t tcp_state;
    uint8_t     fin_seen;       /* bit0: originator sent FIN, bit1: responder */
    bool        seen_reply;
    bool        close_logged;   /* the CLOSE line was written; EXPIRE is then skipped */
    uint8_t     app;            /* app_t: what the payload turned out to be (appid.h) */
    uint8_t     app_tries;      /* data packets examined so far while still unknown */
    uint16_t    icmp_err_count;       /* related ICMP errors allowed in the current window */
    uint64_t    icmp_err_window_ns;   /* start of that one-second window */
    int         rule_line;      /* rules-file line that allowed it (0 = n/a) */
    uint64_t    created_ns, last_seen_ns, expires_ns;
    uint64_t    pkts[2], bytes[2];   /* [0] originator, [1] responder */
    struct flow *next;          /* hash chain */
} flow_t;

typedef struct flowtable flowtable_t;

/* Upper bounds, so a bad size is refused instead of overflowing. */
#define FT_MAX_BUCKETS ((size_t)1 << 26)
#define FT_MAX_FLOWS   ((size_t)1 << 26)

/*
 * nbuckets is rounded up to a power of two. max_flows bounds memory. The hash
 * is keyed with a random per-table secret, so an attacker cannot work out
 * offline which flows share a bucket. NULL if a size is above the limits
 * above, or on allocation / random-source failure.
 */
flowtable_t *ft_create(size_t nbuckets, size_t max_flows);
/* Same with a given 16-byte hash key (tests only; NULL key = random). */
flowtable_t *ft_create_keyed(size_t nbuckets, size_t max_flows, const uint8_t key[16]);
/* The bucket a key hashes to (tests only). */
size_t       ft_bucket_of(const flowtable_t *ft, const flow_key_t *k);
void         ft_destroy(flowtable_t *ft);

flow_key_t   ft_reverse(const flow_key_t *k);

/*
 * Find the flow for key k (either direction). *is_reply is true if k matched
 * the reverse of the stored key. A flow past its expiry is removed (the hook
 * set with ft_set_expire_hook() sees it first) and NULL returned.
 */
flow_t *ft_lookup(flowtable_t *ft, const flow_key_t *k, uint64_t now_ns,
                  bool *is_reply);

/* Why ft_insert_ex() refused a new flow. */
typedef enum {
    FT_OK = 0,
    FT_FULL,             /* no free slot                                      */
    FT_OUTSIDE_QUOTA,    /* flows started from the outside hold their share   */
    FT_SRC_LIMIT         /* this source address already has its share of flows */
} ft_status_t;

/*
 * Limits that stop one party starving the rest (0 = no limit). Call once,
 * right after ft_create(), before any flow exists.
 *   max_per_source:  most flows one originating source address may hold.
 *   max_outside:     most flows that were started from the outside, so that
 *                    inside users keep a reserve however hard the outside
 *                    pushes (spoofed sources defeat a per-source cap alone).
 * Returns false (limits unchanged) if the bookkeeping cannot be allocated.
 */
bool ft_set_limits(flowtable_t *ft, size_t max_per_source, size_t max_outside);

/* Create a flow (zeroed counters, expires_ns = now). NULL if table is full. */
flow_t *ft_insert(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                  uint64_t now_ns);
/* Same, and says why when it returns NULL (status may be NULL). */
flow_t *ft_insert_ex(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                     uint64_t now_ns, ft_status_t *status);
void    ft_remove(flowtable_t *ft, flow_t *f);

/* Remove every flow with expires_ns <= now. cb (optional) sees each first. */
typedef void (*ft_expire_cb)(const flow_t *f, void *ud);
size_t ft_expire(flowtable_t *ft, uint64_t now_ns, ft_expire_cb cb, void *ud);

/* Called for a flow that ft_lookup() finds already expired and removes, so a
 * flow that times out between sweeps is still reported. */
void   ft_set_expire_hook(flowtable_t *ft, ft_expire_cb hook, void *ud);

size_t ft_count(const flowtable_t *ft);
uint64_t ft_expired_total(const flowtable_t *ft);

#endif

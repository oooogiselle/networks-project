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
    int         rule_line;      /* rules-file line that allowed it (0 = n/a) */
    uint64_t    created_ns, last_seen_ns, expires_ns;
    uint64_t    pkts[2], bytes[2];   /* [0] originator, [1] responder */
    struct flow *next;          /* hash chain */
} flow_t;

typedef struct flowtable flowtable_t;

/* nbuckets is rounded up to a power of two. max_flows bounds memory. */
flowtable_t *ft_create(size_t nbuckets, size_t max_flows);
void         ft_destroy(flowtable_t *ft);

flow_key_t   ft_reverse(const flow_key_t *k);

/*
 * Find the flow for key k (either direction). *is_reply is true if k matched
 * the reverse of the stored key. A flow past its expiry is removed and NULL
 * returned.
 */
flow_t *ft_lookup(flowtable_t *ft, const flow_key_t *k, uint64_t now_ns,
                  bool *is_reply);

/* Create a flow (zeroed counters, expires_ns = now). NULL if table is full. */
flow_t *ft_insert(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                  uint64_t now_ns);
void    ft_remove(flowtable_t *ft, flow_t *f);

/* Remove every flow with expires_ns <= now. cb (optional) sees each first. */
typedef void (*ft_expire_cb)(const flow_t *f, void *ud);
size_t ft_expire(flowtable_t *ft, uint64_t now_ns, ft_expire_cb cb, void *ud);

size_t ft_count(const flowtable_t *ft);
uint64_t ft_expired_total(const flowtable_t *ft);

#endif

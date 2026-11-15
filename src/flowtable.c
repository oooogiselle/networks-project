/*=============================================================================
 * File Name:   flowtable.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Flow table implementation: a hash table over a preallocated pool
 *              of flow slots (no allocation per connection or per packet), lazy
 *              expiry on lookup, and a periodic sweep.
 =============================================================================*/

#include "flowtable.h"

#include "fwalloc.h"

#include <stdlib.h>
#include <string.h>

#include "siphash.h"

/*
 * All flow slots are allocated once, in ft_create(), as one array. Free slots
 * form a singly linked list (through flow_t.next), so inserting and removing
 * a flow never calls malloc/free: nothing is allocated per connection, let
 * alone per packet.
 */
/* One counter per source address that currently owns flows. Open addressing
 * with linear probing; a slot is empty when n == 0, and entries are removed
 * by backward shifting, so no tombstones pile up. Allocated once. */
typedef struct { uint32_t ip; uint32_t n; } src_slot_t;

struct flowtable {
    flow_t  **buckets;
    flow_t   *pool;          /* max slots, allocated once */
    flow_t   *free_list;     /* unused slots */
    size_t    mask;          /* nbuckets - 1 */
    size_t    count, max;
    size_t    count_out;        /* flows that were started from the outside */
    size_t    max_out, max_src; /* limits, 0 = none (see ft_set_limits)     */
    src_slot_t *src;            /* per-source counters, NULL if no per-source limit */
    size_t    src_mask;
    uint64_t  expired_total;
    uint8_t   hash_key[16];     /* secret: attackers cannot predict buckets */
    ft_expire_cb expire_hook;   /* sees flows removed lazily by ft_lookup */
    void     *expire_hook_ud;
};

const char *tcp_state_str(tcp_state_t s)
{
    switch (s) {
    case TCPS_NONE:        return "-";
    case TCPS_SYN_SENT:    return "SYN_SENT";
    case TCPS_SYN_RECV:    return "SYN_RECV";
    case TCPS_ESTABLISHED: return "ESTABLISHED";
    case TCPS_FIN_WAIT:    return "FIN_WAIT";
    case TCPS_TIME_WAIT:   return "TIME_WAIT";
    case TCPS_CLOSED:      return "CLOSED";
    }
    return "?";
}

static size_t src_home(const flowtable_t *ft, uint32_t ip)
{
    uint8_t b[4];
    for (int i = 0; i < 4; i++) b[i] = (uint8_t)(ip >> (8 * i));
    return (size_t)fw_siphash24(ft->hash_key, b, sizeof b) & ft->src_mask;
}

static size_t src_count(const flowtable_t *ft, uint32_t ip)
{
    for (size_t i = src_home(ft, ip); ft->src[i].n; i = (i + 1) & ft->src_mask)
        if (ft->src[i].ip == ip) return ft->src[i].n;
    return 0;
}

static void src_inc(flowtable_t *ft, uint32_t ip)
{
    size_t i = src_home(ft, ip);
    while (ft->src[i].n && ft->src[i].ip != ip) i = (i + 1) & ft->src_mask;
    ft->src[i].ip = ip;
    ft->src[i].n++;
}

static void src_dec(flowtable_t *ft, uint32_t ip)
{
    size_t i = src_home(ft, ip);
    while (ft->src[i].n && ft->src[i].ip != ip) i = (i + 1) & ft->src_mask;
    if (!ft->src[i].n || --ft->src[i].n) return;       /* unknown, or still in use */
    /* Count hit zero: remove the slot and shift the rest of the cluster back
     * over it so every remaining entry stays reachable from its home slot. */
    for (size_t j = i;;) {
        j = (j + 1) & ft->src_mask;
        if (!ft->src[j].n) break;
        const size_t home = src_home(ft, ft->src[j].ip);
        const bool stays = i <= j ? (i < home && home <= j) : (i < home || home <= j);
        if (stays) continue;
        ft->src[i] = ft->src[j];
        i = j;
    }
    ft->src[i].n = 0;
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* SipHash-2-4 of the 13-byte key tuple under the table's secret key. */
static uint64_t hash_key(const flowtable_t *ft, const flow_key_t *k)
{
    uint8_t buf[13];
    put32(buf, k->src_ip);
    put32(buf + 4, k->dst_ip);
    buf[8]  = (uint8_t)k->src_port;
    buf[9]  = (uint8_t)(k->src_port >> 8);
    buf[10] = (uint8_t)k->dst_port;
    buf[11] = (uint8_t)(k->dst_port >> 8);
    buf[12] = k->proto;
    return fw_siphash24(ft->hash_key, buf, sizeof buf);
}

static size_t bucket_of(const flowtable_t *ft, const flow_key_t *k)
{
    return (size_t)hash_key(ft, k) & ft->mask;
}

size_t ft_bucket_of(const flowtable_t *ft, const flow_key_t *k)
{
    return bucket_of(ft, k);
}

static bool key_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

flow_key_t ft_reverse(const flow_key_t *k)
{
    flow_key_t r = { k->dst_ip, k->src_ip, k->dst_port, k->src_port, k->proto };
    return r;
}

flowtable_t *ft_create(size_t nbuckets, size_t max_flows)
{
    return ft_create_keyed(nbuckets, max_flows, NULL);
}

flowtable_t *ft_create_keyed(size_t nbuckets, size_t max_flows, const uint8_t key[16])
{
    /* Refuse absurd sizes: rounding nbuckets up to a power of two would
     * overflow (and loop forever) above 2^63. */
    if (nbuckets > FT_MAX_BUCKETS || max_flows > FT_MAX_FLOWS) return NULL;
    size_t n = 16;
    while (n < nbuckets) n <<= 1;
    flowtable_t *ft = fw_calloc(1, sizeof *ft);
    if (!ft) return NULL;
    ft->buckets = fw_calloc(n, sizeof *ft->buckets);
    ft->pool = max_flows ? fw_calloc(max_flows, sizeof *ft->pool) : NULL;
    const bool keyed = key ? (memcpy(ft->hash_key, key, 16), true)
                           : fw_random(ft->hash_key, sizeof ft->hash_key);
    if (!ft->buckets || (max_flows && !ft->pool) || !keyed) {
        free(ft->buckets);
        free(ft->pool);
        free(ft);
        return NULL;
    }
    ft->mask = n - 1;
    ft->max = max_flows;     /* sizes the per-source counters */
    for (size_t i = max_flows; i-- > 0; ) {     /* slot 0 is handed out first */
        ft->pool[i].next = ft->free_list;
        ft->free_list = &ft->pool[i];
    }
    return ft;
}

void ft_destroy(flowtable_t *ft)
{
    if (!ft) return;
    free(ft->src);
    free(ft->pool);
    free(ft->buckets);
    free(ft);
}

/* Return an already-unlinked slot to the free list. */
static void release(flowtable_t *ft, flow_t *f)
{
    if (f->orig_dir == DIR_OUT && ft->count_out) ft->count_out--;
    if (ft->src) src_dec(ft, f->key.src_ip);
    f->next = ft->free_list;
    ft->free_list = f;
    ft->count--;
}

void ft_remove(flowtable_t *ft, flow_t *f)
{
    flow_t **pp = &ft->buckets[bucket_of(ft, &f->key)];
    while (*pp && *pp != f) pp = &(*pp)->next;
    if (!*pp) return;
    *pp = f->next;
    release(ft, f);
}

static flow_t *find_exact(flowtable_t *ft, const flow_key_t *k)
{
    for (flow_t *f = ft->buckets[bucket_of(ft, k)]; f; f = f->next)
        if (key_eq(&f->key, k)) return f;
    return NULL;
}

flow_t *ft_lookup(flowtable_t *ft, const flow_key_t *k, uint64_t now_ns,
                  bool *is_reply)
{
    flow_key_t rev = ft_reverse(k);
    flow_t *f = find_exact(ft, k);
    bool reply = false;
    if (!f) { f = find_exact(ft, &rev); reply = (f != NULL); }
    if (!f) return NULL;
    if (now_ns >= f->expires_ns) {          /* lazily expire */
        if (ft->expire_hook) ft->expire_hook(f, ft->expire_hook_ud);
        ft->expired_total++;
        ft_remove(ft, f);
        return NULL;
    }
    if (is_reply) *is_reply = reply;
    return f;
}

bool ft_set_limits(flowtable_t *ft, size_t max_per_source, size_t max_outside)
{
    if (max_per_source && !ft->src) {
        size_t n = 16;
        while (n < 2 * ft->max) n <<= 1;       /* load factor <= 1/2: never full */
        ft->src = fw_calloc(n, sizeof *ft->src);
        if (!ft->src) return false;
        ft->src_mask = n - 1;
    }
    ft->max_src = max_per_source;
    ft->max_out = max_outside;
    return true;
}

flow_t *ft_insert(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                  uint64_t now_ns)
{
    return ft_insert_ex(ft, k, orig_dir, now_ns, NULL);
}

flow_t *ft_insert_ex(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                     uint64_t now_ns, ft_status_t *status)
{
    ft_status_t why = FT_OK;
    if (!ft->free_list)
        why = FT_FULL;
    else if (ft->max_out && orig_dir == DIR_OUT && ft->count_out >= ft->max_out)
        why = FT_OUTSIDE_QUOTA;
    else if (ft->max_src && src_count(ft, k->src_ip) >= ft->max_src)
        why = FT_SRC_LIMIT;
    if (status) *status = why;
    if (why != FT_OK) return NULL;

    flow_t *f = ft->free_list;
    ft->free_list = f->next;
    memset(f, 0, sizeof *f);              /* slots are reused: start clean */
    f->key = *k;
    f->orig_dir = orig_dir;
    f->created_ns = f->last_seen_ns = f->expires_ns = now_ns;
    flow_t **head = &ft->buckets[bucket_of(ft, k)];
    f->next = *head;
    *head = f;
    ft->count++;
    if (orig_dir == DIR_OUT) ft->count_out++;
    if (ft->src) src_inc(ft, k->src_ip);
    return f;
}

size_t ft_expire(flowtable_t *ft, uint64_t now_ns, ft_expire_cb cb, void *ud)
{
    size_t removed = 0;
    for (size_t i = 0; i <= ft->mask; i++) {
        flow_t **pp = &ft->buckets[i];
        while (*pp) {
            flow_t *f = *pp;
            if (f->expires_ns <= now_ns) {
                if (cb) cb(f, ud);
                *pp = f->next;
                release(ft, f);
                removed++;
            } else {
                pp = &f->next;
            }
        }
    }
    ft->expired_total += removed;
    return removed;
}

void ft_set_expire_hook(flowtable_t *ft, ft_expire_cb hook, void *ud)
{
    ft->expire_hook = hook;
    ft->expire_hook_ud = ud;
}

size_t ft_count(const flowtable_t *ft) { return ft->count; }
uint64_t ft_expired_total(const flowtable_t *ft) { return ft->expired_total; }

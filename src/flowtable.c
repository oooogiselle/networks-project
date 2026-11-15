#include "flowtable.h"

#include <stdlib.h>
#include <string.h>

struct flowtable {
    flow_t  **buckets;
    size_t    mask;          /* nbuckets - 1 */
    size_t    count, max;
    uint64_t  expired_total;
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

static uint32_t fnv_mix(uint32_t h, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        h ^= (v >> (8 * i)) & 0xff;
        h *= 16777619u;
    }
    return h;
}

static uint32_t hash_key(const flow_key_t *k)
{
    uint32_t h = 2166136261u;
    h = fnv_mix(h, k->src_ip);
    h = fnv_mix(h, k->dst_ip);
    h = fnv_mix(h, ((uint32_t)k->src_port << 16) | k->dst_port);
    h = fnv_mix(h, k->proto);
    return h;
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
    size_t n = 16;
    while (n < nbuckets) n <<= 1;
    flowtable_t *ft = calloc(1, sizeof *ft);
    if (!ft) return NULL;
    ft->buckets = calloc(n, sizeof *ft->buckets);
    if (!ft->buckets) { free(ft); return NULL; }
    ft->mask = n - 1;
    ft->max = max_flows;
    return ft;
}

void ft_destroy(flowtable_t *ft)
{
    if (!ft) return;
    for (size_t i = 0; i <= ft->mask; i++) {
        flow_t *f = ft->buckets[i];
        while (f) { flow_t *n = f->next; free(f); f = n; }
    }
    free(ft->buckets);
    free(ft);
}

void ft_remove(flowtable_t *ft, flow_t *f)
{
    flow_t **pp = &ft->buckets[hash_key(&f->key) & ft->mask];
    while (*pp && *pp != f) pp = &(*pp)->next;
    if (!*pp) return;
    *pp = f->next;
    free(f);
    ft->count--;
}

static flow_t *find_exact(flowtable_t *ft, const flow_key_t *k)
{
    for (flow_t *f = ft->buckets[hash_key(k) & ft->mask]; f; f = f->next)
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
        ft->expired_total++;
        ft_remove(ft, f);
        return NULL;
    }
    if (is_reply) *is_reply = reply;
    return f;
}

flow_t *ft_insert(flowtable_t *ft, const flow_key_t *k, dir_t orig_dir,
                  uint64_t now_ns)
{
    if (ft->count >= ft->max) return NULL;
    flow_t *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->key = *k;
    f->orig_dir = orig_dir;
    f->created_ns = f->last_seen_ns = f->expires_ns = now_ns;
    flow_t **head = &ft->buckets[hash_key(k) & ft->mask];
    f->next = *head;
    *head = f;
    ft->count++;
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
                free(f);
                ft->count--;
                removed++;
            } else {
                pp = &f->next;
            }
        }
    }
    ft->expired_total += removed;
    return removed;
}

size_t ft_count(const flowtable_t *ft) { return ft->count; }
uint64_t ft_expired_total(const flowtable_t *ft) { return ft->expired_total; }

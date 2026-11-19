/*=============================================================================
 * File Name:   scandetect.c
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Port-scan detection: per-source distinct-port counting in a
 *              sliding window, and temporary blocking. See scandetect.h.
 =============================================================================*/

#include "scandetect.h"

#include <stdlib.h>

#include "fwalloc.h"
#include "siphash.h"

#define NSEC_PER_SEC 1000000000ull

typedef struct {
    uint32_t key;              /* proto << 16 | port */
    uint64_t t;                /* last hit on this port */
} scan_port_t;

typedef struct {
    bool        used;
    uint32_t    ip;
    uint16_t    n;             /* ports[0..n) are remembered */
    uint64_t    last_seen_ns;
    uint64_t    blocked_until; /* 0 = not blocked */
    uint64_t    blocked_drops;
    scan_port_t *ports;        /* cfg.ports entries, inside scan_t.port_mem */
} scan_src_t;

struct scan {
    scan_cfg_t   cfg;
    uint64_t     window_ns, block_ns;
    size_t       set_mask;     /* nsets - 1 */
    uint8_t      hash_key[16]; /* secret: attackers cannot aim at one set */
    scan_src_t  *slots;        /* nsets * SCAN_WAYS */
    scan_port_t *port_mem;
    size_t       nblocked;
};

static size_t hash_ip(const scan_t *s, uint32_t ip)
{
    const uint8_t b[4] = { ip >> 24, ip >> 16, ip >> 8, ip };
    return (size_t)fw_siphash24(s->hash_key, b, sizeof b);
}

scan_t *scan_create_n(const scan_cfg_t *cfg, size_t nsets)
{
    if (!cfg || cfg->ports == 0 || cfg->ports > SCAN_MAX_PORTS ||
        cfg->window_s == 0 || cfg->block_s == 0)
        return NULL;
    size_t n = 1;
    while (n < nsets) n <<= 1;
    const size_t nslots = n * SCAN_WAYS;

    scan_t *s = fw_calloc(1, sizeof *s);
    if (!s) return NULL;
    s->slots = fw_calloc(nslots, sizeof *s->slots);
    s->port_mem = s->slots ? fw_calloc(nslots * cfg->ports, sizeof *s->port_mem) : NULL;
    if (!s->slots || !s->port_mem || !fw_random(s->hash_key, sizeof s->hash_key)) {
        scan_destroy(s);
        return NULL;
    }
    for (size_t i = 0; i < nslots; i++)
        s->slots[i].ports = s->port_mem + i * cfg->ports;
    s->cfg = *cfg;
    s->window_ns = (uint64_t)cfg->window_s * NSEC_PER_SEC;
    s->block_ns = (uint64_t)cfg->block_s * NSEC_PER_SEC;
    s->set_mask = n - 1;
    return s;
}

scan_t *scan_create(const scan_cfg_t *cfg)
{
    return scan_create_n(cfg, SCAN_DEFAULT_SETS);
}

void scan_destroy(scan_t *s)
{
    if (!s) return;
    free(s->port_mem);
    free(s->slots);
    free(s);
}

static scan_src_t *set_of(scan_t *s, uint32_t ip)
{
    return s->slots + (hash_ip(s, ip) & s->set_mask) * SCAN_WAYS;
}

static scan_src_t *find(scan_t *s, uint32_t ip)
{
    scan_src_t *set = set_of(s, ip);
    for (int w = 0; w < SCAN_WAYS; w++)
        if (set[w].used && set[w].ip == ip)
            return &set[w];
    return NULL;
}

/* Slot for a new source: a free one, else the least recently seen unblocked
 * one, else NULL (every slot in the set is blocked). */
static scan_src_t *claim(scan_t *s, uint32_t ip)
{
    scan_src_t *set = set_of(s, ip), *victim = NULL;
    for (int w = 0; w < SCAN_WAYS; w++) {
        if (!set[w].used) { victim = &set[w]; break; }
        if (set[w].blocked_until) continue;
        if (!victim || set[w].last_seen_ns < victim->last_seen_ns)
            victim = &set[w];
    }
    if (victim) {
        victim->used = true;
        victim->ip = ip;
        victim->n = 0;
        victim->blocked_until = 0;
        victim->blocked_drops = 0;
    }
    return victim;
}

bool scan_hit(scan_t *s, uint32_t ip, uint8_t proto, uint16_t port,
              uint64_t now_ns, uint64_t *span_ns)
{
    scan_src_t *src = find(s, ip);
    if (src && src->blocked_until > now_ns)
        return false;                       /* already blocked */
    if (!src && !(src = claim(s, ip)))
        return false;                       /* set full of blocked hosts */
    src->last_seen_ns = now_ns;

    /* Forget ports last hit a full window ago or more; find this one. */
    const uint32_t key = (uint32_t)proto << 16 | port;
    uint64_t oldest = now_ns;
    bool seen = false;
    uint16_t keep = 0;
    for (uint16_t i = 0; i < src->n; i++) {
        scan_port_t pe = src->ports[i];
        if (now_ns - pe.t >= s->window_ns) continue;
        if (pe.key == key) { pe.t = now_ns; seen = true; }
        if (pe.t < oldest) oldest = pe.t;
        src->ports[keep++] = pe;
    }
    src->n = keep;
    if (!seen)
        src->ports[src->n++] = (scan_port_t){ key, now_ns };

    if (src->n < s->cfg.ports)
        return false;

    /* Threshold reached: block. A block that ended but hasn't been swept by
     * scan_expire() yet is still counted in nblocked; just extend it. */
    if (!src->blocked_until) {
        s->nblocked++;
        src->blocked_drops = 0;
    }
    src->blocked_until = now_ns + s->block_ns;
    src->n = 0;
    if (span_ns) *span_ns = now_ns - oldest;
    return true;
}

bool scan_blocked(scan_t *s, uint32_t ip, uint64_t now_ns)
{
    scan_src_t *src = find(s, ip);
    if (!src || src->blocked_until <= now_ns)
        return false;
    src->blocked_drops++;
    return true;
}

size_t scan_nblocked(const scan_t *s)
{
    return s->nblocked;
}

size_t scan_expire(scan_t *s, uint64_t now_ns, scan_unblock_cb cb, void *ud)
{
    size_t cleared = 0;
    if (!s->nblocked) return 0;
    const size_t nslots = (s->set_mask + 1) * SCAN_WAYS;
    for (size_t i = 0; i < nslots; i++) {
        scan_src_t *src = &s->slots[i];
        if (!src->used || !src->blocked_until || src->blocked_until > now_ns)
            continue;
        if (cb) cb(src->ip, src->blocked_drops, ud);
        src->blocked_until = 0;
        src->blocked_drops = 0;
        src->n = 0;
        s->nblocked--;
        cleared++;
    }
    return cleared;
}

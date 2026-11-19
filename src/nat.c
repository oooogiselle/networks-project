/*=============================================================================
 * File Name:   nat.c
 * Author:      Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Source NAT with port translation (see nat.h). A preallocated
 *              pool of mappings, a keyed hash for the inside -> outside
 *              lookup, and one array per protocol indexed by NAT port for the
 *              outside -> inside lookup, so both directions are O(1) and no
 *              memory is allocated per packet.
 =============================================================================*/

#include "nat.h"

#include <stdlib.h>
#include <string.h>

#include "fwalloc.h"
#include "parser.h"
#include "siphash.h"

#define NAT_BUCKETS 65536u            /* power of two */
#define NO_ENTRY    (-1)

enum { PI_TCP = 0, PI_UDP, PI_ICMP, PI_COUNT };

typedef struct mapping {
    uint32_t in_ip, rem_ip;
    uint16_t in_port, rem_port;   /* ICMP echo: the inside host's identifier in both */
    uint16_t nat_port;
    uint8_t  proto;               /* 0 = free slot */
    int32_t  next;                /* hash chain, or the free list when free */
} mapping_t;

struct nat {
    uint32_t   addr;
    uint16_t   port_lo, port_hi;
    uint32_t   nports;
    mapping_t *pool;
    uint32_t   cap;
    int32_t    free_head;
    int32_t   *bucket;               /* NAT_BUCKETS chain heads */
    int32_t   *rev[PI_COUNT];        /* [proto][nat_port - port_lo] -> pool index */
    uint32_t   cursor[PI_COUNT];     /* next port to try, round robin */
    uint8_t    hash_key[16];
    nat_stats_t st;
};

/* ---- byte helpers and checksums ----------------------------------------- */

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

uint16_t nat_csum_adjust16(uint16_t csum, uint16_t old_word, uint16_t new_word)
{
    uint32_t sum = (uint32_t)(uint16_t)~csum + (uint16_t)~old_word + new_word;
    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t nat_csum_adjust32(uint16_t csum, uint32_t old_val, uint32_t new_val)
{
    csum = nat_csum_adjust16(csum, (uint16_t)(old_val >> 16), (uint16_t)(new_val >> 16));
    return nat_csum_adjust16(csum, (uint16_t)old_val, (uint16_t)new_val);
}

/*
 * Rewrite the source (dst == false) or destination address and port of the
 * IPv4 packet at ip, of which only avail bytes may be present (an ICMP error
 * embeds a truncated copy). The IP header checksum is always updated; the
 * port and the TCP/UDP/ICMP checksum only if they lie within avail. TCP and
 * UDP checksums cover the addresses through the pseudo-header, so they change
 * with the address too. For ICMP echo the "port" is the identifier, the same
 * field in both directions. Other ICMP types have no port: only the address
 * changes (the caller fixes an ICMP error's checksum itself).
 */
static void rewrite_endpoint(uint8_t *ip, size_t avail, bool dst,
                             uint32_t new_ip, uint16_t new_port)
{
    const size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    const uint8_t proto = ip[9];
    uint8_t *a = ip + (dst ? 16 : 12);
    const uint32_t old_ip = rd32(a);
    wr32(a, new_ip);
    wr16(ip + 10, nat_csum_adjust32(rd16(ip + 10), old_ip, new_ip));

    if (avail <= ihl) return;
    uint8_t *l4 = ip + ihl;
    const size_t l4avail = avail - ihl;

    if (proto == FW_PROTO_TCP || proto == FW_PROTO_UDP) {
        const size_t poff = dst ? 2 : 0;
        const size_t coff = proto == FW_PROTO_TCP ? 16 : 6;
        if (l4avail < poff + 2) return;
        const uint16_t old_port = rd16(l4 + poff);
        wr16(l4 + poff, new_port);
        if (l4avail < coff + 2) return;
        uint16_t c = rd16(l4 + coff);
        if (proto == FW_PROTO_UDP && c == 0) return;      /* sender used no checksum */
        c = nat_csum_adjust32(c, old_ip, new_ip);
        c = nat_csum_adjust16(c, old_port, new_port);
        if (proto == FW_PROTO_UDP && c == 0) c = 0xffff;  /* 0 would mean "none" */
        wr16(l4 + coff, c);
    } else if (proto == FW_PROTO_ICMP) {
        if (l4avail < 6) return;
        if (l4[0] != ICMP_ECHO_REQUEST && l4[0] != ICMP_ECHO_REPLY) return;
        const uint16_t old_id = rd16(l4 + 4);
        wr16(l4 + 4, new_port);
        wr16(l4 + 2, nat_csum_adjust16(rd16(l4 + 2), old_id, new_port));
    }
}

/* After changing an ICMP error's embedded packet, its checksum (which covers
 * the whole ICMP message) is recomputed; the message is at most a few hundred
 * bytes. */
static void icmp_recompute(uint8_t *buf)
{
    const size_t ihl = (size_t)(buf[0] & 0x0f) * 4;
    const size_t total = rd16(buf + 2);
    uint8_t *l4 = buf + ihl;
    wr16(l4 + 2, 0);
    wr16(l4 + 2, csum_fold(csum_partial(l4, total - ihl, 0)));
}

/* ---- the mapping table --------------------------------------------------- */

static int proto_index(uint8_t proto)
{
    switch (proto) {
    case FW_PROTO_TCP:  return PI_TCP;
    case FW_PROTO_UDP:  return PI_UDP;
    case FW_PROTO_ICMP: return PI_ICMP;
    default:            return -1;
    }
}

static uint32_t hash_tuple(const nat_t *n, uint8_t proto, uint32_t in_ip,
                           uint16_t in_port, uint32_t rem_ip, uint16_t rem_port)
{
    uint8_t b[13];
    wr32(b, in_ip); wr32(b + 4, rem_ip);
    wr16(b + 8, in_port); wr16(b + 10, rem_port);
    b[12] = proto;
    return (uint32_t)fw_siphash24(n->hash_key, b, sizeof b) & (NAT_BUCKETS - 1);
}

static int32_t find(const nat_t *n, uint8_t proto, uint32_t in_ip, uint16_t in_port,
                    uint32_t rem_ip, uint16_t rem_port)
{
    for (int32_t i = n->bucket[hash_tuple(n, proto, in_ip, in_port, rem_ip, rem_port)];
         i != NO_ENTRY; i = n->pool[i].next) {
        const mapping_t *m = &n->pool[i];
        if (m->proto == proto && m->in_ip == in_ip && m->in_port == in_port &&
            m->rem_ip == rem_ip && m->rem_port == rem_port)
            return i;
    }
    return NO_ENTRY;
}

/* The mapping that owns NAT port `port` for proto, or NO_ENTRY. */
static int32_t by_nat_port(const nat_t *n, uint8_t proto, uint16_t port)
{
    const int pi = proto_index(proto);
    if (pi < 0 || port < n->port_lo || port > n->port_hi) return NO_ENTRY;
    return n->rev[pi][port - n->port_lo];
}

/* A free NAT port for protocol pi, round robin so a port just released is
 * not handed out again right away. -1 if every port is taken. */
static int alloc_port(nat_t *n, int pi)
{
    for (uint32_t k = 0; k < n->nports; k++) {
        const uint32_t slot = (n->cursor[pi] + k) % n->nports;
        if (n->rev[pi][slot] == NO_ENTRY) {
            n->cursor[pi] = (slot + 1) % n->nports;
            return (int)slot;
        }
    }
    return -1;
}

static int32_t create(nat_t *n, uint8_t proto, uint32_t in_ip, uint16_t in_port,
                      uint32_t rem_ip, uint16_t rem_port)
{
    const int pi = proto_index(proto);
    if (pi < 0 || n->free_head == NO_ENTRY) return NO_ENTRY;
    const int slot = alloc_port(n, pi);
    if (slot < 0) return NO_ENTRY;

    const int32_t i = n->free_head;
    mapping_t *m = &n->pool[i];
    n->free_head = m->next;
    *m = (mapping_t){ in_ip, rem_ip, in_port, rem_port,
                      (uint16_t)(n->port_lo + slot), proto, NO_ENTRY };
    const uint32_t h = hash_tuple(n, proto, in_ip, in_port, rem_ip, rem_port);
    m->next = n->bucket[h];
    n->bucket[h] = i;
    n->rev[pi][slot] = i;
    n->st.mappings_created++;
    n->st.mappings_active++;
    return i;
}

static void release(nat_t *n, int32_t i)
{
    mapping_t *m = &n->pool[i];
    const uint32_t h = hash_tuple(n, m->proto, m->in_ip, m->in_port, m->rem_ip, m->rem_port);
    for (int32_t *link = &n->bucket[h]; *link != NO_ENTRY; link = &n->pool[*link].next) {
        if (*link == i) { *link = m->next; break; }
    }
    n->rev[proto_index(m->proto)][m->nat_port - n->port_lo] = NO_ENTRY;
    m->proto = 0;
    m->next = n->free_head;
    n->free_head = i;
    n->st.mappings_freed++;
    n->st.mappings_active--;
}

/* ---- public interface ---------------------------------------------------- */

nat_t *nat_create(uint32_t addr, uint16_t port_lo, uint16_t port_hi)
{
    if (addr == 0 || port_lo == 0 || port_lo > port_hi) return NULL;
    nat_t *n = fw_calloc(1, sizeof *n);
    if (!n) return NULL;
    n->addr = addr;
    n->port_lo = port_lo;
    n->port_hi = port_hi;
    n->nports = (uint32_t)port_hi - port_lo + 1;
    n->cap = n->nports * PI_COUNT < NAT_MAX_MAPPINGS ? n->nports * PI_COUNT : NAT_MAX_MAPPINGS;

    n->pool = fw_calloc(n->cap, sizeof *n->pool);
    n->bucket = fw_calloc(NAT_BUCKETS, sizeof *n->bucket);
    bool ok = n->pool && n->bucket && fw_random(n->hash_key, sizeof n->hash_key);
    for (int pi = 0; ok && pi < PI_COUNT; pi++)
        ok = (n->rev[pi] = fw_calloc(n->nports, sizeof *n->rev[pi])) != NULL;
    if (!ok) { nat_destroy(n); return NULL; }

    for (uint32_t b = 0; b < NAT_BUCKETS; b++) n->bucket[b] = NO_ENTRY;
    for (int pi = 0; pi < PI_COUNT; pi++)
        for (uint32_t s = 0; s < n->nports; s++) n->rev[pi][s] = NO_ENTRY;
    for (uint32_t i = 0; i < n->cap; i++)
        n->pool[i].next = i + 1 < n->cap ? (int32_t)(i + 1) : NO_ENTRY;
    n->free_head = 0;
    return n;
}

void nat_destroy(nat_t *n)
{
    if (!n) return;
    for (int pi = 0; pi < PI_COUNT; pi++) free(n->rev[pi]);
    free(n->bucket);
    free(n->pool);
    free(n);
}

uint32_t nat_addr(const nat_t *n) { return n->addr; }

nat_result_t nat_outbound(nat_t *n, uint8_t *buf, const pkt_t *p,
                          bool may_create, uint64_t now_ns)
{
    (void)now_ns;
    const size_t ihl = (size_t)(buf[0] & 0x0f) * 4;

    if (p->proto == FW_PROTO_ICMP && icmp_is_error(p->icmp_type)) {
        /* The inside host reports a problem with a packet it received: that
         * packet was translated on its way in, so the embedded copy names the
         * inside host where the remote side saw the NAT address. */
        pkt_t inner;
        if (parse_icmp_inner(p, &inner) != PARSE_OK) return NAT_PASS;
        const int32_t i = find(n, inner.proto, inner.dst_ip, inner.dst_port,
                               inner.src_ip, inner.src_port);
        if (i == NO_ENTRY) return NAT_PASS;
        rewrite_endpoint(buf, ihl, false, n->addr, 0);
        rewrite_endpoint(buf + ihl + 8, p->ip_len - ihl - 8, true, n->addr,
                         n->pool[i].nat_port);
        icmp_recompute(buf);
        n->st.translated_out++;
        n->st.icmp_errors_translated++;
        return NAT_TRANSLATED;
    }

    int32_t i = find(n, p->proto, p->src_ip, p->src_port, p->dst_ip, p->dst_port);
    if (i == NO_ENTRY) {
        if (!may_create || proto_index(p->proto) < 0) return NAT_PASS;
        i = create(n, p->proto, p->src_ip, p->src_port, p->dst_ip, p->dst_port);
        if (i == NO_ENTRY) { n->st.drop_full++; return NAT_FULL; }
    }
    rewrite_endpoint(buf, p->ip_len, false, n->addr, n->pool[i].nat_port);
    n->st.translated_out++;
    return NAT_TRANSLATED;
}

nat_result_t nat_inbound(nat_t *n, uint8_t *buf, const pkt_t *p, uint64_t now_ns)
{
    (void)now_ns;
    if (p->dst_ip != n->addr) return NAT_PASS;
    const size_t ihl = (size_t)(buf[0] & 0x0f) * 4;

    if (p->proto == FW_PROTO_ICMP && icmp_is_error(p->icmp_type)) {
        /* An error about a packet we translated: its embedded copy carries
         * the NAT address and port as the source. */
        pkt_t inner;
        int32_t i = NO_ENTRY;
        if (parse_icmp_inner(p, &inner) == PARSE_OK && inner.src_ip == n->addr)
            i = by_nat_port(n, inner.proto, inner.src_port);
        const mapping_t *m = i == NO_ENTRY ? NULL : &n->pool[i];
        if (!m || m->rem_ip != inner.dst_ip ||
            (inner.proto != FW_PROTO_ICMP && m->rem_port != inner.dst_port)) {
            n->st.drop_no_mapping++;
            return NAT_NO_MAPPING;
        }
        rewrite_endpoint(buf, ihl, true, m->in_ip, 0);
        rewrite_endpoint(buf + ihl + 8, p->ip_len - ihl - 8, false, m->in_ip, m->in_port);
        icmp_recompute(buf);
        n->st.translated_in++;
        n->st.icmp_errors_translated++;
        return NAT_TRANSLATED;
    }

    const int32_t i = by_nat_port(n, p->proto, p->dst_port);
    const mapping_t *m = i == NO_ENTRY ? NULL : &n->pool[i];
    /* Only the remote endpoint the connection was opened to may answer. */
    if (!m || m->rem_ip != p->src_ip ||
        (p->proto != FW_PROTO_ICMP && m->rem_port != p->src_port)) {
        n->st.drop_no_mapping++;
        return NAT_NO_MAPPING;
    }
    rewrite_endpoint(buf, p->ip_len, true, m->in_ip, m->in_port);
    n->st.translated_in++;
    return NAT_TRANSLATED;
}

size_t nat_sweep(nat_t *n, nat_alive_fn alive, void *ud)
{
    size_t freed = 0;
    for (uint32_t i = 0; i < n->cap; i++) {
        const mapping_t *m = &n->pool[i];
        if (m->proto == 0) continue;
        pkt_t t;
        memset(&t, 0, sizeof t);
        t.proto = m->proto;
        t.src_ip = m->in_ip;   t.src_port = m->in_port;
        t.dst_ip = m->rem_ip;  t.dst_port = m->rem_port;
        if (m->proto == FW_PROTO_ICMP) t.icmp_type = ICMP_ECHO_REQUEST;
        if (!alive(ud, &t)) {
            release(n, (int32_t)i);
            freed++;
        }
    }
    return freed;
}

void nat_get_stats(const nat_t *n, nat_stats_t *out)
{
    *out = n->st;
}

void nat_stats_print(const nat_t *n, FILE *out)
{
    const nat_stats_t *s = &n->st;
    fprintf(out,
            "nat:     addr=%u.%u.%u.%u mappings active=%llu created=%llu freed=%llu "
            "translated out=%llu in=%llu icmp-errors=%llu "
            "dropped no-mapping=%llu full=%llu\n",
            n->addr >> 24, (n->addr >> 16) & 0xff, (n->addr >> 8) & 0xff, n->addr & 0xff,
            (unsigned long long)s->mappings_active, (unsigned long long)s->mappings_created,
            (unsigned long long)s->mappings_freed, (unsigned long long)s->translated_out,
            (unsigned long long)s->translated_in, (unsigned long long)s->icmp_errors_translated,
            (unsigned long long)s->drop_no_mapping, (unsigned long long)s->drop_full);
}

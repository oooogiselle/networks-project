/*=============================================================================
 * File Name:   pktbuild.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Test helper: builds wire-format TCP, UDP, ICMP echo and ICMP
 *              error packets, and recomputes checksums so a single defect can
 *              be tested in isolation.
 =============================================================================*/

/* pktbuild.c - test packet construction. See pktbuild.h. */
#include "pktbuild.h"

#include <string.h>

#include "parser.h"

void pb_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void pb_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

/* Write an IPv4 header (with options as NOPs). Returns the header length,
 * or 0 if the packet won't fit. */
static size_t ip_header(uint8_t *buf, size_t cap, const struct pb_opts *o,
                        uint8_t proto, uint32_t src, uint32_t dst,
                        size_t l4len)
{
    size_t optlen = o ? o->ip_opt_len : 0;
    size_t ihl = 20 + optlen;
    if (optlen % 4 || optlen > 40 || ihl + l4len > cap || ihl + l4len > 65535)
        return 0;

    memset(buf, 0, ihl);
    buf[0] = (uint8_t)(0x40 | (ihl / 4));
    pb_wr16(buf + 2, (uint16_t)(ihl + l4len));
    pb_wr16(buf + 4, 0x1234);          /* identification */
    pb_wr16(buf + 6, 0x4000);          /* DF */
    buf[8] = (o && o->ttl) ? o->ttl : 64;
    buf[9] = proto;
    pb_wr32(buf + 12, src);
    pb_wr32(buf + 16, dst);
    memset(buf + 20, 1, optlen);       /* IP option NOP */
    return ihl;
}

static uint16_t l4_csum(const uint8_t *ip, const uint8_t *l4, size_t l4len,
                        uint8_t proto)
{
    uint32_t src = rd32(ip + 12), dst = rd32(ip + 16);
    uint32_t sum = (src >> 16) + (src & 0xffff) + (dst >> 16) +
                   (dst & 0xffff) + proto + (uint32_t)l4len;
    return csum_fold(csum_partial(l4, l4len, sum));
}

void pb_fix_csums(uint8_t *pkt, size_t len)
{
    if (len < 20)
        return;
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len)
        return;

    pb_wr16(pkt + 10, 0);
    pb_wr16(pkt + 10, csum_fold(csum_partial(pkt, ihl, 0)));

    uint8_t *l4 = pkt + ihl;
    size_t l4len = len - ihl;
    switch (pkt[9]) {
    case FW_PROTO_TCP:
        if (l4len >= 20) {
            pb_wr16(l4 + 16, 0);
            pb_wr16(l4 + 16, l4_csum(pkt, l4, l4len, FW_PROTO_TCP));
        }
        break;
    case FW_PROTO_UDP:
        if (l4len >= 8 && rd16(l4 + 6) != 0) {
            pb_wr16(l4 + 6, 0);
            uint16_t c = l4_csum(pkt, l4, l4len, FW_PROTO_UDP);
            pb_wr16(l4 + 6, c ? c : 0xffff); /* 0 on the wire means "none" */
        }
        break;
    case FW_PROTO_ICMP:
        if (l4len >= 8) {
            pb_wr16(l4 + 2, 0);
            pb_wr16(l4 + 2, csum_fold(csum_partial(l4, l4len, 0)));
        }
        break;
    }
}

size_t pb_tcp(uint8_t *buf, size_t cap, const struct pb_opts *o,
              uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport,
              uint8_t flags, const void *payload, size_t plen)
{
    size_t optlen = o ? o->tcp_opt_len : 0;
    size_t thl = 20 + optlen;
    if (optlen % 4 || optlen > 40)
        return 0;
    size_t ihl = ip_header(buf, cap, o, FW_PROTO_TCP, src, dst, thl + plen);
    if (!ihl)
        return 0;

    uint8_t *t = buf + ihl;
    memset(t, 0, thl);
    pb_wr16(t, sport);
    pb_wr16(t + 2, dport);
    pb_wr32(t + 4, 1000);              /* seq */
    pb_wr32(t + 8, (flags & TCP_ACK) ? 2000 : 0);
    t[12] = (uint8_t)((thl / 4) << 4);
    t[13] = flags;
    pb_wr16(t + 14, 65535);            /* window */
    memset(t + 20, 1, optlen);         /* TCP option NOP */
    if (plen)
        memcpy(t + thl, payload, plen);

    size_t len = ihl + thl + plen;
    pb_fix_csums(buf, len);
    return len;
}

size_t pb_udp(uint8_t *buf, size_t cap, const struct pb_opts *o,
              uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport,
              const void *payload, size_t plen)
{
    size_t ihl = ip_header(buf, cap, o, FW_PROTO_UDP, src, dst, 8 + plen);
    if (!ihl)
        return 0;

    uint8_t *u = buf + ihl;
    pb_wr16(u, sport);
    pb_wr16(u + 2, dport);
    pb_wr16(u + 4, (uint16_t)(8 + plen));
    pb_wr16(u + 6, (o && o->udp_no_csum) ? 0 : 1); /* nonzero: fill in below */
    if (plen)
        memcpy(u + 8, payload, plen);

    size_t len = ihl + 8 + plen;
    pb_fix_csums(buf, len);
    return len;
}

size_t pb_icmp_echo(uint8_t *buf, size_t cap, const struct pb_opts *o,
                    uint32_t src, uint32_t dst, uint8_t type, uint16_t id,
                    uint16_t seq, const void *payload, size_t plen)
{
    size_t ihl = ip_header(buf, cap, o, FW_PROTO_ICMP, src, dst, 8 + plen);
    if (!ihl)
        return 0;

    uint8_t *c = buf + ihl;
    c[0] = type;
    c[1] = 0;
    pb_wr16(c + 4, id);
    pb_wr16(c + 6, seq);
    if (plen)
        memcpy(c + 8, payload, plen);

    size_t len = ihl + 8 + plen;
    pb_fix_csums(buf, len);
    return len;
}

size_t pb_icmp_error(uint8_t *buf, size_t cap, const struct pb_opts *o,
                     uint32_t src, uint32_t dst, uint8_t type, uint8_t code,
                     const uint8_t *orig, size_t embed_len)
{
    size_t ihl = ip_header(buf, cap, o, FW_PROTO_ICMP, src, dst, 8 + embed_len);
    if (!ihl)
        return 0;

    uint8_t *c = buf + ihl;
    memset(c, 0, 8);
    c[0] = type;
    c[1] = code;
    if (embed_len)
        memcpy(c + 8, orig, embed_len);

    size_t len = ihl + 8 + embed_len;
    pb_fix_csums(buf, len);
    return len;
}

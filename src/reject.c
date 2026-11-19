/*=============================================================================
 * File Name:   reject.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: The answer to a rejected packet (see reject.h): a TCP RST or
 *              an ICMP destination unreachable, built with full checksums.
 =============================================================================*/

#include "reject.h"

#include <string.h>

#include "engine.h"
#include "parser.h"

#define IP_HDR   20
#define TCP_HDR  20
#define ICMP_HDR 8
#define REPLY_TTL 64

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* A 20-byte IPv4 header from src to dst (host order), checksum filled in. */
static void put_ip(uint8_t *h, uint16_t total, uint8_t proto, uint32_t src, uint32_t dst)
{
    h[0] = 0x45;                 /* version 4, IHL 5 */
    h[1] = 0;
    wr16(h + 2, total);
    wr16(h + 4, 0);              /* ID: DF is set, so it is never used */
    wr16(h + 6, 0x4000);         /* DF */
    h[8] = REPLY_TTL;
    h[9] = proto;
    wr16(h + 10, 0);
    wr32(h + 12, src);
    wr32(h + 16, dst);
    wr16(h + 10, csum_fold(csum_partial(h, IP_HDR, 0)));
}

static size_t build_rst(const uint8_t *pkt, size_t ihl, size_t len, uint8_t *out, size_t cap)
{
    if (len < ihl + TCP_HDR || cap < IP_HDR + TCP_HDR) return 0;
    const uint8_t *tcp = pkt + ihl;
    const uint8_t flags = tcp[13];
    if (flags & TCP_RST) return 0;               /* never answer a RST */

    const uint32_t src = rd32(pkt + 16), dst = rd32(pkt + 12);   /* swapped */
    const size_t doff = (size_t)(tcp[12] >> 4) * 4;
    const size_t total = rd16(pkt + 2);
    if (doff < TCP_HDR || total > len || ihl + doff > total) return 0;
    const uint32_t seg_len = (uint32_t)(total - ihl - doff) +
                             ((flags & TCP_SYN) ? 1 : 0) + ((flags & TCP_FIN) ? 1 : 0);

    uint8_t *t = out + IP_HDR;
    memset(t, 0, TCP_HDR);
    wr16(t, rd16(tcp + 2));                      /* ports swapped */
    wr16(t + 2, rd16(tcp));
    if (flags & TCP_ACK) {
        wr32(t + 4, rd32(tcp + 8));              /* seq = their ack */
        t[13] = TCP_RST;
    } else {
        wr32(t + 4, 0);
        wr32(t + 8, rd32(tcp + 4) + seg_len);    /* ack what they sent */
        t[13] = TCP_RST | TCP_ACK;
    }
    t[12] = (TCP_HDR / 4) << 4;
    wr16(t + 16, csum_fold(csum_partial(t, TCP_HDR,
                                        csum_pseudo(src, dst, FW_PROTO_TCP, TCP_HDR))));
    put_ip(out, IP_HDR + TCP_HDR, FW_PROTO_TCP, src, dst);
    return IP_HDR + TCP_HDR;
}

static size_t build_unreach(const uint8_t *pkt, size_t ihl, size_t len, uint8_t code,
                            uint8_t *out, size_t cap)
{
    const size_t quote = ihl + 8;                /* RFC 792: IP header + 64 bits */
    const size_t total = IP_HDR + ICMP_HDR + quote;
    if (len < quote || cap < total) return 0;
    const uint32_t src = rd32(pkt + 16), dst = rd32(pkt + 12);   /* swapped */

    uint8_t *icmp = out + IP_HDR;
    memset(icmp, 0, ICMP_HDR);
    icmp[0] = ICMP_DEST_UNREACH;
    icmp[1] = code;
    memcpy(icmp + ICMP_HDR, pkt, quote);
    wr16(icmp + 2, csum_fold(csum_partial(icmp, ICMP_HDR + quote, 0)));
    put_ip(out, (uint16_t)total, FW_PROTO_ICMP, src, dst);
    return total;
}

size_t reject_build(const uint8_t *pkt, size_t len, uint8_t *out, size_t cap)
{
    if (!pkt || !out || len < IP_HDR || (pkt[0] >> 4) != 4) return 0;
    const size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < IP_HDR || ihl > len) return 0;

    switch (pkt[9]) {
    case FW_PROTO_TCP:
        return build_rst(pkt, ihl, len, out, cap);
    case FW_PROTO_UDP:
        return build_unreach(pkt, ihl, len, ICMP_CODE_PORT_UNREACH, out, cap);
    case FW_PROTO_ICMP:
        if (len < ihl + 1 || pkt[ihl] != ICMP_ECHO_REQUEST) return 0;
        return build_unreach(pkt, ihl, len, ICMP_CODE_ADMIN_PROHIB, out, cap);
    default:
        return 0;
    }
}

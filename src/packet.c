/*
 * packet.c - zero-copy IPv4 / TCP / UDP / ICMP parser and RFC 1071 checksums.
 *
 * All multi-byte fields are read a byte at a time, so the parser makes no
 * alignment or endianness assumptions about the buffer.
 */
#include "packet.h"

#include <string.h>

#define IPV4_MIN_HDR 20
#define TCP_MIN_HDR  20
#define UDP_HDR      8
#define ICMP_HDR     8

#define IP_FLAG_RESERVED 0x8000
#define IP_FLAG_MF       0x2000
#define IP_OFFSET_MASK   0x1fff

static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

/* ---- checksums ---------------------------------------------------------- */

/*
 * One's-complement sum of big-endian 16-bit words. The result is unfolded;
 * pass it to csum_fold(). Carries fold back in early, so the 32-bit
 * accumulator can't overflow on any input length.
 */
uint32_t csum_partial(const void *data, size_t len, uint32_t sum)
{
    const uint8_t *p = data;

    while (len > 1) {
        sum += (uint32_t)p[0] << 8 | p[1];
        if (sum & 0x80000000u)
            sum = (sum & 0xffff) + (sum >> 16);
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

/* Fold to 16 bits and complement. Verifying a checksummed region gives 0. */
uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* TCP/UDP pseudo-header: src, dst, zero, protocol, L4 length. */
static uint32_t pseudo_sum(uint32_t src, uint32_t dst, uint8_t proto,
                           uint16_t l4len)
{
    return (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) +
           proto + l4len;
}

/* ---- address sanity ------------------------------------------------------ */

static int bad_source(uint32_t a)
{
    return a == 0 ||                 /* 0.0.0.0 */
           (a >> 24) == 127 ||       /* loopback */
           (a >> 28) >= 0xe;         /* multicast 224/4, class E, broadcast */
}

static int bad_dest(uint32_t a)
{
    return a == 0 || (a >> 24) == 127;
}

static int multicast_or_broadcast(uint32_t a)
{
    return (a >> 28) >= 0xe;
}

/* ---- L4 parsers ----------------------------------------------------------- */

static enum reason parse_tcp(const uint8_t *l4, uint16_t l4len, struct pkt *out)
{
    if (l4len < TCP_MIN_HDR)
        return R_MALFORMED;

    unsigned doff = (unsigned)(l4[12] >> 4) * 4;
    if (doff < TCP_MIN_HDR || doff > l4len)
        return R_MALFORMED;

    out->sport = rd16(l4);
    out->dport = rd16(l4 + 2);
    if (out->sport == 0 || out->dport == 0)
        return R_MALFORMED;

    uint32_t sum = pseudo_sum(out->src, out->dst, PROTO_TCP, l4len);
    if (csum_fold(csum_partial(l4, l4len, sum)) != 0)
        return R_BAD_CSUM;

    out->tcp_flags = l4[13];
    return R_OK;
}

static enum reason parse_udp(const uint8_t *l4, uint16_t l4len, struct pkt *out)
{
    if (l4len < UDP_HDR)
        return R_MALFORMED;
    if (rd16(l4 + 4) != l4len)
        return R_MALFORMED;

    out->sport = rd16(l4);
    out->dport = rd16(l4 + 2);
    if (out->sport == 0 || out->dport == 0)
        return R_MALFORMED;

    if (rd16(l4 + 6) != 0) { /* 0 means the sender computed no checksum */
        uint32_t sum = pseudo_sum(out->src, out->dst, PROTO_UDP, l4len);
        if (csum_fold(csum_partial(l4, l4len, sum)) != 0)
            return R_BAD_CSUM;
    }
    return R_OK;
}

static enum reason parse_icmp(const uint8_t *l4, uint16_t l4len,
                              struct pkt *out)
{
    if (l4len < ICMP_HDR)
        return R_MALFORMED;
    if (csum_fold(csum_partial(l4, l4len, 0)) != 0)
        return R_BAD_CSUM;

    out->icmp_type = l4[0];
    out->icmp_code = l4[1];

    switch (out->icmp_type) {
    case ICMP_ECHO_REQUEST:
    case ICMP_ECHO_REPLY:
        out->sport = out->dport = rd16(l4 + 4);
        return R_OK;
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAM_PROBLEM: {
        out->inner = l4 + ICMP_HDR;
        out->inner_len = (uint16_t)(l4len - ICMP_HDR);
        struct pkt tmp;
        return pkt_parse_inner(out, &tmp);
    }
    default:
        return R_UNSUPPORTED;
    }
}

/* ---- public ---------------------------------------------------------------- */

enum reason pkt_parse(const uint8_t *buf, size_t len, struct pkt *out)
{
    if (buf == NULL || out == NULL || len == 0)
        return R_MALFORMED;
    if ((buf[0] >> 4) != 4)
        return R_UNSUPPORTED;
    if (len < IPV4_MIN_HDR)
        return R_MALFORMED;

    unsigned ihl = (unsigned)(buf[0] & 0x0f) * 4;
    unsigned total = rd16(buf + 2);
    if (ihl < IPV4_MIN_HDR || total < ihl || total != len)
        return R_MALFORMED;

    if (csum_fold(csum_partial(buf, ihl, 0)) != 0)
        return R_BAD_CSUM;

    uint16_t frag = rd16(buf + 6);
    if (frag & IP_FLAG_RESERVED)
        return R_MALFORMED;
    if (frag & (IP_FLAG_MF | IP_OFFSET_MASK))
        return R_FRAGMENT;

    memset(out, 0, sizeof *out);
    out->buf = buf;
    out->len = (uint16_t)total;
    out->l4_off = (uint16_t)ihl;
    out->l4_len = (uint16_t)(total - ihl);
    out->ttl = buf[8];
    out->proto = buf[9];
    out->src = rd32(buf + 12);
    out->dst = rd32(buf + 16);

    if (bad_source(out->src) || bad_dest(out->dst))
        return R_MALFORMED;
    if (multicast_or_broadcast(out->dst))
        return R_UNSUPPORTED;

    const uint8_t *l4 = buf + ihl;
    switch (out->proto) {
    case PROTO_TCP:
        return parse_tcp(l4, out->l4_len, out);
    case PROTO_UDP:
        return parse_udp(l4, out->l4_len, out);
    case PROTO_ICMP:
        return parse_icmp(l4, out->l4_len, out);
    default:
        return R_UNSUPPORTED;
    }
}

enum reason pkt_parse_inner(const struct pkt *p, struct pkt *out)
{
    if (p == NULL || out == NULL || p->inner == NULL)
        return R_MALFORMED;

    const uint8_t *ip = p->inner;
    uint16_t len = p->inner_len;

    if (len < IPV4_MIN_HDR || (ip[0] >> 4) != 4)
        return R_MALFORMED;
    unsigned ihl = (unsigned)(ip[0] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HDR || (unsigned)len < ihl + 8)
        return R_MALFORMED;
    if (rd16(ip + 6) & IP_OFFSET_MASK)
        return R_FRAGMENT; /* non-first fragment: no L4 header to match */

    memset(out, 0, sizeof *out);
    out->buf = ip;
    out->len = len;
    out->l4_off = (uint16_t)ihl;
    out->l4_len = (uint16_t)(len - ihl);
    out->ttl = ip[8];
    out->proto = ip[9];
    out->src = rd32(ip + 12);
    out->dst = rd32(ip + 16);

    const uint8_t *l4 = ip + ihl;
    switch (out->proto) {
    case PROTO_TCP:
    case PROTO_UDP:
        out->sport = rd16(l4);
        out->dport = rd16(l4 + 2);
        return R_OK;
    case PROTO_ICMP:
        out->icmp_type = l4[0];
        out->icmp_code = l4[1];
        /* An error about an error is never generated (RFC 1122), and only
         * echo can belong to a flow. */
        if (out->icmp_type != ICMP_ECHO_REQUEST &&
            out->icmp_type != ICMP_ECHO_REPLY)
            return R_UNSUPPORTED;
        out->sport = out->dport = rd16(l4 + 4);
        return R_OK;
    default:
        return R_UNSUPPORTED;
    }
}

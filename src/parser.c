/*
 * parser.c - zero-copy IPv4 / TCP / UDP / ICMP parser and RFC 1071 checksums.
 *
 * All multi-byte fields are read a byte at a time, so the parser makes no
 * alignment or endianness assumptions about the buffer.
 */
#include "parser.h"

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

const char *parse_result_str(parse_result_t r)
{
    static const char *const names[PARSE_RESULT_COUNT] = {
        [PARSE_OK] = "ok",
        [PARSE_MALFORMED] = "malformed",
        [PARSE_FRAGMENT] = "fragment",
        [PARSE_UNSUPPORTED] = "unsupported",
        [PARSE_BAD_CSUM] = "bad-checksum",
    };
    return ((unsigned)r < PARSE_RESULT_COUNT) ? names[r] : "unknown";
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

static void set_payload(pkt_t *out, const uint8_t *l4, uint16_t l4len,
                        unsigned hdrlen)
{
    out->payload_len = (uint16_t)(l4len - hdrlen);
    out->payload = out->payload_len ? l4 + hdrlen : NULL;
}

static parse_result_t parse_tcp(const uint8_t *l4, uint16_t l4len, pkt_t *out)
{
    if (l4len < TCP_MIN_HDR)
        return PARSE_MALFORMED;

    unsigned doff = (unsigned)(l4[12] >> 4) * 4;
    if (doff < TCP_MIN_HDR || doff > l4len)
        return PARSE_MALFORMED;

    out->src_port = rd16(l4);
    out->dst_port = rd16(l4 + 2);
    if (out->src_port == 0 || out->dst_port == 0)
        return PARSE_MALFORMED;

    uint32_t sum = pseudo_sum(out->src_ip, out->dst_ip, FW_PROTO_TCP, l4len);
    if (csum_fold(csum_partial(l4, l4len, sum)) != 0)
        return PARSE_BAD_CSUM;

    out->tcp_flags = l4[13];
    set_payload(out, l4, l4len, doff);
    return PARSE_OK;
}

static parse_result_t parse_udp(const uint8_t *l4, uint16_t l4len, pkt_t *out)
{
    if (l4len < UDP_HDR)
        return PARSE_MALFORMED;
    if (rd16(l4 + 4) != l4len)
        return PARSE_MALFORMED;

    out->src_port = rd16(l4);
    out->dst_port = rd16(l4 + 2);
    if (out->src_port == 0 || out->dst_port == 0)
        return PARSE_MALFORMED;

    if (rd16(l4 + 6) != 0) { /* 0 means the sender computed no checksum */
        uint32_t sum =
            pseudo_sum(out->src_ip, out->dst_ip, FW_PROTO_UDP, l4len);
        if (csum_fold(csum_partial(l4, l4len, sum)) != 0)
            return PARSE_BAD_CSUM;
    }
    set_payload(out, l4, l4len, UDP_HDR);
    return PARSE_OK;
}

int icmp_is_error(uint8_t icmp_type)
{
    return icmp_type == ICMP_DEST_UNREACH || icmp_type == ICMP_TIME_EXCEEDED ||
           icmp_type == ICMP_PARAM_PROBLEM;
}

static parse_result_t parse_icmp(const uint8_t *l4, uint16_t l4len,
                                 pkt_t *out)
{
    if (l4len < ICMP_HDR)
        return PARSE_MALFORMED;
    if (csum_fold(csum_partial(l4, l4len, 0)) != 0)
        return PARSE_BAD_CSUM;

    out->icmp_type = l4[0];
    set_payload(out, l4, l4len, ICMP_HDR);

    if (out->icmp_type == ICMP_ECHO_REQUEST ||
        out->icmp_type == ICMP_ECHO_REPLY) {
        out->src_port = out->dst_port = rd16(l4 + 4);
        return PARSE_OK;
    }
    if (icmp_is_error(out->icmp_type)) {
        pkt_t tmp;
        return parse_icmp_inner(out, &tmp);
    }
    return PARSE_UNSUPPORTED;
}

/* ---- public ---------------------------------------------------------------- */

parse_result_t parse_packet(const uint8_t *buf, size_t len, pkt_t *out)
{
    if (buf == NULL || out == NULL || len == 0)
        return PARSE_MALFORMED;
    if ((buf[0] >> 4) != 4)
        return PARSE_UNSUPPORTED;
    if (len < IPV4_MIN_HDR)
        return PARSE_MALFORMED;

    unsigned ihl = (unsigned)(buf[0] & 0x0f) * 4;
    unsigned total = rd16(buf + 2);
    if (ihl < IPV4_MIN_HDR || total < ihl || total != len)
        return PARSE_MALFORMED;

    if (csum_fold(csum_partial(buf, ihl, 0)) != 0)
        return PARSE_BAD_CSUM;

    uint16_t frag = rd16(buf + 6);
    if (frag & IP_FLAG_RESERVED)
        return PARSE_MALFORMED;
    if (frag & (IP_FLAG_MF | IP_OFFSET_MASK))
        return PARSE_FRAGMENT;

    memset(out, 0, sizeof *out);
    out->ip_len = (uint16_t)total;
    out->proto = buf[9];
    out->src_ip = rd32(buf + 12);
    out->dst_ip = rd32(buf + 16);

    if (bad_source(out->src_ip) || bad_dest(out->dst_ip))
        return PARSE_MALFORMED;
    if (multicast_or_broadcast(out->dst_ip))
        return PARSE_UNSUPPORTED;

    const uint8_t *l4 = buf + ihl;
    uint16_t l4len = (uint16_t)(total - ihl);
    switch (out->proto) {
    case FW_PROTO_TCP:
        return parse_tcp(l4, l4len, out);
    case FW_PROTO_UDP:
        return parse_udp(l4, l4len, out);
    case FW_PROTO_ICMP:
        return parse_icmp(l4, l4len, out);
    default:
        return PARSE_UNSUPPORTED;
    }
}

parse_result_t parse_icmp_inner(const pkt_t *p, pkt_t *inner)
{
    if (p == NULL || inner == NULL || p->proto != FW_PROTO_ICMP ||
        !icmp_is_error(p->icmp_type) || p->payload == NULL)
        return PARSE_MALFORMED;

    const uint8_t *ip = p->payload;
    uint16_t len = p->payload_len;

    if (len < IPV4_MIN_HDR || (ip[0] >> 4) != 4)
        return PARSE_MALFORMED;
    unsigned ihl = (unsigned)(ip[0] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HDR || (unsigned)len < ihl + 8)
        return PARSE_MALFORMED;
    if (rd16(ip + 6) & IP_OFFSET_MASK)
        return PARSE_FRAGMENT;

    memset(inner, 0, sizeof *inner);
    inner->ip_len = len;
    inner->proto = ip[9];
    inner->src_ip = rd32(ip + 12);
    inner->dst_ip = rd32(ip + 16);

    const uint8_t *l4 = ip + ihl;
    switch (inner->proto) {
    case FW_PROTO_TCP:
    case FW_PROTO_UDP:
        inner->src_port = rd16(l4);
        inner->dst_port = rd16(l4 + 2);
        return PARSE_OK;
    case FW_PROTO_ICMP:
        inner->icmp_type = l4[0];
        /* An error about an error is never generated (RFC 1122), and only
         * echo can belong to a flow. */
        if (inner->icmp_type != ICMP_ECHO_REQUEST &&
            inner->icmp_type != ICMP_ECHO_REPLY)
            return PARSE_UNSUPPORTED;
        inner->src_port = inner->dst_port = rd16(l4 + 4);
        return PARSE_OK;
    default:
        return PARSE_UNSUPPORTED;
    }
}

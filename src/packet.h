/*
 * packet.h - zero-copy IPv4 / TCP / UDP / ICMP parser.
 *
 * pkt_parse() validates lengths and checksums and fills a struct pkt whose
 * pointers refer into the caller's buffer. Nothing is copied or allocated.
 * All numeric fields are in HOST byte order.
 */
#ifndef TUNWALL_PACKET_H
#define TUNWALL_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "common.h"

struct pkt {
    const uint8_t *buf;    /* start of the IPv4 header */
    uint16_t len;          /* IPv4 total length (<= bytes read) */
    uint16_t l4_off;       /* offset of the L4 header from buf */
    uint16_t l4_len;       /* bytes from l4_off to the end of the packet */

    uint8_t proto;         /* PROTO_TCP / PROTO_UDP / PROTO_ICMP */
    uint8_t ttl;
    uint8_t tcp_flags;     /* TCP only */
    uint8_t icmp_type;     /* ICMP only */
    uint8_t icmp_code;     /* ICMP only */

    uint32_t src, dst;     /* IPv4 addresses */
    uint16_t sport, dport; /* TCP/UDP ports; ICMP echo: both = identifier */

    /* ICMP error messages only (dest unreachable, time exceeded, param
     * problem): the embedded original IP header plus >= 8 bytes of its L4
     * header. NULL / 0 otherwise. */
    const uint8_t *inner;
    uint16_t inner_len;
};

/*
 * Parse and validate one raw IPv4 packet of `len` bytes.
 * Returns R_OK and fills *out on success; otherwise returns the drop reason
 * (R_MALFORMED, R_FRAGMENT, R_UNSUPPORTED, R_BAD_CSUM) and *out is undefined.
 * Never reads outside buf[0 .. len).
 *
 * Validation, in order:
 *   - IPv4 only (else R_UNSUPPORTED); 20 <= IHL*4 <= total length == len
 *     (TUN delivers exactly one packet per read, so trailing bytes are
 *     malformed too)
 *   - IP header checksum (R_BAD_CSUM)
 *   - reserved flag bit clear (R_MALFORMED); MF clear and offset 0
 *     (R_FRAGMENT)
 *   - source not 0.0.0.0, 127/8, multicast/class E, or broadcast;
 *     destination not 0.0.0.0 or 127/8 (R_MALFORMED). Multicast or
 *     broadcast destination: R_UNSUPPORTED
 *   - TCP: header fits, data offset >= 5 and fits, ports != 0, checksum
 *   - UDP: header fits, UDP length == IP payload length, ports != 0,
 *     checksum (0 = no checksum is accepted)
 *   - ICMP: header fits, checksum; only echo request/reply and the errors
 *     (dest unreachable, time exceeded, parameter problem) are supported.
 *     Errors must embed a parseable IPv4 header plus 8 bytes of its L4
 *     header (see pkt_parse_inner).
 *   - any other IP protocol: R_UNSUPPORTED
 */
enum reason pkt_parse(const uint8_t *buf, size_t len, struct pkt *out);

/*
 * Parse the original packet embedded in an ICMP error (p->inner). Fills
 * src, dst, proto, ttl, and sport/dport (TCP/UDP), or icmp_type/icmp_code
 * plus sport = dport = identifier for an embedded echo.
 * Lengths and checksums of the embedded packet are NOT checked, because it is
 * truncated by design. tcp_flags is 0 and inner is NULL in the result.
 * Returns R_OK, R_MALFORMED (no inner / too short / bad header),
 * R_FRAGMENT (non-first fragment, so no L4 header), or R_UNSUPPORTED.
 */
enum reason pkt_parse_inner(const struct pkt *p, struct pkt *out);

/* RFC 1071 Internet checksum helpers (exposed for tests and for NAT later). */
uint32_t csum_partial(const void *data, size_t len, uint32_t sum);
uint16_t csum_fold(uint32_t sum);

#endif /* TUNWALL_PACKET_H */

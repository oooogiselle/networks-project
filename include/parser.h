/*=============================================================================
 * File Name:   parser.h
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Packet parser interface: zero-copy IPv4/TCP/UDP/ICMP parsing,
 *              ICMP error inner-packet extraction, and RFC 1071 checksum
 *              helpers.
 =============================================================================*/

/*
 * parser.h - zero-copy IPv4 / TCP / UDP / ICMP parser.
 *
 * parse_packet() validates one raw packet read from a TUN device and fills
 * the pkt_t that engine_decide() consumes (see the contract in engine.h).
 * Nothing is copied or allocated: pkt_t.payload points into the caller's
 * buffer. All numeric fields are in HOST byte order.
 *
 * Packets that fail parsing must be dropped before engine_decide(); the
 * I/O loop counts and logs them by parse_result_t.
 */
#ifndef FW_PARSER_H
#define FW_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "engine.h"

/* ICMP error types (echo types are in engine.h). */
#define ICMP_DEST_UNREACH  3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAM_PROBLEM 12

typedef enum {
    PARSE_OK = 0,
    PARSE_MALFORMED,     /* bad lengths, header fields, or addresses */
    PARSE_FRAGMENT,      /* IP fragment (unsupported in this version) */
    PARSE_UNSUPPORTED,   /* not IPv4, unknown protocol, untracked ICMP type,
                            multicast/broadcast destination */
    PARSE_BAD_CSUM,      /* IP or L4 checksum mismatch */
    PARSE_RESULT_COUNT
} parse_result_t;

const char *parse_result_str(parse_result_t r);

/*
 * Parse and validate one raw IPv4 packet of `len` bytes.
 * Returns PARSE_OK and fills *out; otherwise *out is undefined.
 * Never reads outside buf[0 .. len).
 *
 * Validation, in order:
 *   - IPv4 only (else UNSUPPORTED); 20 <= IHL*4 <= total length == len
 *     (TUN delivers exactly one packet per read, so trailing bytes are
 *     malformed too)
 *   - IP header checksum (BAD_CSUM)
 *   - reserved flag bit clear (MALFORMED); MF clear and offset 0 (FRAGMENT)
 *   - source not 0.0.0.0, 127/8, multicast/class E, or broadcast;
 *     destination not 0.0.0.0 or 127/8 (MALFORMED). Multicast or broadcast
 *     destination: UNSUPPORTED
 *   - TCP: header fits, data offset >= 5 and fits, ports != 0, checksum
 *   - UDP: header fits, UDP length == IP payload length, ports != 0,
 *     checksum (0 = no checksum is accepted)
 *   - ICMP: header fits, checksum. Only echo request/reply and the errors
 *     (dest unreachable, time exceeded, parameter problem) are supported.
 *     Errors must embed a parseable IPv4 header plus 8 bytes of its L4
 *     header (see parse_icmp_inner).
 *   - any other IP protocol: UNSUPPORTED
 *
 * Fills, per engine.h: proto, src_ip, dst_ip, src_port, dst_port (ICMP echo:
 * identifier in both; ICMP error: 0), tcp_flags (raw header byte, including
 * ECE/CWR; judging flag combinations is the TCP state machine's job),
 * icmp_type, ip_len, and payload/payload_len (the bytes after the L4 header;
 * NULL when empty). For an ICMP error, payload is the embedded original
 * packet.
 */
parse_result_t parse_packet(const uint8_t *buf, size_t len, pkt_t *out);

/* True for ICMP types whose payload is an embedded original packet. */
int icmp_is_error(uint8_t icmp_type);

/*
 * Extract the original packet's tuple from an ICMP error (p from a
 * successful parse_packet with icmp_is_error(p->icmp_type)).
 * Fills proto, src_ip, dst_ip, src_port, dst_port (or icmp_type plus echo
 * identifier for an embedded echo). The inner packet's lengths and checksums
 * are NOT checked, because it is truncated by design; ip_len is the embedded
 * length, and tcp_flags, payload and payload_len are 0/NULL.
 * Returns PARSE_OK, MALFORMED (not an error / too short / bad header),
 * FRAGMENT (non-first fragment: no L4 header to match), or UNSUPPORTED.
 *
 * The tuple is as the original sender wrote it, i.e. the REVERSE of the
 * direction the error travels.
 */
parse_result_t parse_icmp_inner(const pkt_t *p, pkt_t *inner);

/* RFC 1071 Internet checksum helpers (exposed for tests and for NAT later). */
uint32_t csum_partial(const void *data, size_t len, uint32_t sum);
uint16_t csum_fold(uint32_t sum);
/* Unfolded sum of the TCP/UDP pseudo-header (addresses in host order); pass
 * it as the starting sum to csum_partial() over the L4 header and data. */
uint32_t csum_pseudo(uint32_t src, uint32_t dst, uint8_t proto, uint16_t l4len);

#endif /* FW_PARSER_H */

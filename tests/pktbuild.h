/*=============================================================================
 * File Name:   pktbuild.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Test helper interface for building valid wire-format IPv4
 *              packets with correct checksums.
 =============================================================================*/

/*
 * pktbuild.h - build valid IPv4 test packets with correct checksums.
 *
 * Every builder writes into buf (capacity cap) and returns the packet length,
 * or 0 if it doesn't fit. Addresses and ports are in host byte order.
 * To test a single defect: build a valid packet, corrupt one field, then call
 * pb_fix_csums() so the checksum isn't what gets caught.
 */
#ifndef TUNWALL_PKTBUILD_H
#define TUNWALL_PKTBUILD_H

#include <stddef.h>
#include <stdint.h>

#define IP4(a, b, c, d) \
    ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 | (uint32_t)(d))

/* Optional knobs; pass NULL for defaults. */
struct pb_opts {
    uint8_t ttl;          /* 0 means 64 */
    uint8_t ip_opt_len;   /* bytes of IP options (multiple of 4, <= 40) */
    uint8_t tcp_opt_len;  /* bytes of TCP options (multiple of 4, <= 40) */
    int udp_no_csum;      /* send UDP checksum as 0 */
};

size_t pb_tcp(uint8_t *buf, size_t cap, const struct pb_opts *o,
              uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport,
              uint8_t flags, const void *payload, size_t plen);

size_t pb_udp(uint8_t *buf, size_t cap, const struct pb_opts *o,
              uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport,
              const void *payload, size_t plen);

/* type is ICMP_ECHO_REQUEST or ICMP_ECHO_REPLY. */
size_t pb_icmp_echo(uint8_t *buf, size_t cap, const struct pb_opts *o,
                    uint32_t src, uint32_t dst, uint8_t type, uint16_t id,
                    uint16_t seq, const void *payload, size_t plen);

/* ICMP error from src to dst that embeds the first embed_len bytes of orig. */
size_t pb_icmp_error(uint8_t *buf, size_t cap, const struct pb_opts *o,
                     uint32_t src, uint32_t dst, uint8_t type, uint8_t code,
                     const uint8_t *orig, size_t embed_len);

/* Recompute the IP header checksum and (if it fits) the L4 checksum. */
void pb_fix_csums(uint8_t *pkt, size_t len);

/* Big-endian field writers for corrupting packets in tests. */
void pb_wr16(uint8_t *p, uint16_t v);
void pb_wr32(uint8_t *p, uint32_t v);

#endif /* TUNWALL_PKTBUILD_H */

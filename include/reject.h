/*=============================================================================
 * File Name:   reject.h
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Builds the answer to a packet a `reject` rule matched, so the
 *              sender learns at once that it was refused instead of waiting
 *              for a timeout: a TCP RST for TCP, an ICMP destination
 *              unreachable for UDP (port unreachable) and for an ICMP echo
 *              request (administratively prohibited). Pure: no I/O, no
 *              allocation, so it is unit-testable and safe per packet.
 =============================================================================*/

#ifndef FW_REJECT_H
#define FW_REJECT_H

#include <stddef.h>
#include <stdint.h>

#define ICMP_DEST_UNREACH        3
#define ICMP_CODE_PORT_UNREACH   3
#define ICMP_CODE_ADMIN_PROHIB  13

/* Room for the largest answer: IP (20) + ICMP (8) + the quoted original IP
 * header (up to 60) + 8 bytes of its L4 header. */
#define REJECT_MAX_LEN 96

/*
 * Write the answer to pkt (a packet parse_packet() accepted, len bytes) into
 * out and return its length, or 0 if pkt must not be answered or out is too
 * small. The answer appears to come from the host pkt was sent to (source
 * and destination swapped), so it is routed back like a genuine reply, and
 * all its checksums are valid.
 *   TCP:  RST (RFC 793 section 3.4). If pkt had no ACK: seq 0, ACK set,
 *         ack = pkt's seq + its length in sequence space (data, SYN, FIN).
 *         If it had: seq = its ack, RST alone. A RST is never answered.
 *   UDP:  ICMP 3/3 port unreachable quoting pkt's IP header + 8 bytes.
 *   ICMP: only an echo request is answered, with ICMP 3/13 (administratively
 *         prohibited). ICMP errors and echo replies never are, so two
 *         firewalls cannot answer each other forever.
 */
size_t reject_build(const uint8_t *pkt, size_t len, uint8_t *out, size_t cap);

#endif

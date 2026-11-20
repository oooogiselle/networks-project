/*=============================================================================
 * File Name:   tcpseq.h
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: TCP sequence-number checks: track each direction's sequence
 *              window and refuse segments outside it, so a blind attacker
 *              cannot reset or inject into a connection.
 =============================================================================*/

/*
 * tcpseq.h - TCP window tracking, as in Linux conntrack (tcp_in_window) and
 * pf, after Guido van Rooij, "Real Stateful TCP Packet Filtering in IP
 * Filter" (2000).
 *
 * tcpstate.c follows a connection by its flags alone, so anyone who knows a
 * connection's addresses and ports could end it with one forged RST, or slip
 * data into it, without ever seeing a packet of it. Here each direction
 * remembers (flow_t.tw[]):
 *   end     the highest sequence number it has sent (seq + length),
 *   maxend  the highest one its peer has allowed it (peer's ack + window),
 *   maxwin  the largest window it has advertised (scaled).
 * A segment from sender s to receiver r, with end = seq + length (+1 for SYN,
 * +1 for FIN), must pass all of:
 *   A  seq <= s.maxend                          not beyond what r allowed
 *   B  end >= s.end - r.maxwin                  not older than one window
 *   C  ack <= r.end                    (if ACK) not acking unsent data
 *   D  ack >= r.end - max(s.maxwin, 66000)  (if ACK) not a stale ack
 * A forged segment must therefore guess a sequence number inside the
 * receiver's window: about window / 2^32, instead of always succeeding.
 * Comparisons are modulo 2^32, so connections may wrap.
 *
 * The handshake sets the windows up. The SYN (which created the flow, see
 * tcpseq_init) gives the originator's. The SYN-ACK must acknowledge the SYN
 * (ack in [isn + 1, end]: a TCP Fast Open server may ack only the SYN, not
 * its data) and gives the responder's. Window scaling (RFC 7323) applies
 * only when both SYNs offered it, and windows in SYNs are never scaled. An
 * RST answering a SYN must acknowledge it, as RFC 793 requires. SACK blocks
 * and timestamps (PAWS) are not checked, as Linux does not by default.
 *
 * Pure logic, no I/O. The engine calls tcpseq_check() before the flag state
 * machine and tcpseq_update() only once both have accepted the packet, so a
 * refused segment changes nothing.
 */
#ifndef FW_TCPSEQ_H
#define FW_TCPSEQ_H

#include <stdbool.h>

#include "engine.h"
#include "flowtable.h"

/* Bound for check D when the sender's window is small (as in Linux). */
#define TCPSEQ_MIN_ACK_WINDOW 66000u

/* Set up a new TCP flow's windows from the SYN that created it. */
void tcpseq_init(flow_t *f, const pkt_t *syn);

/* Is p (travelling from the originator if from_orig) inside the windows? */
bool tcpseq_check(const flow_t *f, const pkt_t *p, bool from_orig);

/* Record p in the windows. Call only after p was accepted. */
void tcpseq_update(flow_t *f, const pkt_t *p, bool from_orig);

#endif

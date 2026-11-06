/*
 * tcpstate.h - connection-tracking TCP state machine.
 *
 * Like Linux conntrack, we track state from observed flags only (we are a
 * middlebox, not an endpoint). Sequence-number validation is NOT done yet.
 *
 *   originator            responder
 *   SYN        ------->            SYN_SENT
 *              <-------  SYN+ACK   SYN_RECV
 *   ACK        ------->            ESTABLISHED
 *   FIN (either side)              FIN_WAIT
 *   FIN (other side)               TIME_WAIT
 *   RST (any time)                 CLOSED
 */
#ifndef FW_TCPSTATE_H
#define FW_TCPSTATE_H

#include "flowtable.h"

/* A TCP packet with these flags may start a new flow (plain SYN). */
bool tcp_is_pure_syn(uint8_t flags);

/* Set a freshly created TCP flow to SYN_SENT. */
void tcp_flow_init(flow_t *f);

/*
 * Feed one packet's flags to the flow's state machine.
 * from_orig: true if the packet travels originator -> responder.
 * Returns true if the packet is legal in the current state (and the state is
 * advanced); false if it must be dropped (state unchanged).
 */
bool tcp_track(flow_t *f, uint8_t flags, bool from_orig);

/* Idle timeout for a flow in its current state, in nanoseconds. */
uint64_t flow_timeout_ns(const flow_t *f);

#endif

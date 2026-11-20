/*=============================================================================
 * File Name:   tcpstate.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: TCP connection-tracking state machine (SYN_SENT through
 *              TIME_WAIT/CLOSED) with illegal-flag detection, plus the per-
 *              state idle timeouts from the spec.
 =============================================================================*/

#include "tcpstate.h"

#define SEC 1000000000ull

/* A connection starts with a SYN. ECE and CWR may ride along (ECN setup); any
 * other flag (ACK, FIN, RST, PSH, URG) makes it something else. */
bool tcp_is_pure_syn(uint8_t flags)
{
    return (flags & (uint8_t)~(TCP_ECE | TCP_CWR)) == TCP_SYN;
}

void tcp_flow_init(flow_t *f)
{
    f->tcp_state = TCPS_SYN_SENT;
    f->fin_seen = 0;
}

/* Flag combinations that are never legitimate. */
static bool flags_sane(uint8_t fl)
{
    if ((fl & 0x3f) == 0) return false;                       /* NULL scan */
    if ((fl & TCP_SYN) && (fl & (TCP_FIN | TCP_RST))) return false;
    if ((fl & TCP_FIN) && (fl & TCP_RST)) return false;
    if ((fl & TCP_FIN) && !(fl & TCP_ACK)) return false;      /* FIN scan  */
    return true;
}

bool tcp_track(flow_t *f, uint8_t fl, bool from_orig)
{
    return tcp_track_ex(f, fl, from_orig, 0);
}

bool tcp_track_ex(flow_t *f, uint8_t fl, bool from_orig, size_t payload_len)
{
    if (!flags_sane(fl)) return false;

    const bool syn = fl & TCP_SYN, ack = fl & TCP_ACK;
    const bool fin = fl & TCP_FIN, rst = fl & TCP_RST;

    /* RST tears the connection down from any state. (No sequence check yet:
     * a blind RST could kill a flow - listed as future work.) */
    if (rst) {
        if (f->tcp_state == TCPS_CLOSED) return true;   /* retransmitted RST */
        f->tcp_state = TCPS_CLOSED;
        return true;
    }

    switch (f->tcp_state) {
    case TCPS_SYN_SENT:
        if (from_orig) return syn && !ack;              /* SYN retransmit    */
        if (syn) { f->tcp_state = TCPS_SYN_RECV; return true; } /* SYN-ACK or
                                                         simultaneous open  */
        return false;

    case TCPS_SYN_RECV:
        if (from_orig) {
            if (syn) return true;       /* SYN retransmit, or SYN-ACK when both
                                           ends opened at once               */
            if (ack) { f->tcp_state = TCPS_ESTABLISHED; return true; }
            return false;
        }
        return syn;                                     /* SYN-ACK retransmit*/

    case TCPS_ESTABLISHED:
        if (syn) return !from_orig && ack;              /* late SYN-ACK retx */
        if (!ack) return false;
        if (fin) {
            f->fin_seen |= from_orig ? 1 : 2;
            f->tcp_state = TCPS_FIN_WAIT;
        }
        return true;

    case TCPS_FIN_WAIT:
        if (syn || !ack) return false;
        if (fin) {
            f->fin_seen |= from_orig ? 1 : 2;
            if (f->fin_seen == 3) f->tcp_state = TCPS_TIME_WAIT;
        }
        return true;

    case TCPS_TIME_WAIT:
        /* Both sides have closed: only payload-free ACKs (the last ACK, FIN
         * retransmits) make sense. Data here would let a closed connection
         * carry traffic indefinitely. */
        return !syn && ack && payload_len == 0;

    case TCPS_CLOSED:
    case TCPS_NONE:
    default:                       /* corrupt state value: never allow */
        return false;
    }
}

uint64_t flow_timeout_ns(const flow_t *f)
{
    switch (f->key.proto) {
    case FW_PROTO_TCP:
        switch (f->tcp_state) {
        case TCPS_SYN_SENT:
        case TCPS_SYN_RECV:    return 30 * SEC;
        case TCPS_ESTABLISHED: return 3600 * SEC;   /* 1 hour, per the spec */
        /* One side has sent FIN, the other may keep sending for as long as it
         * likes (ssh, rsync, a remote command after shutdown(WR)), so the
         * half-closed connection lives as long as an established one. */
        case TCPS_FIN_WAIT:    return 3600 * SEC;
        case TCPS_TIME_WAIT:   return 30 * SEC;
        case TCPS_CLOSED:      return 5 * SEC;
        case TCPS_NONE:        break;
        }
        return 30 * SEC;
    case FW_PROTO_UDP:
        return f->seen_reply ? 120 * SEC : 30 * SEC;
    case FW_PROTO_ICMP:
    default:
        return 30 * SEC;
    }
}

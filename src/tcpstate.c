#include "tcpstate.h"

#define SEC 1000000000ull

bool tcp_is_pure_syn(uint8_t flags)
{
    return (flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST)) == TCP_SYN;
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
            if (syn && !ack) return true;               /* SYN retransmit    */
            if (!syn && ack) { f->tcp_state = TCPS_ESTABLISHED; return true; }
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
        return !syn && ack;                             /* last ACKs / retx  */

    case TCPS_CLOSED:
    case TCPS_NONE:
        return false;
    }
    (void)fin;
    return false;
}

uint64_t flow_timeout_ns(const flow_t *f)
{
    switch (f->key.proto) {
    case FW_PROTO_TCP:
        switch (f->tcp_state) {
        case TCPS_SYN_SENT:
        case TCPS_SYN_RECV:    return 30 * SEC;
        case TCPS_ESTABLISHED: return 300 * SEC;
        case TCPS_FIN_WAIT:    return 60 * SEC;
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

/*=============================================================================
 * File Name:   tcpseq.c
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: TCP sequence-number checks (window tracking). See tcpseq.h.
 =============================================================================*/

#include "tcpseq.h"

#include <string.h>

/* Sequence-number order modulo 2^32 (RFC 793 / RFC 1982). */
static bool seq_lt(uint32_t a, uint32_t b)  { return (int32_t)(a - b) < 0; }
static bool seq_leq(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static bool seq_geq(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }

/* lo <= x <= hi, modulo 2^32. */
static bool seq_in(uint32_t x, uint32_t lo, uint32_t hi)
{
    return seq_geq(x, lo) && seq_leq(x, hi);
}

/* The sequence number just past this segment: SYN and FIN count as one. */
static uint32_t seg_end(const pkt_t *p)
{
    return p->tcp_seq + p->payload_len + ((p->tcp_flags & TCP_SYN) ? 1 : 0) +
           ((p->tcp_flags & TCP_FIN) ? 1 : 0);
}

/* A side's window state from its SYN (or SYN-ACK). Its windows are not
 * scaled yet: that is decided once both SYNs are known. */
static void init_side(tcp_win_t *w, const pkt_t *syn)
{
    memset(w, 0, sizeof *w);
    w->isn = syn->tcp_seq;
    w->end = seg_end(syn);
    w->maxend = w->end;
    w->maxwin = syn->tcp_win ? syn->tcp_win : 1;
    w->wscale = syn->tcp_wscale;
    w->init = true;
}

void tcpseq_init(flow_t *f, const pkt_t *syn)
{
    init_side(&f->tw[0], syn);
    memset(&f->tw[1], 0, sizeof f->tw[1]);
}

/* Does ack acknowledge side w's SYN (and at most what it sent with it)? */
static bool acks_syn(const tcp_win_t *w, uint32_t ack)
{
    return seq_in(ack, w->isn + 1, w->end);
}

bool tcpseq_check(const flow_t *f, const pkt_t *p, bool from_orig)
{
    const tcp_win_t *s = &f->tw[from_orig ? 0 : 1];
    const tcp_win_t *r = &f->tw[from_orig ? 1 : 0];
    const uint8_t fl = p->tcp_flags;
    const bool syn = fl & TCP_SYN, ack = fl & TCP_ACK, rst = fl & TCP_RST;

    if (syn) {
        /* The originator's SYN again before any answer: possibly with a new
         * ISN (tcpseq_update starts over from it). */
        if (from_orig && !r->init) return true;
        /* A SYN-ACK (or the other end's SYN in a simultaneous open) must
         * acknowledge the peer's SYN if it carries an ACK, and a repeat of a
         * SYN already seen must carry the same ISN. */
        if (ack && !acks_syn(r, p->tcp_ack)) return false;
        return !s->init || p->tcp_seq == s->isn;
    }

    if (!s->init) {
        /* The responder has not sent its SYN yet: the only thing it may send
         * is an RST refusing the connection, and that must acknowledge the
         * originator's SYN (RFC 793), which a blind attacker cannot guess. */
        return rst && ack && acks_syn(r, p->tcp_ack);
    }
    if (!r->init) {
        /* The originator aborting before any answer: an RST at its next
         * sequence number. */
        return rst && seq_in(p->tcp_seq, s->isn, s->end);
    }

    const uint32_t end = seg_end(p);
    if (!seq_leq(p->tcp_seq, s->maxend)) return false;                 /* A */
    if (!seq_geq(end, s->end - r->maxwin)) return false;               /* B */
    if (ack) {
        const uint32_t ackwin = s->maxwin > TCPSEQ_MIN_ACK_WINDOW
                                ? s->maxwin : TCPSEQ_MIN_ACK_WINDOW;
        if (!seq_leq(p->tcp_ack, r->end)) return false;                /* C */
        if (!seq_geq(p->tcp_ack, r->end - ackwin)) return false;       /* D */
    }
    return true;
}

void tcpseq_update(flow_t *f, const pkt_t *p, bool from_orig)
{
    tcp_win_t *s = &f->tw[from_orig ? 0 : 1];
    tcp_win_t *r = &f->tw[from_orig ? 1 : 0];
    const uint8_t fl = p->tcp_flags;
    const bool syn = fl & TCP_SYN, ack = fl & TCP_ACK;

    if (syn) {
        if (from_orig && !r->init) {             /* SYN retransmit: start over */
            init_side(s, p);
            return;
        }
        if (!s->init) {
            /* The other end's SYN: it may send as much as the originator's
             * SYN advertised. Both SYNs are known now, so decide scaling. */
            init_side(s, p);
            s->maxend = s->end + r->maxwin;
            const bool scaled = s->wscale != TCP_NO_WSCALE && r->wscale != TCP_NO_WSCALE;
            s->scale = scaled ? s->wscale : 0;
            r->scale = scaled ? r->wscale : 0;
        }
        /* Windows in SYN segments are never scaled. */
        if (ack && seq_lt(r->maxend, p->tcp_ack + p->tcp_win))
            r->maxend = p->tcp_ack + p->tcp_win;
        return;
    }
    if (!s->init || !r->init) return;            /* an RST before the handshake */

    const uint32_t win = (uint32_t)p->tcp_win << s->scale;
    const uint32_t end = seg_end(p);
    if (seq_lt(s->end, end)) s->end = end;
    if (win > s->maxwin) s->maxwin = win;
    if (ack && seq_lt(r->maxend, p->tcp_ack + win))
        r->maxend = p->tcp_ack + win;
}

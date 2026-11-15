/*=============================================================================
 * File Name:   forwarder.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: The packet loop (see forwarder.h). One read() per packet, one
 *              write() to the opposite side if the engine allows it. The one
 *              packet buffer is allocated at startup; nothing is allocated
 *              while forwarding.
 =============================================================================*/

#define _GNU_SOURCE        /* ppoll() */
#include "forwarder.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "fwalloc.h"
#include "log.h"
#include "parser.h"

struct forwarder {
    engine_t      *engine;
    int            fd[2];             /* indexed by dir_t: [DIR_IN]=inside, [DIR_OUT]=outside */
    uint8_t       *buf;               /* the one packet buffer, FWD_MAX_PACKET bytes */
    fwd_clock_fn   clock;
    sigset_t       sigmask;           /* used with ppoll when have_sigmask */
    bool           have_sigmask;
    uint64_t       last_expire_ns;
    fwd_counters_t counters;
};

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static bool set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

forwarder_t *fwd_create(engine_t *e, int fd_in, int fd_out)
{
    if (!e || fd_in < 0 || fd_out < 0) return NULL;
    forwarder_t *f = fw_calloc(1, sizeof *f);
    if (!f) return NULL;
    f->buf = fw_calloc(1, FWD_MAX_PACKET + 1);   /* one spare byte detects oversize reads */
    if (!f->buf || !set_nonblocking(fd_in) || !set_nonblocking(fd_out)) {
        free(f->buf);
        free(f);
        return NULL;
    }
    f->engine = e;
    f->fd[DIR_IN] = fd_in;
    f->fd[DIR_OUT] = fd_out;
    f->clock = monotonic_ns;
    f->last_expire_ns = f->clock();
    return f;
}

void fwd_destroy(forwarder_t *f)
{
    if (!f) return;
    free(f->buf);
    free(f);
}

void fwd_set_sigmask(forwarder_t *f, const sigset_t *mask)
{
    f->have_sigmask = mask != NULL;
    if (mask) f->sigmask = *mask;
}

void fwd_set_clock(forwarder_t *f, fwd_clock_fn clock)
{
    f->clock = clock;
    f->last_expire_ns = clock();
}

/*
 * The kernel lowers the TTL when it routes a packet into the tun device and
 * lowers it again when it routes the packet out, so a packet crossing the
 * firewall loses 2. Give 1 back (the firewall is one hop), and fix the IPv4
 * header checksum incrementally (RFC 1624: HC' = ~(~HC + ~m + m')) rather
 * than recomputing it. A TTL of 255 cannot go up and is left alone. The
 * caller has already parsed the packet, so it has a valid 20+ byte header.
 */
static void give_back_one_hop(uint8_t *pkt)
{
    if (pkt[8] == 255) return;
    const uint32_t old_word = ((uint32_t)pkt[8] << 8) | pkt[9];        /* TTL | protocol */
    pkt[8]++;
    const uint32_t new_word = ((uint32_t)pkt[8] << 8) | pkt[9];
    uint32_t sum = (~(((uint32_t)pkt[10] << 8) | pkt[11]) & 0xffffu) +
                   (~old_word & 0xffffu) + new_word;
    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    pkt[10] = (uint8_t)(~sum >> 8);
    pkt[11] = (uint8_t)~sum;
}

/* Decide one packet that arrived on `dir` and forward it if allowed. */
static void handle_packet(forwarder_t *f, dir_t dir, size_t len)
{
    const uint64_t now = f->clock();
    pkt_t pkt;
    /* An IPv4 packet cannot exceed 65535 bytes; reading more means something
     * other than a tun device is on the other end. Never parse or forward it. */
    const parse_result_t pr = len > FWD_MAX_PACKET ? PARSE_MALFORMED
                                                   : parse_packet(f->buf, len, &pkt);
    if (pr != PARSE_OK) {
        engine_parse_failed(f->engine, pr, dir, len, now);
        return;
    }
    if (engine_decide(f->engine, &pkt, dir, now, NULL) != VERDICT_ALLOW)
        return;

    give_back_one_hop(f->buf);
    /* A tun device takes exactly one packet per write(). */
    const dir_t other = dir == DIR_IN ? DIR_OUT : DIR_IN;
    if (write(f->fd[other], f->buf, len) == (ssize_t)len) {
        f->counters.forwarded[dir]++;
    } else {
        f->counters.write_errors++;
        f->counters.last_write_errno = errno;
        /* Nobody saw this packet: do not leave a flow behind that it started. */
        engine_undo_new_flow(f->engine, &pkt, dir, now);
    }
}

/* Read up to FWD_BURST packets from one side. Returns false on a fatal error. */
static bool drain(forwarder_t *f, dir_t dir)
{
    for (int i = 0; i < FWD_BURST; i++) {
        const ssize_t n = read(f->fd[dir], f->buf, FWD_MAX_PACKET + 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return true;
            return false;
        }
        if (n == 0) {              /* a tun device never returns 0: this is end of file */
            errno = EPIPE;
            return false;
        }
        f->counters.rx[dir]++;
        handle_packet(f, dir, (size_t)n);
    }
    return true;
}

int fwd_step(forwarder_t *f, int timeout_ms)
{
    struct pollfd pfd[2] = {
        { .fd = f->fd[DIR_IN],  .events = POLLIN },
        { .fd = f->fd[DIR_OUT], .events = POLLIN },
    };
    int ready;
#ifdef __linux__
    if (f->have_sigmask) {
        const struct timespec ts = { timeout_ms / 1000, (long)(timeout_ms % 1000) * 1000000L };
        ready = ppoll(pfd, 2, timeout_ms < 0 ? NULL : &ts, &f->sigmask);
    } else
#endif
        ready = poll(pfd, 2, timeout_ms);
    if (ready < 0 && errno != EINTR) return -1;

    if (ready > 0) {
        for (int d = 0; d < 2; d++) {
            if (pfd[d].revents & POLLIN) {
                if (!drain(f, (dir_t)d)) return -1;
            } else if (pfd[d].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                errno = pfd[d].revents & POLLNVAL ? EBADF : EIO;
                return -1;
            }
        }
    }

    const uint64_t now = f->clock();
    if (now - f->last_expire_ns >= FWD_EXPIRE_INTERVAL_NS) {
        engine_expire(f->engine, now);
        f->last_expire_ns = now;
    }
    return 0;
}

void fwd_get_counters(const forwarder_t *f, fwd_counters_t *out)
{
    *out = f->counters;
}

void fwd_print_stats(const forwarder_t *f, FILE *out)
{
    engine_stats_t st;
    engine_get_stats(f->engine, &st);
    engine_stats_print(&st, out);
    fprintf(out,
            "io:      rx in=%llu out=%llu forwarded in=%llu out=%llu write-errors=%llu\n",
            (unsigned long long)f->counters.rx[DIR_IN],
            (unsigned long long)f->counters.rx[DIR_OUT],
            (unsigned long long)f->counters.forwarded[DIR_IN],
            (unsigned long long)f->counters.forwarded[DIR_OUT],
            (unsigned long long)f->counters.write_errors);
    fprintf(out, "log:     suppressed=%llu\n", (unsigned long long)fw_log_suppressed());
}

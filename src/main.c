/*
 * main.c - tunwall: single-threaded poll() loop between two TUN devices.
 *
 *   tun-in  (inside side)  --read--> parse -> engine --write--> tun-out
 *   tun-out (outside side) --read--> parse -> engine --write--> tun-in
 *
 * One read() and at most one write() per packet, no per-packet allocation.
 * Run inside the firewall namespace created by scripts/ns_setup.sh:
 *   sudo ip netns exec fw ./tunwall -r config/rules.example.conf -v
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "engine.h"
#include "log.h"
#include "pipeline.h"
#include "tun_io.h"

#define NSEC_PER_SEC   1000000000ull
#define NSEC_PER_MSEC  1000000ull
#define EXPIRE_EVERY   NSEC_PER_SEC
#define MAX_BATCH      64     /* reads per fd per wakeup, so neither starves */

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_dump;

static void on_stop(int sig) { (void)sig; g_stop = 1; }
static void on_dump(int sig) { (void)sig; g_dump = 1; }

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static int install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: poll() returns EINTR promptly */

    sa.sa_handler = on_stop;
    if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
        return -1;
    sa.sa_handler = on_dump;
    if (sigaction(SIGUSR1, &sa, NULL))
        return -1;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -r RULES [-i TUN_IN] [-o TUN_OUT] [-v] [-v]\n"
            "  -r RULES   rule file (see include/rules.h)\n"
            "  -i NAME    inside TUN device  (default tun-in)\n"
            "  -o NAME    outside TUN device (default tun-out)\n"
            "  -v         log flow open/close; -vv also logs every drop\n"
            "  SIGUSR1 prints counters; SIGINT/SIGTERM print them and exit\n",
            prog);
}

/*
 * Read up to MAX_BATCH packets from fds[side] and forward allowed ones to
 * the other side. Returns -1 on a fatal read error.
 */
static int drain(pipeline_t *pl, const int fds[2], int side)
{
    static uint8_t buf[65536];
    const dir_t dir = side == 0 ? DIR_IN : DIR_OUT;
    const int out_fd = fds[1 - side];
    const uint64_t now = now_ns();

    for (int k = 0; k < MAX_BATCH; k++) {
        ssize_t n = read(fds[side], buf, sizeof buf);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (errno == EINTR)
                continue;
            perror("read");
            return -1;
        }
        if (n == 0)
            return 0;

        if (pipeline_handle(pl, buf, (size_t)n, dir, now) != VERDICT_ALLOW)
            continue;

        ssize_t w = write(out_fd, buf, (size_t)n);
        if (w != n)
            pl->st.write_errors++; /* EAGAIN/ENOBUFS: drop, like a full queue */
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *rules_path = NULL;
    const char *tun_in = "tun-in", *tun_out = "tun-out";
    int verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "r:i:o:vh")) != -1) {
        switch (opt) {
        case 'r': rules_path = optarg; break;
        case 'i': tun_in = optarg; break;
        case 'o': tun_out = optarg; break;
        case 'v': verbose++; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }
    if (!rules_path || optind != argc) {
        usage(argv[0]);
        return 2;
    }

    /* Line-buffered so logs are current even when redirected to a file. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    fw_log_set(stdout, verbose >= 2 ? LOG_DEBUG : verbose ? LOG_INFO : LOG_OFF);

    char err[256] = "";
    engine_t *e = engine_create(rules_path, err, sizeof err);
    if (!e) {
        fprintf(stderr, "tunwall: %s\n", err[0] ? err : "cannot create engine");
        return 1;
    }

    int fds[2];
    fds[0] = tun_open(tun_in);
    fds[1] = fds[0] < 0 ? -1 : tun_open(tun_out);
    if (fds[0] < 0 || fds[1] < 0) {
        if (fds[0] >= 0)
            close(fds[0]);
        engine_destroy(e);
        return 1;
    }

    if (install_signals() < 0) {
        perror("sigaction");
        return 1;
    }

    pipeline_t pl;
    memset(&pl, 0, sizeof pl);
    pl.engine = e;
    pl.drop_log = verbose >= 2 ? stdout : NULL;

    printf("tunwall: ready (pid %ld, %s <-> %s, rules %s)\n", (long)getpid(),
           tun_in, tun_out, rules_path);

    int rc = 0;
    uint64_t next_expire = now_ns() + EXPIRE_EVERY;

    while (!g_stop) {
        if (g_dump) {
            g_dump = 0;
            printf("--- tunwall stats ---\n");
            pipeline_stats_print(&pl, stdout);
        }

        uint64_t now = now_ns();
        if (now >= next_expire) {
            engine_expire(e, now);
            next_expire = now + EXPIRE_EVERY;
        }
        int timeout_ms = (int)((next_expire - now + NSEC_PER_MSEC - 1) /
                               NSEC_PER_MSEC);

        struct pollfd pfd[2] = {
            {.fd = fds[0], .events = POLLIN},
            {.fd = fds[1], .events = POLLIN},
        };
        int ready = poll(pfd, 2, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            rc = 1;
            break;
        }

        for (int side = 0; side < 2 && !g_stop; side++) {
            if (pfd[side].revents & (POLLERR | POLLNVAL)) {
                fprintf(stderr, "tunwall: error on %s\n",
                        side == 0 ? tun_in : tun_out);
                rc = 1;
                g_stop = 1;
                break;
            }
            if ((pfd[side].revents & POLLIN) && drain(&pl, fds, side) < 0) {
                rc = 1;
                g_stop = 1;
            }
        }
    }

    printf("--- tunwall final stats ---\n");
    pipeline_stats_print(&pl, stdout);
    close(fds[0]);
    close(fds[1]);
    engine_destroy(e);
    return rc;
}

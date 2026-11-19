/*=============================================================================
 * File Name:   main.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: tunwall, the userspace stateful firewall. Loads the rules file
 *              (refusing to start on any error), opens the two tun devices,
 *              and runs the packet loop until SIGINT or SIGTERM. SIGUSR1
 *              prints the counters; they are also printed on exit. Flow
 *              opens/closes and dropped packets (with the reason) are logged
 *              to stderr, rate-limited so a flood cannot flood the log.
 =============================================================================*/

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "engine.h"
#include "forwarder.h"
#include "log.h"
#include "nat.h"
#include "tun_io.h"

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_dump_stats;

static void on_stop(int sig)  { (void)sig; g_stop = 1; }
static void on_usr1(int sig)  { (void)sig; g_dump_stats = 1; }

static void usage(FILE *out)
{
    fprintf(out,
        "usage: tunwall -r <rules-file> [-i <tun-in>] [-o <tun-out>] [-n <addr>] [-f | -q]\n"
        "  -r FILE   rules file (required); the program refuses to start on a syntax error\n"
        "  -i NAME   tun device facing the trusted network   (default tun-in)\n"
        "  -o NAME   tun device facing the untrusted network (default tun-out)\n"
        "  -n ADDR   source NAT: connections from the inside leave as ADDR, with\n"
        "            ports %d-%d (ADDR must route to the outside tun device)\n"
        "  -f        log flow opens/closes only, not individual dropped packets\n"
        "  -q        log nothing but errors\n"
        "  -d        accepted for old scripts: logging drops is now the default\n"
        "By default every flow open/close and every dropped packet (with its reason)\n"
        "is logged to stderr, limited to %d lines/s (a summary line says how many\n"
        "were suppressed). SIGUSR1 prints the counters; SIGINT/SIGTERM stop it and\n"
        "print them.\n", NAT_PORT_LO_DEFAULT, NAT_PORT_HI_DEFAULT, FW_LOG_LINES_PER_SEC);
}

/* Installed first thing, so no signal can arrive while it is still unhandled
 * (a default SIGUSR1 would kill the process mid-start-up). */
static void install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* no SA_RESTART: waits must be interrupted */
    sa.sa_handler = on_stop;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/*
 * Keep the three signals blocked except inside the forwarder's wait, which
 * unblocks them atomically (ppoll). Otherwise a stop signal landing between
 * "should I stop?" and "wait" would be missed until the wait timed out.
 */
static void block_signals_outside_the_wait(forwarder_t *fwd)
{
    sigset_t block, orig;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block, &orig);
    fwd_set_sigmask(fwd, &orig);
}

int main(int argc, char **argv)
{
    install_handlers();

    const char *rules = NULL, *in_name = "tun-in", *out_name = "tun-out", *nat_arg = NULL;
    log_level_t level = LOG_DEBUG;
    int opt;
    while ((opt = getopt(argc, argv, "r:i:o:n:fqdh")) != -1) {
        switch (opt) {
        case 'r': rules = optarg; break;
        case 'i': in_name = optarg; break;
        case 'o': out_name = optarg; break;
        case 'n': nat_arg = optarg; break;
        case 'f': level = LOG_INFO; break;
        case 'q': level = LOG_OFF; break;
        case 'd': level = LOG_DEBUG; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 2;
        }
    }
    if (!rules || optind != argc) { usage(stderr); return 2; }

    uint32_t nat_ip = 0;
    if (nat_arg) {
        struct in_addr a;
        if (inet_pton(AF_INET, nat_arg, &a) != 1 || a.s_addr == 0) {
            fprintf(stderr, "tunwall: -n needs an IPv4 address, got '%s'\n", nat_arg);
            return 2;
        }
        nat_ip = ntohl(a.s_addr);
    }

    char err[256];
    engine_t *engine = engine_create(rules, err, sizeof err);
    if (!engine) {
        fprintf(stderr, "tunwall: %s\n", err);       /* the message names the file */
        return 1;
    }

    const int fd_in = tun_open(in_name, err, sizeof err);
    if (fd_in < 0) { fprintf(stderr, "tunwall: %s\n", err); engine_destroy(engine); return 1; }
    const int fd_out = tun_open(out_name, err, sizeof err);
    if (fd_out < 0) {
        fprintf(stderr, "tunwall: %s\n", err);
        close(fd_in);
        engine_destroy(engine);
        return 1;
    }

    forwarder_t *fwd = fwd_create(engine, fd_in, fd_out);
    if (!fwd) {
        fprintf(stderr, "tunwall: out of memory\n");
        close(fd_in); close(fd_out);
        engine_destroy(engine);
        return 1;
    }

    nat_t *nat = NULL;
    if (nat_ip) {
        nat = nat_create(nat_ip, NAT_PORT_LO_DEFAULT, NAT_PORT_HI_DEFAULT);
        if (!nat) {
            fprintf(stderr, "tunwall: out of memory\n");
            fwd_destroy(fwd);
            close(fd_in); close(fd_out);
            engine_destroy(engine);
            return 1;
        }
        fwd_set_nat(fwd, nat);
    }

    fw_log_set(stderr, level);
    block_signals_outside_the_wait(fwd);
    if (level != LOG_OFF)
        fprintf(stderr, "tunwall: running (rules %s, inside %s, outside %s%s%s)\n",
                rules, in_name, out_name, nat ? ", source NAT to " : "", nat ? nat_arg : "");

    int rc = 0;
    uint64_t reported_write_errors = 0;
    time_t last_warn = 0;
    while (!g_stop) {
        if (fwd_step(fwd, 1000) < 0) {
            fprintf(stderr, "tunwall: a tun device failed: %s\n", strerror(errno));
            rc = 1;
            break;
        }
        if (g_dump_stats) {
            g_dump_stats = 0;
            fwd_print_stats(fwd, stderr);
            fflush(stderr);
        }
        fwd_counters_t c;
        fwd_get_counters(fwd, &c);
        if (c.write_errors != reported_write_errors && time(NULL) != last_warn) {
            fprintf(stderr, "tunwall: %llu allowed packets could not be written (%s)\n",
                    (unsigned long long)c.write_errors, strerror(c.last_write_errno));
            reported_write_errors = c.write_errors;
            last_warn = time(NULL);
        }
    }

    fwd_print_stats(fwd, stderr);
    fwd_destroy(fwd);
    nat_destroy(nat);
    close(fd_in);
    close(fd_out);
    engine_destroy(engine);
    return rc;
}

/*=============================================================================
 * File Name:   main.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: tunwall, the userspace stateful firewall. Loads the rules file
 *              (refusing to start on any error), opens the two tun devices,
 *              and runs the packet loop until SIGINT or SIGTERM. SIGUSR1
 *              prints the counters (they are also printed on exit), and
 *              SIGHUP reloads the rules file without a restart. An outside
 *              host that probes too many ports is blocked for a while (-s).
 *              Flow opens/closes and dropped packets (with the reason) are
 *              logged to stderr, rate-limited so a flood cannot flood the log.
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
static volatile sig_atomic_t g_reload;

static void on_stop(int sig)  { (void)sig; g_stop = 1; }
static void on_usr1(int sig)  { (void)sig; g_dump_stats = 1; }
static void on_hup(int sig)   { (void)sig; g_reload = 1; }

static void usage(FILE *out)
{
    fprintf(out,
        "usage: tunwall -r <rules-file> [-i <tun-in>] [-o <tun-out>] [-n <addr>] [-s <scan>] [-f | -q]\n"
        "  -r FILE   rules file (required); the program refuses to start on a syntax error\n"
        "  -i NAME   tun device facing the trusted network   (default tun-in)\n"
        "  -o NAME   tun device facing the untrusted network (default tun-out)\n"
        "  -n ADDR   source NAT: connections from the inside leave as ADDR, with\n"
        "            ports %d-%d (ADDR must route to the outside tun device);\n"
        "            also turns on the rules file's 'forward' lines (port forwarding)\n"
        "  -s P[,W[,B]]  port-scan detection: an outside host dropped on P distinct\n"
        "            ports within W s is blocked for B s (default %d,%d,%d; -s 0 = off)\n"
        "  -f        log flow opens/closes only, not individual dropped packets\n"
        "  -q        log nothing but errors\n"
        "  -d        accepted for old scripts: logging drops is now the default\n"
        "By default every flow open/close and every dropped packet (with its reason)\n"
        "is logged to stderr, limited to %d lines/s (a summary line says how many\n"
        "were suppressed). SIGUSR1 prints the counters; SIGHUP reloads the rules file\n"
        "(a bad file keeps the old rules); SIGINT/SIGTERM stop it and print them.\n", NAT_PORT_LO_DEFAULT, NAT_PORT_HI_DEFAULT,
        SCAN_DEFAULT_PORTS, SCAN_DEFAULT_WINDOW_S, SCAN_DEFAULT_BLOCK_S, FW_LOG_LINES_PER_SEC);
}

/* One decimal field of -s in [lo, hi], ending at ',' or the end. */
static bool parse_field(const char **sp, unsigned long lo, unsigned long hi,
                        unsigned long *out)
{
    char *end;
    errno = 0;
    const unsigned long v = strtoul(*sp, &end, 10);
    if (end == *sp || errno || v < lo || v > hi || (*end && *end != ','))
        return false;
    *out = v;
    *sp = *end ? end + 1 : end;
    return true;
}

/* -s "P[,W[,B]]" or "0" (off). Fields left out keep their defaults. */
static bool parse_scan(const char *arg, scan_cfg_t *cfg)
{
    if (strcmp(arg, "0") == 0) { cfg->ports = 0; return true; }
    unsigned long v;
    const char *s = arg;
    if (!parse_field(&s, 2, SCAN_MAX_PORTS, &v)) return false;
    cfg->ports = (uint16_t)v;
    if (!*s) return true;
    if (!parse_field(&s, 1, 3600, &v)) return false;
    cfg->window_s = (uint32_t)v;
    if (!*s) return true;
    if (!parse_field(&s, 1, 86400, &v) || *s) return false;
    cfg->block_s = (uint32_t)v;
    return true;
}

/*
 * Can these rules' `forward` lines be used? They need source NAT (-n), and
 * their external ports must stay out of its port range. False with err
 * (naming the file) if not.
 */
static bool forwards_ok(const nat_t *nat, const rules_t *r, const char *path,
                        char *err, size_t errlen)
{
    if (r->nfwd == 0) return true;
    if (!nat) {
        snprintf(err, errlen, "%s: line %d: 'forward' needs source NAT (-n ADDR)",
                 path, r->fwd[0].line);
        return false;
    }
    char msg[200];
    if (!nat_check_forwards(nat, r->fwd, r->nfwd, msg, sizeof msg)) {
        snprintf(err, errlen, "%s: %s", path, msg);
        return false;
    }
    return true;
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
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/*
 * Keep the four signals blocked except inside the forwarder's wait, which
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
    sigaddset(&block, SIGHUP);
    sigprocmask(SIG_BLOCK, &block, &orig);
    fwd_set_sigmask(fwd, &orig);
}

int main(int argc, char **argv)
{
    install_handlers();

    const char *rules = NULL, *in_name = "tun-in", *out_name = "tun-out", *nat_arg = NULL;
    log_level_t level = LOG_DEBUG;
    scan_cfg_t scan = { SCAN_DEFAULT_PORTS, SCAN_DEFAULT_WINDOW_S, SCAN_DEFAULT_BLOCK_S };
    int opt;
    while ((opt = getopt(argc, argv, "r:i:o:n:s:fqdh")) != -1) {
        switch (opt) {
        case 'r': rules = optarg; break;
        case 'i': in_name = optarg; break;
        case 'o': out_name = optarg; break;
        case 'n': nat_arg = optarg; break;
        case 's':
            if (!parse_scan(optarg, &scan)) {
                fprintf(stderr, "tunwall: -s needs PORTS[,WINDOW_S[,BLOCK_S]] with PORTS "
                        "2-%d, WINDOW_S 1-3600, BLOCK_S 1-86400, or 0 for off; got '%s'\n",
                        SCAN_MAX_PORTS, optarg);
                return 2;
            }
            break;
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
    if (!engine_set_scan(engine, &scan)) {
        fprintf(stderr, "tunwall: out of memory\n");
        engine_destroy(engine);
        return 1;
    }

    /* Source NAT and the rules' port forwards, checked before touching the
     * tun devices so a bad configuration is refused the same way anywhere. */
    nat_t *nat = NULL;
    if (nat_ip) {
        nat = nat_create(nat_ip, NAT_PORT_LO_DEFAULT, NAT_PORT_HI_DEFAULT);
        if (!nat) { fprintf(stderr, "tunwall: out of memory\n"); engine_destroy(engine); return 1; }
    }
    const rules_t *loaded = engine_rules(engine);
    if (!forwards_ok(nat, loaded, rules, err, sizeof err)) {
        fprintf(stderr, "tunwall: %s\n", err);
        nat_destroy(nat);
        engine_destroy(engine);
        return 1;
    }
    if (nat) nat_set_forwards(nat, loaded->fwd, loaded->nfwd);

    const int fd_in = tun_open(in_name, err, sizeof err);
    if (fd_in < 0) {
        fprintf(stderr, "tunwall: %s\n", err);
        nat_destroy(nat);
        engine_destroy(engine);
        return 1;
    }
    const int fd_out = tun_open(out_name, err, sizeof err);
    if (fd_out < 0) {
        fprintf(stderr, "tunwall: %s\n", err);
        close(fd_in);
        nat_destroy(nat);
        engine_destroy(engine);
        return 1;
    }

    forwarder_t *fwd = fwd_create(engine, fd_in, fd_out);
    if (!fwd) {
        fprintf(stderr, "tunwall: out of memory\n");
        close(fd_in); close(fd_out);
        nat_destroy(nat);
        engine_destroy(engine);
        return 1;
    }

    if (nat) fwd_set_nat(fwd, nat);

    fw_log_set(stderr, level);
    block_signals_outside_the_wait(fwd);
    if (level != LOG_OFF)
        fprintf(stderr, "tunwall: running (rules %s, inside %s, outside %s%s%s)\n",
                rules, in_name, out_name, nat ? ", source NAT to " : "", nat ? nat_arg : "");
    if (level != LOG_OFF) {
        if (scan.ports)
            fprintf(stderr, "tunwall: scan detection on: %u ports in %u s blocks the host for %u s\n",
                    (unsigned)scan.ports, (unsigned)scan.window_s, (unsigned)scan.block_s);
        else
            fprintf(stderr, "tunwall: scan detection off\n");
    }

    int rc = 0;
    uint64_t reported_write_errors = 0;
    time_t last_warn = 0;
    while (!g_stop) {
        if (fwd_step(fwd, 1000) < 0) {
            fprintf(stderr, "tunwall: a tun device failed: %s\n", strerror(errno));
            rc = 1;
            break;
        }
        if (g_reload) {
            /* New rules (and port forwards) apply to new connections;
             * existing flows keep going. Any error leaves the running rules
             * and forwards exactly as they were. */
            g_reload = 0;
            rules_t *r = engine_load_rules(rules, err, sizeof err);
            if (r && !forwards_ok(nat, r, rules, err, sizeof err)) {
                rules_free(r);
                r = NULL;
            }
            if (r && engine_replace_rules(engine, r)) {
                const rules_t *now = engine_rules(engine);
                if (nat) nat_set_forwards(nat, now->fwd, now->nfwd);
                fprintf(stderr, "tunwall: rules reloaded from %s\n", rules);
            } else {
                fprintf(stderr, "tunwall: reload failed, keeping the old rules: %s\n", err);
            }
            fflush(stderr);
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

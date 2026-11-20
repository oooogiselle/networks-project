/*=============================================================================
 * File Name:   test_reload.c
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Tests for replacing the rules while the firewall runs
 *              (tunwall reloads its rules file on SIGHUP): new rules govern
 *              new connections, existing flows keep going, and a bad file
 *              (syntax error, no inside network, missing) leaves the old
 *              rules exactly as they were.
 =============================================================================*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "engine.h"
#include "rules.h"
#include "testutil.h"

#define CLIENT IP(10, 0, 1, 2)
#define SERVER IP(10, 0, 2, 2)

static const char *WEB_ONLY =
    "inside 10.0.1.0/24\n"
    "allow out tcp 10.0.1.0/24 any 80\n";

static const char *SSH_ONLY =
    "inside 10.0.1.0/24\n"
    "allow out tcp 10.0.1.0/24 any 22\n";

static engine_t *mk(const char *text)
{
    char err[128];
    engine_t *e = engine_create_with_rules(rules_parse_string(text, err, sizeof err));
    CHECK(e != NULL);
    return e;
}

static verdict_t syn_to(engine_t *e, uint16_t sport, uint16_t dport, uint64_t now)
{
    const pkt_t p = mk_tcp(CLIENT, sport, SERVER, dport, TCP_SYN);
    return engine_decide(e, &p, DIR_IN, now, NULL);
}

/* Write text to a fresh temporary file; returns 0 and fills path, or -1. */
static int write_tmp(char *path, size_t cap, const char *text)
{
    const char *dir = getenv("TMPDIR");
    snprintf(path, cap, "%s/fw_reload_test_XXXXXX", dir && *dir ? dir : "/tmp");
    const int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return -1;
    const ssize_t n = write(fd, text, strlen(text));
    close(fd);
    CHECK(n == (ssize_t)strlen(text));
    return 0;
}

static void test_new_rules_govern_new_connections(void)
{
    engine_t *e = mk(WEB_ONLY);
    if (!e) return;
    CHECK(syn_to(e, 40000, 80, SEC) == VERDICT_ALLOW);
    CHECK(syn_to(e, 40001, 22, SEC) == VERDICT_DROP);

    char err[128];
    CHECK(engine_replace_rules(e, rules_parse_string(SSH_ONLY, err, sizeof err)));
    CHECK(syn_to(e, 40002, 22, 2 * SEC) == VERDICT_ALLOW);
    CHECK(syn_to(e, 40003, 80, 2 * SEC) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_existing_flows_survive_a_reload(void)
{
    /* Like Linux conntrack: a connection allowed under the old rules keeps
     * working after they change, in both directions. */
    engine_t *e = mk(WEB_ONLY);
    if (!e) return;
    pkt_t p = mk_tcp(CLIENT, 40000, SERVER, 80, TCP_SYN);
    CHECK(engine_decide(e, &p, DIR_IN, SEC, NULL) == VERDICT_ALLOW);
    p = mk_tcp(SERVER, 80, CLIENT, 40000, TCP_SYN | TCP_ACK);
    CHECK(engine_decide(e, &p, DIR_OUT, SEC, NULL) == VERDICT_ALLOW);

    char err[128];
    CHECK(engine_replace_rules(e, rules_parse_string(SSH_ONLY, err, sizeof err)));

    p = mk_tcp(CLIENT, 40000, SERVER, 80, TCP_ACK);
    CHECK(engine_decide(e, &p, DIR_IN, 2 * SEC, NULL) == VERDICT_ALLOW);
    p = mk_tcp(SERVER, 80, CLIENT, 40000, TCP_ACK | TCP_PSH);
    CHECK(engine_decide(e, &p, DIR_OUT, 2 * SEC, NULL) == VERDICT_ALLOW);
    engine_stats_t st;
    engine_get_stats(e, &st);
    CHECK(st.flows_active == 1);
    engine_destroy(e);
}

static void test_the_inside_network_can_change(void)
{
    /* Anti-spoofing follows the new inside network at once. */
    engine_t *e = mk(WEB_ONLY);
    if (!e) return;
    const pkt_t from_b = mk_tcp(IP(10, 0, 9, 2), 40000, SERVER, 80, TCP_SYN);
    drop_reason_t why = DROP_NONE;
    CHECK(engine_decide(e, &from_b, DIR_IN, SEC, &why) == VERDICT_DROP);
    CHECK(why == DROP_BAD_SRC);

    char err[128];
    CHECK(engine_replace_rules(e, rules_parse_string(
        "inside 10.0.9.0/24\nallow out tcp 10.0.9.0/24 any 80\n", err, sizeof err)));
    CHECK(engine_decide(e, &from_b, DIR_IN, SEC, NULL) == VERDICT_ALLOW);
    CHECK(syn_to(e, 40001, 80, SEC) == VERDICT_DROP);     /* 10.0.1.2 is not inside now */
    engine_destroy(e);
}

static void test_bad_replacements_keep_the_old_rules(void)
{
    engine_t *e = mk(WEB_ONLY);
    if (!e) return;
    char err[128];
    CHECK(!engine_replace_rules(e, NULL));
    CHECK(!engine_replace_rules(e, rules_parse_string(
        "allow out tcp 10.0.1.0/24 any 22\n", err, sizeof err)));   /* no inside: freed (ASan) */
    CHECK(syn_to(e, 40000, 80, SEC) == VERDICT_ALLOW);
    CHECK(syn_to(e, 40001, 22, SEC) == VERDICT_DROP);
    engine_destroy(e);
}

static void test_reload_from_a_file(void)
{
    engine_t *e = mk(WEB_ONLY);
    if (!e) return;
    char path[512], err[256];

    /* a good file switches the rules */
    if (write_tmp(path, sizeof path, SSH_ONLY) != 0) { engine_destroy(e); return; }
    CHECK(engine_reload_rules(e, path, err, sizeof err));
    CHECK(syn_to(e, 40000, 22, SEC) == VERDICT_ALLOW);
    CHECK(syn_to(e, 40001, 80, SEC) == VERDICT_DROP);
    unlink(path);

    /* a syntax error names the file and the line, and changes nothing */
    if (write_tmp(path, sizeof path, "inside 10.0.1.0/24\nallow out tcp 10.0.1.0/24 any 80\nallow bogus\n") != 0) {
        engine_destroy(e);
        return;
    }
    err[0] = '\0';
    CHECK(!engine_reload_rules(e, path, err, sizeof err));
    CHECK(strncmp(err, path, strlen(path)) == 0);
    CHECK(strstr(err, ": line 3:") != NULL);
    CHECK(syn_to(e, 40002, 22, SEC) == VERDICT_ALLOW);    /* still the SSH-only rules */
    CHECK(syn_to(e, 40003, 80, SEC) == VERDICT_DROP);
    unlink(path);

    /* no inside network: refused, and says why */
    if (write_tmp(path, sizeof path, "allow out tcp 10.0.1.0/24 any 80\n") != 0) {
        engine_destroy(e);
        return;
    }
    err[0] = '\0';
    CHECK(!engine_reload_rules(e, path, err, sizeof err));
    CHECK(strstr(err, "inside") != NULL);
    CHECK(syn_to(e, 40004, 22, SEC) == VERDICT_ALLOW);
    unlink(path);

    /* the file is gone (e.g. mid-edit): refused, nothing changes */
    err[0] = '\0';
    CHECK(!engine_reload_rules(e, path, err, sizeof err));
    CHECK(strstr(err, "cannot open") != NULL);
    CHECK(syn_to(e, 40005, 22, SEC) == VERDICT_ALLOW);
    engine_destroy(e);
}

int main(void)
{
    RUN(test_new_rules_govern_new_connections);
    RUN(test_existing_flows_survive_a_reload);
    RUN(test_the_inside_network_can_change);
    RUN(test_bad_replacements_keep_the_old_rules);
    RUN(test_reload_from_a_file);
    TEST_DONE();
}

/*=============================================================================
 * File Name:   test_alloc_fail.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Out-of-memory tests. For each constructor, fail the 1st, 2nd, 3rd...
 *              allocation in turn and check it returns NULL cleanly. Leaks are
 *              caught by running this under `make asan` on Linux (LeakSanitizer).
 =============================================================================*/

#include <stdlib.h>
#include <unistd.h>

#include "engine.h"
#include "flowtable.h"
#include "fwalloc.h"
#include "rules.h"
#include "testutil.h"

#define MAX_SWEEP 64     /* far more allocations than any call here makes */

/* Longest realistic policy, to force the rule array to grow (starts at 16). */
static char *many_rules(int n)
{
    static char text[8192];
    text[0] = '\0';
    char line[96];
    for (int i = 0; i < n; i++) {
        snprintf(line, sizeof line, "allow tcp 10.0.1.0/24 any %d\n", 1000 + i);
        strcat(text, line);
    }
    return text;
}

static void test_flowtable_create_survives_each_failure(void)
{
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        fw_alloc_fail_nth(k);
        flowtable_t *ft = ft_create(64, 10);
        if (!fw_alloc_failure_fired()) {           /* ran out of allocations */
            CHECK(ft != NULL);
            ft_destroy(ft);
            break;
        }
        failures++;
        CHECK(ft == NULL);
    }
    CHECK(failures == 4);              /* table, buckets, pool, hash key */
    fw_alloc_fail_nth(0);

    /* a zero-capacity table has no pool, so one allocation fewer */
    fw_alloc_fail_nth(4);
    flowtable_t *z = ft_create(8, 0);
    CHECK(z != NULL && !fw_alloc_failure_fired());
    ft_destroy(z);
    fw_alloc_fail_nth(0);
}

static void test_rules_parse_survives_each_failure(void)
{
    const char *text = many_rules(40);            /* > 16: array must grow */
    char err[128];
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        strcpy(err, "UNSET");
        fw_alloc_fail_nth(k);
        rules_t *r = rules_parse_string(text, err, sizeof err);
        if (!fw_alloc_failure_fired()) {
            CHECK(r != NULL && r->n == 40);
            rules_free(r);
            break;
        }
        failures++;
        CHECK(r == NULL);
        CHECK(strstr(err, "out of memory") != NULL);     /* never left untouched */
    }
    CHECK(failures >= 4);     /* rules_t, copy, and at least two array growths */
    fw_alloc_fail_nth(0);

    /* with injection off everything is normal again */
    rules_t *r = rules_parse_string(text, err, sizeof err);
    CHECK(r && r->n == 40);
    rules_free(r);
}

/* Write a rules file bigger than one read chunk (4096 bytes). */
static char *big_rules_file(void)
{
    static char path[512];
    const char *dir = getenv("TMPDIR");
    snprintf(path, sizeof path, "%s/fw_alloc_test_XXXXXX", dir && *dir ? dir : "/tmp");
    int fd = mkstemp(path);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "w");
    for (int i = 0; i < 150; i++)
        fprintf(f, "# padding comment line number %03d to push the file past one chunk\n", i);
    fprintf(f, "allow tcp 10.0.1.0/24 any 80\n");
    fclose(f);
    return path;
}

static void test_rules_load_file_survives_each_failure(void)
{
    char *path = big_rules_file();
    CHECK(path != NULL);
    if (!path) return;
    char err[128];
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        strcpy(err, "UNSET");
        fw_alloc_fail_nth(k);
        rules_t *r = rules_load_file(path, err, sizeof err);
        if (!fw_alloc_failure_fired()) {
            CHECK(r != NULL && r->n == 1);
            rules_free(r);
            break;
        }
        failures++;
        CHECK(r == NULL);
        CHECK(strstr(err, "out of memory") != NULL);
    }
    CHECK(failures >= 4);          /* two buffer growths + parse allocations */
    fw_alloc_fail_nth(0);

    /* an empty file takes the calloc(1,1) path */
    FILE *f = fopen(path, "w");
    fclose(f);
    strcpy(err, "UNSET");
    fw_alloc_fail_nth(1);
    rules_t *r = rules_load_file(path, err, sizeof err);
    CHECK(fw_alloc_failure_fired() && r == NULL);
    CHECK(strstr(err, "out of memory") != NULL);
    fw_alloc_fail_nth(0);
    r = rules_load_file(path, err, sizeof err);
    CHECK(r && r->n == 0);
    rules_free(r);
    unlink(path);
}

static void test_engine_create_survives_each_failure(void)
{
    char err[128];
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        rules_t *rules = rules_parse_string("inside 10.0.0.0/8\nallow udp any any\n", err, sizeof err);
        CHECK(rules != NULL);
        fw_alloc_fail_nth(k);
        /* the engine owns the rules even when it fails: no leak, no double free */
        engine_t *e = engine_create_with_rules_sized(rules, 16);
        if (!fw_alloc_failure_fired()) {
            CHECK(e != NULL);
            engine_destroy(e);
            break;
        }
        failures++;
        CHECK(e == NULL);
    }
    CHECK(failures == 5);       /* engine, then the flow table's four */
    fw_alloc_fail_nth(0);

    CHECK(engine_create_with_rules(NULL) == NULL);
}

static void test_default_engine_with_limits_survives_each_failure(void)
{
    /* engine_create_with_rules() also allocates the per-source counter table */
    char err[128];
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        rules_t *rules = rules_parse_string("inside 10.0.0.0/8\nallow udp any any\n", err, sizeof err);
        CHECK(rules != NULL);
        fw_alloc_fail_nth(k);
        engine_t *e = engine_create_with_rules(rules);
        if (!fw_alloc_failure_fired()) {
            CHECK(e != NULL);
            engine_destroy(e);
            break;
        }
        failures++;
        CHECK(e == NULL);               /* and nothing leaks: run under make asan */
    }
    fw_alloc_fail_nth(0);
    CHECK(failures == 6);               /* engine, the flow table's four, the per-source counters */
}

static void test_engine_create_from_file_survives_each_failure(void)
{
    char err[128];
    int failures = 0;
    for (long k = 1; k < MAX_SWEEP; k++) {
        strcpy(err, "UNSET");
        fw_alloc_fail_nth(k);
        engine_t *e = engine_create("config/rules.example.conf", err, sizeof err);
        if (!fw_alloc_failure_fired()) {
            CHECK(e != NULL);
            engine_destroy(e);
            break;
        }
        failures++;
        CHECK(e == NULL);
        CHECK(strstr(err, "out of memory") != NULL);
    }
    CHECK(failures >= 8);
    fw_alloc_fail_nth(0);
}

static void test_wrappers_behave_like_the_originals(void)
{
    fw_alloc_fail_nth(0);
    char *p = fw_calloc(4, 4);
    CHECK(p != NULL && p[15] == 0);
    p = fw_realloc(p, 64);
    CHECK(p != NULL);
    free(p);
    char *s = fw_strdup("firewall");
    CHECK(s && strcmp(s, "firewall") == 0);
    free(s);

    fw_alloc_fail_nth(2);                  /* only the 2nd allocation fails */
    void *a = fw_calloc(1, 8);
    void *b = fw_calloc(1, 8);
    void *c = fw_calloc(1, 8);
    CHECK(a && !b && c && fw_alloc_failure_fired());
    free(a); free(c);
    fw_alloc_fail_nth(1);
    CHECK(fw_strdup("x") == NULL);
    fw_alloc_fail_nth(1);
    CHECK(fw_realloc(NULL, 8) == NULL);
    fw_alloc_fail_nth(0);
    CHECK(!fw_alloc_failure_fired());
}

int main(void)
{
    RUN(test_flowtable_create_survives_each_failure);
    RUN(test_rules_parse_survives_each_failure);
    RUN(test_rules_load_file_survives_each_failure);
    RUN(test_engine_create_survives_each_failure);
    RUN(test_default_engine_with_limits_survives_each_failure);
    RUN(test_engine_create_from_file_survives_each_failure);
    RUN(test_wrappers_behave_like_the_originals);
    TEST_DONE();
}

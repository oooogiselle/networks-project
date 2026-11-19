/* test_pipeline.c - raw bytes through parser + engine. */
#include <string.h>

#include "parser.h"
#include "pipeline.h"
#include "pktbuild.h"
#include "rules.h"
#include "testutil.h"

#define CLIENT_A IP4(10, 0, 1, 2)
#define SERVER   IP4(10, 0, 2, 2)

static pipeline_t make_pipeline(void)
{
    char err[128];
    rules_t *r = rules_parse_string(
        "allow out tcp from 10.0.1.0/24 to any port 80\n", err, sizeof err);
    CHECK(r != NULL);
    pipeline_t pl;
    memset(&pl, 0, sizeof pl);
    pl.engine = engine_create_with_rules(r);
    CHECK(pl.engine != NULL);
    return pl;
}

static uint64_t engine_total(const pipeline_t *pl)
{
    engine_stats_t s;
    engine_get_stats(pl->engine, &s);
    return s.pkts_total;
}

static void valid_packets_reach_engine(void)
{
    pipeline_t pl = make_pipeline();
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 80,
                      TCP_SYN, NULL, 0);
    CHECK(pipeline_handle(&pl, b, n, DIR_IN, SEC) == VERDICT_ALLOW);
    n = pb_tcp(b, sizeof b, NULL, SERVER, 80, CLIENT_A, 50000,
               TCP_SYN | TCP_ACK, NULL, 0);
    CHECK(pipeline_handle(&pl, b, n, DIR_OUT, SEC + 1) == VERDICT_ALLOW);

    /* Parses fine, but no rule allows it: the engine drops it. */
    n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50001, SERVER, 22, TCP_SYN,
               NULL, 0);
    CHECK(pipeline_handle(&pl, b, n, DIR_IN, SEC + 2) == VERDICT_DROP);

    CHECK(engine_total(&pl) == 3);
    for (int i = 0; i < PARSE_RESULT_COUNT; i++)
        CHECK(pl.st.parse_drops[i] == 0);
    engine_destroy(pl.engine);
}

static void parse_failures_never_reach_engine(void)
{
    pipeline_t pl = make_pipeline();
    uint8_t b[128];
    size_t n = pb_tcp(b, sizeof b, NULL, CLIENT_A, 50000, SERVER, 80,
                      TCP_SYN, NULL, 0);

    /* Truncated. */
    CHECK(pipeline_handle(&pl, b, n - 1, DIR_IN, SEC) == VERDICT_DROP);
    /* Bad TCP checksum. */
    b[n - 1] ^= 0x01;
    CHECK(pipeline_handle(&pl, b, n, DIR_IN, SEC) == VERDICT_DROP);
    b[n - 1] ^= 0x01;
    /* Fragment. */
    pb_wr16(b + 6, 0x2000);
    pb_fix_csums(b, n);
    CHECK(pipeline_handle(&pl, b, n, DIR_IN, SEC) == VERDICT_DROP);
    /* IPv6. */
    uint8_t v6[40] = {0x60};
    CHECK(pipeline_handle(&pl, v6, sizeof v6, DIR_OUT, SEC) == VERDICT_DROP);

    CHECK(pl.st.parse_drops[PARSE_MALFORMED] == 1);
    CHECK(pl.st.parse_drops[PARSE_BAD_CSUM] == 1);
    CHECK(pl.st.parse_drops[PARSE_FRAGMENT] == 1);
    CHECK(pl.st.parse_drops[PARSE_UNSUPPORTED] == 1);
    CHECK(pl.st.parse_drops[PARSE_OK] == 0);
    CHECK(engine_total(&pl) == 0);
    engine_destroy(pl.engine);
}

static void drop_log_and_stats_output(void)
{
    pipeline_t pl = make_pipeline();
    char logbuf[512] = {0}, statbuf[1024] = {0};
    FILE *log = fmemopen(logbuf, sizeof logbuf, "w");
    FILE *stats = fmemopen(statbuf, sizeof statbuf, "w");
    CHECK(log && stats);
    if (!log || !stats)
        return;
    pl.drop_log = log;

    uint8_t junk[3] = {0x45, 0, 0};
    pipeline_handle(&pl, junk, sizeof junk, DIR_OUT, 2 * SEC);
    pl.st.write_errors = 7;
    fflush(log);
    pipeline_stats_print(&pl, stats);
    fclose(log);
    fclose(stats);

    CHECK(strstr(logbuf, "DROP len=3 on=out why=malformed") != NULL);
    CHECK(strstr(statbuf, "packets:") != NULL);
    CHECK(strstr(statbuf, "drop[malformed]=1") != NULL);
    CHECK(strstr(statbuf, "write_errors=7") != NULL);
    engine_destroy(pl.engine);
}

int main(void)
{
    RUN(valid_packets_reach_engine);
    RUN(parse_failures_never_reach_engine);
    RUN(drop_log_and_stats_output);
    TEST_DONE();
}

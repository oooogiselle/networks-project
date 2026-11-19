/* pipeline.c - raw packet -> parse -> engine verdict. See pipeline.h. */
#include "pipeline.h"

#include <inttypes.h>

#include "log.h"

verdict_t pipeline_handle(pipeline_t *pl, const uint8_t *buf, size_t len,
                          dir_t dir, uint64_t now_ns)
{
    pkt_t p;
    parse_result_t r = parse_packet(buf, len, &p);
    if (r != PARSE_OK) {
        pl->st.parse_drops[r]++;
        if (pl->drop_log)
            fprintf(pl->drop_log, "[%10.6f] DROP len=%zu on=%s why=%s\n",
                    now_ns / 1e9, len, dir == DIR_IN ? "in" : "out",
                    parse_result_str(r));
        return VERDICT_DROP;
    }
    return engine_decide(pl->engine, &p, dir, now_ns, NULL);
}

void pipeline_stats_print(const pipeline_t *pl, FILE *out)
{
    engine_stats_t es;
    engine_get_stats(pl->engine, &es);
    engine_stats_print(&es, out);

    for (int i = 1; i < PARSE_RESULT_COUNT; i++)
        if (pl->st.parse_drops[i])
            fprintf(out, "drop[%s]=%" PRIu64 "\n",
                    parse_result_str((parse_result_t)i), pl->st.parse_drops[i]);
    if (pl->st.write_errors)
        fprintf(out, "write_errors=%" PRIu64 "\n", pl->st.write_errors);
    fflush(out);
}

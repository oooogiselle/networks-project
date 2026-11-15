/* test_common.c - sanity checks on the shared interface headers. */
#include <string.h>

#include "../../src/common.h"
#include "../../src/fw.h"
#include "../../src/packet.h"
#include "suites.h"
#include "test.h"

TEST(default_verdict_is_drop)
{
    enum verdict v = 0;
    CHECK_EQ(v, V_DROP);
}

TEST(every_reason_has_a_name)
{
    for (int r = 0; r < R__COUNT; r++) {
        const char *s = reason_str((enum reason)r);
        CHECK(s != NULL);
        CHECK(strcmp(s, "unknown") != 0);
    }
    CHECK(strcmp(reason_str(R__COUNT), "unknown") == 0);
}

TEST(stats_has_slot_per_reason)
{
    struct fw_stats s;
    CHECK_EQ(sizeof s.dropped / sizeof s.dropped[0], R__COUNT);
}

void suite_common(void)
{
    RUN(default_verdict_is_drop);
    RUN(every_reason_has_a_name);
    RUN(stats_has_slot_per_reason);
}

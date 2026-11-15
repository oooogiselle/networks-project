/*
 * test.h - minimal dependency-free unit test harness.
 *
 *   TEST(name) { CHECK(x == 1); CHECK_EQ(a, b); }
 *
 * Register each test in the suite's run function with RUN(name).
 * A failed CHECK records the failure and continues the test.
 */
#ifndef TUNWALL_TEST_H
#define TUNWALL_TEST_H

#include <stdio.h>

extern int t_failures;
extern int t_checks;
extern int t_tests;

#define TEST(name) static void name(void)

#define RUN(name)                                   \
    do {                                            \
        int before_ = t_failures;                   \
        t_tests++;                                  \
        name();                                     \
        printf("  %s %s\n",                         \
               t_failures == before_ ? "ok  " : "FAIL", #name); \
    } while (0)

#define CHECK(cond)                                                    \
    do {                                                               \
        t_checks++;                                                    \
        if (!(cond)) {                                                 \
            t_failures++;                                              \
            fprintf(stderr, "    %s:%d: CHECK(%s) failed\n",           \
                    __FILE__, __LINE__, #cond);                        \
        }                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                 \
    do {                                                               \
        long long a_ = (long long)(a), b_ = (long long)(b);            \
        t_checks++;                                                    \
        if (a_ != b_) {                                                \
            t_failures++;                                              \
            fprintf(stderr, "    %s:%d: CHECK_EQ(%s, %s): %lld != %lld\n", \
                    __FILE__, __LINE__, #a, #b, a_, b_);               \
        }                                                              \
    } while (0)

#endif /* TUNWALL_TEST_H */

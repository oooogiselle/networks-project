/*
 * test_main.c - runs every unit test suite.
 *
 * To add a suite: write tests/unit/test_<name>.c exposing
 * `void suite_<name>(void)`, declare it in suites.h, and call it from main().
 * The Makefile picks up every .c file in tests/unit automatically.
 */
#include <stdio.h>

#include "suites.h"
#include "test.h"

int t_failures = 0;
int t_checks = 0;
int t_tests = 0;

int main(void)
{
    printf("common\n");
    suite_common();
    printf("packet\n");
    suite_packet();

    printf("\n%d tests, %d checks, %d failures\n", t_tests, t_checks,
           t_failures);
    return t_failures ? 1 : 0;
}

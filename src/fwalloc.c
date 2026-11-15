/*=============================================================================
 * File Name:   fwalloc.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Allocation wrappers with a test hook for injecting a single allocation
 *              failure (see fwalloc.h).
 =============================================================================*/

#include "fwalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long g_countdown;      /* > 0: allocations left until the failing one */
static bool g_fired;

/* True if this allocation is the one a test asked to fail. */
static bool inject_failure(void)
{
    if (g_countdown > 0 && --g_countdown == 0) {
        g_fired = true;
        return true;
    }
    return false;
}

void fw_alloc_fail_nth(long n)
{
    g_countdown = n > 0 ? n : 0;
    g_fired = false;
}

bool fw_alloc_failure_fired(void) { return g_fired; }

bool fw_random(void *buf, size_t n)
{
    if (inject_failure()) return false;
    FILE *f = fopen("/dev/urandom", "rb");
    const bool ok = f != NULL && fread(buf, 1, n, f) == n;
    if (f) fclose(f);
    return ok;
}

void *fw_calloc(size_t n, size_t size)
{
    return inject_failure() ? NULL : calloc(n, size);
}

void *fw_realloc(void *p, size_t size)
{
    return inject_failure() ? NULL : realloc(p, size);
}

char *fw_strdup(const char *s)
{
    if (inject_failure()) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    return d ? memcpy(d, s, n) : NULL;
}

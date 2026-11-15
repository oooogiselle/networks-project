/*=============================================================================
 * File Name:   fwalloc.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Allocation wrappers used for the startup-time allocations (flow pool, rules,
 *              engine). They behave exactly like calloc/realloc/strdup, but let
 *              a test make a chosen allocation fail so the out-of-memory paths
 *              can be exercised. Nothing on the per-packet path allocates.
 =============================================================================*/

#ifndef FW_ALLOC_H
#define FW_ALLOC_H

#include <stdbool.h>
#include <stddef.h>

void *fw_calloc(size_t n, size_t size);
void *fw_realloc(void *p, size_t size);
char *fw_strdup(const char *s);

/*
 * Testing only: make the n-th allocation from now fail (n = 1 is the very
 * next one). Exactly one allocation fails; later ones succeed again. n <= 0
 * turns injection off. fw_alloc_failure_fired() reports whether the chosen
 * allocation was actually reached, so a test can sweep n = 1, 2, 3, ... until
 * the operation under test no longer allocates that many times.
 */
void fw_alloc_fail_nth(long n);
bool fw_alloc_failure_fired(void);

#endif

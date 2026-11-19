/*
 * pipeline.h - one packet from raw bytes to a verdict.
 *
 *   raw bytes -> parse_packet() -> engine_decide() -> verdict
 *
 * Portable (no I/O besides optional logging), so the whole per-packet path
 * the I/O loop runs is unit-testable on any machine. Packets that fail to
 * parse never reach the engine; they are counted here by parse_result_t.
 */
#ifndef FW_PIPELINE_H
#define FW_PIPELINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "engine.h"
#include "parser.h"

typedef struct pipeline_stats {
    uint64_t parse_drops[PARSE_RESULT_COUNT]; /* [PARSE_OK] stays 0 */
    uint64_t write_errors;                    /* filled in by the I/O loop */
} pipeline_stats_t;

typedef struct pipeline {
    engine_t *engine;
    FILE *drop_log;           /* if non-NULL, one line per parse drop (-vv) */
    pipeline_stats_t st;
} pipeline_t;

/* Decide one raw packet that arrived on `dir`. */
verdict_t pipeline_handle(pipeline_t *pl, const uint8_t *buf, size_t len,
                          dir_t dir, uint64_t now_ns);

/* Print engine stats followed by parse drops and write errors. */
void pipeline_stats_print(const pipeline_t *pl, FILE *out);

#endif

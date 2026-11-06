/*
 * log.h - per-flow event logging and metrics output.
 *
 * Logging is OFF by default (so unit tests and benchmarks stay quiet).
 * Per-packet drop logging is only done at LOG_DEBUG; it is guarded by
 * fw_log_enabled() so a port scan doesn't cost a printf per packet.
 */
#ifndef FW_LOG_H
#define FW_LOG_H

#include <stdio.h>
#include "flowtable.h"

typedef enum { LOG_OFF = 0, LOG_INFO, LOG_DEBUG } log_level_t;

void fw_log_set(FILE *out, log_level_t level);
bool fw_log_enabled(log_level_t level);

/* Format a host-order IPv4 address into buf (>= 16 bytes). */
const char *ip_str(uint32_t ip, char *buf, size_t len);
const char *proto_str(uint8_t proto);

/* INFO: flow lifecycle. event is "NEW", "EXPIRE", "CLOSE", ... */
void log_flow(const char *event, const flow_t *f, uint64_t now_ns);

/* DEBUG: a dropped packet. */
void log_drop(const pkt_t *p, dir_t dir, drop_reason_t why, uint64_t now_ns);

void engine_stats_print(const engine_stats_t *s, FILE *out);

#endif

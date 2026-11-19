/*=============================================================================
 * File Name:   engine.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Shared interface between the packet parser / I/O loop and the
 *              decision engine: pkt_t, verdicts, drop reasons, statistics, and
 *              engine_decide().
 =============================================================================*/

/*
 * engine.h - the shared interface between the packet parser / I/O loop
 * (Giselle) and the decision engine (flow table, TCP state, rules).
 *
 * CONTRACT FOR THE PARSER
 *   - Fill a pkt_t from a *validated* IPv4 packet (checksums good, lengths
 *     consistent). Malformed packets must be dropped before engine_decide().
 *   - IP addresses are in HOST byte order (use ntohl on the wire value).
 *   - Ports are in HOST byte order.
 *   - ICMP: set src_port = dst_port = echo identifier, and icmp_type.
 *     (Echo request type 8 and echo reply type 0 then form a reversible flow.)
 *   - Non-TCP packets: tcp_flags = 0. Non-ICMP packets: icmp_type = 0.
 *   - Non-first IP fragments have no L4 header; drop them in the parser.
 *   - payload may be NULL when payload_len == 0.
 *   - ICMP errors (dest unreachable, time exceeded, parameter problem): pass
 *     them to engine_decide() as parsed; payload is the embedded original
 *     packet. The engine matches it to an existing flow itself.
 *   - Packets that FAIL parsing never reach engine_decide(); report each one
 *     with engine_parse_failed() so it is counted and logged.
 *
 * THREADING: engine_t is NOT thread safe. Call from the single I/O thread.
 */
#ifndef FW_ENGINE_H
#define FW_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "appid.h"

#define FW_PROTO_ICMP 1
#define FW_PROTO_TCP  6
#define FW_PROTO_UDP  17

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

typedef struct pkt {
    uint8_t  proto;
    uint32_t src_ip, dst_ip;        /* host byte order */
    uint16_t src_port, dst_port;    /* host byte order; ICMP: echo id in both */
    uint8_t  tcp_flags;
    uint8_t  icmp_type;
    uint16_t ip_len;                /* total IP length, for byte counters */
    uint16_t payload_len;
    const uint8_t *payload;         /* L4 payload (for app identification) */
} pkt_t;

/* Which interface the packet ARRIVED on. */
typedef enum {
    DIR_IN  = 0,   /* arrived on tun-in:  from the trusted/inside network   */
    DIR_OUT = 1    /* arrived on tun-out: from the untrusted/outside network */
} dir_t;

typedef enum { VERDICT_DROP = 0, VERDICT_ALLOW = 1 } verdict_t;

/* Defaults applied by engine_create() / engine_create_with_rules(): one source
 * address may hold 1/16 of the table, and flows started from the outside at
 * most 3/4 of it, so a flood from outside can never take the inside users'
 * reserve. engine_create_with_rules_sized() applies none (see engine_set_limits). */
#define FW_DEFAULT_MAX_PER_SOURCE  (FW_DEFAULT_MAX_FLOWS / 16)
#define FW_DEFAULT_MAX_OUTSIDE     (FW_DEFAULT_MAX_FLOWS / 4 * 3)

/* Related ICMP errors allowed per flow per second; more are dropped. */
#define ICMP_ERRORS_PER_FLOW_PER_SEC 8

typedef enum {
    DROP_NONE = 0,
    DROP_NO_RULE,          /* new flow, no rule matched: default deny       */
    DROP_RULE_DENY,        /* new flow, an explicit deny rule matched       */
    DROP_NOT_SYN,          /* TCP packet with no flow that isn't a SYN      */
    DROP_TCP_STATE,        /* TCP flags illegal for the current state       */
    DROP_NO_FLOW,          /* UDP/ICMP reply-type packet with no flow       */
    DROP_SPOOF,            /* matches a flow's tuple but arrived wrong side */
    DROP_TABLE_FULL,       /* flow table at capacity                        */
    DROP_UNSUPPORTED,      /* e.g. ICMP type we don't track                 */
    DROP_BAD_SRC,          /* anti-spoofing: source address on wrong side   */
    DROP_ICMP_ERR,         /* ICMP error not about any tracked flow         */
    DROP_ICMP_TYPE,        /* ICMP type wrong for this direction of an echo flow */
    DROP_ICMP_RATE,        /* too many ICMP errors for one flow this second */
    DROP_BAD_DST,          /* new flow aimed at the wrong side or a broadcast address */
    DROP_SRC_LIMIT,        /* this source already holds its share of flows  */
    DROP_OUTSIDE_QUOTA,    /* outside-started flows already hold their share */
    DROP_WRITE_FAILED,     /* allowed, but the other side would not take it */
    DROP_REASON_COUNT
} drop_reason_t;

const char *drop_reason_str(drop_reason_t r);

/* Room for one counter per parse_result_t (see parser.h); engine.c checks. */
#define ENGINE_PARSE_KINDS 8

typedef struct engine_stats {
    /* pkts_total/pkts_dropped also include packets that failed parsing. */
    uint64_t pkts_total, pkts_allowed, pkts_dropped;
    uint64_t icmp_related;         /* ICMP errors allowed via a tracked flow */
    uint64_t parse_fail[ENGINE_PARSE_KINDS];  /* indexed by parse_result_t  */
    uint64_t fastpath;             /* hit an existing flow: hash lookup only */
    uint64_t slowpath;             /* no flow: rules evaluated               */
    uint64_t flows_created, flows_expired, flows_active;
    uint64_t drops[DROP_REASON_COUNT];
    /* Application identification (appid.h): flows labelled by what their
     * payload is, and how many of them used a port that suggests a different
     * protocol (e.g. HTTP on 443, TLS on 80, anything but DNS on 53). Labels
     * never change a verdict. */
    uint64_t app_flows[APP_COUNT];
    uint64_t app_mismatch;
} engine_stats_t;

typedef struct engine engine_t;
typedef struct rules rules_t;

/* Flow table capacity when not specified (the requirements spec's default). */
#define FW_DEFAULT_MAX_FLOWS 65536u

/* Load rules from a file. Returns NULL and fills err on failure. */
engine_t *engine_create(const char *rules_path, char *err, size_t errlen);
/* Takes ownership of rules, including when it fails (returns NULL). */
engine_t *engine_create_with_rules(rules_t *rules);
/* Same, with an explicit flow table capacity (all slots allocated up front). */
engine_t *engine_create_with_rules_sized(rules_t *rules, size_t max_flows);
void      engine_destroy(engine_t *e);

/*
 * Decide the fate of one packet. now_ns is a monotonic clock in nanoseconds
 * (passed in so tests can control time). reason may be NULL.
 */
verdict_t engine_decide(engine_t *e, const pkt_t *p, dir_t dir,
                        uint64_t now_ns, drop_reason_t *reason);

/*
 * Record a packet that parse_packet() rejected (result is the non-OK
 * parse_result_t, len the raw length). It counts as a dropped packet and is
 * logged at DEBUG, next to the engine's own drop reasons.
 */
void engine_parse_failed(engine_t *e, unsigned result, dir_t dir, size_t len,
                         uint64_t now_ns);

/* Sweep expired flows. Call about once per second from the I/O loop. */
size_t engine_expire(engine_t *e, uint64_t now_ns);

void engine_get_stats(const engine_t *e, engine_stats_t *out);

/*
 * Cap the flows one source address may hold and the flows started from the
 * outside (0 = no cap). Call before traffic flows. False if it cannot allocate.
 */
bool engine_set_limits(engine_t *e, size_t max_per_source, size_t max_outside);

/*
 * The caller could not deliver a packet engine_decide() allowed. Call it
 * right after that engine_decide(), for the same packet. If the packet
 * created its flow, forget the flow (nobody ever saw its first packet). If it
 * belonged to an existing flow, put the flow back as it was before the packet:
 * counters, TCP state, timer and ICMP error budget (the application label is
 * kept). Either way the packet counts as dropped (DROP_WRITE_FAILED).
 * Returns true if a flow was removed.
 */
bool engine_undo_new_flow(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now_ns);

/*
 * Is there a live flow for p's tuple (in either direction)? If so and
 * orig_dir is not NULL, *orig_dir is the side that started it. Read-only
 * apart from reaping the flow if it has already expired. Used by source NAT
 * (nat.h): only connections started from the inside are translated, and a
 * NAT mapping lives as long as its flow.
 */
bool engine_flow_origin(engine_t *e, const pkt_t *p, uint64_t now_ns, dir_t *orig_dir);

#endif

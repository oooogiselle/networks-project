/*
 * common.h - types shared by every Tunwall module.
 *
 * This is the contract between the packet parser / I/O side and the
 * decision engine. Change it only by agreement (see the build plan).
 */
#ifndef TUNWALL_COMMON_H
#define TUNWALL_COMMON_H

#include <stdint.h>

/* Which TUN device a packet arrived on. */
enum dir {
    DIR_IN = 0,   /* arrived on tun-in:  inside -> outside */
    DIR_OUT = 1,  /* arrived on tun-out: outside -> inside */
};

enum verdict {
    V_DROP = 0,   /* zero value is DROP: default deny */
    V_ALLOW = 1,
};

/* Why a packet was dropped (R_OK when allowed). Keep reason_str() in sync. */
enum reason {
    R_OK = 0,
    R_MALFORMED,      /* bad lengths, bad header fields, invalid TCP flags */
    R_FRAGMENT,       /* IP fragment (unsupported in this version) */
    R_UNSUPPORTED,    /* not IPv4, or an L4 protocol we do not handle */
    R_BAD_CSUM,       /* IP or L4 checksum mismatch */
    R_SPOOFED,        /* source address on the wrong side */
    R_NO_RULE,        /* new flow, no rule matched (default deny) */
    R_DENIED,         /* new flow, matched a deny rule */
    R_INVALID_STATE,  /* packet does not fit the flow state, or no flow */
    R_TABLE_FULL,     /* flow table full; new flow refused */
    R__COUNT
};

static inline const char *reason_str(enum reason r)
{
    static const char *const names[R__COUNT] = {
        [R_OK] = "ok",
        [R_MALFORMED] = "malformed",
        [R_FRAGMENT] = "fragment",
        [R_UNSUPPORTED] = "unsupported",
        [R_BAD_CSUM] = "bad-checksum",
        [R_SPOOFED] = "spoofed",
        [R_NO_RULE] = "no-matching-rule",
        [R_DENIED] = "denied-by-rule",
        [R_INVALID_STATE] = "invalid-state",
        [R_TABLE_FULL] = "table-full",
    };
    return ((unsigned)r < R__COUNT) ? names[r] : "unknown";
}

/* IP protocol numbers we handle. */
#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

/* TCP flag bits (as in the TCP header byte 13). */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* ICMP types we care about. */
#define ICMP_ECHO_REPLY     0
#define ICMP_DEST_UNREACH   3
#define ICMP_ECHO_REQUEST   8
#define ICMP_TIME_EXCEEDED  11
#define ICMP_PARAM_PROBLEM  12

#endif /* TUNWALL_COMMON_H */

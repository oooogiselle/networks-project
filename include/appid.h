/*=============================================================================
 * File Name:   appid.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Application identification: recognizes HTTP, TLS and DNS from
 *              the first bytes of a flow's payload instead of trusting the
 *              port number. Pure functions, no state, no allocation. The
 *              engine uses them only to label, log and count flows; an
 *              identification never changes a verdict.
 =============================================================================*/

#ifndef FW_APPID_H
#define FW_APPID_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    APP_UNKNOWN = 0,     /* not identified (yet)                            */
    APP_OTHER,           /* looked at the first packets, none recognized    */
    APP_HTTP,
    APP_TLS,
    APP_DNS,
    APP_COUNT
} app_t;

/* How many data-carrying packets of a flow are examined before giving up. */
#define APPID_MAX_TRIES 3

/* "http", "tls", "dns", "other", or "-" for APP_UNKNOWN. */
const char *app_name(app_t a);

/*
 * Classify one packet's TCP or UDP payload. Returns APP_HTTP, APP_TLS or
 * APP_DNS if the bytes are unmistakably that protocol, otherwise APP_UNKNOWN
 * (the caller decides when to give up and call the flow APP_OTHER). The check
 * is deliberately strict: a wrong label is worse than no label. Reads only
 * within [payload, payload + len).
 *   HTTP: a request line ("GET /x HTTP/1.1"), a response line ("HTTP/1.1 200"),
 *         or the HTTP/2 connection preface.
 *   TLS:  a handshake record carrying a ClientHello or ServerHello.
 *   DNS:  a well-formed header plus one valid question (over UDP, or over TCP
 *         with its 2-byte length prefix).
 */
app_t appid_detect(uint8_t proto, const uint8_t *payload, size_t len);

/* The protocol a destination port suggests (53 dns, 80 http, 443 tls), or
 * APP_UNKNOWN for any other port. Used only to flag a mismatch. */
app_t appid_expected_for_port(uint8_t proto, uint16_t dst_port);

#endif

/*=============================================================================
 * File Name:   appid.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Payload-based recognition of HTTP, TLS and DNS (see appid.h).
 *              Every read is bounds-checked against len; nothing is copied.
 =============================================================================*/

#include "appid.h"

#include <string.h>

#include "engine.h"

const char *app_name(app_t a)
{
    switch (a) {
    case APP_HTTP:  return "http";
    case APP_TLS:   return "tls";
    case APP_DNS:   return "dns";
    case APP_OTHER: return "other";
    case APP_UNKNOWN:
    case APP_COUNT: break;
    }
    return "-";
}

app_t appid_expected_for_port(uint8_t proto, uint16_t dst_port)
{
    if (proto != FW_PROTO_TCP && proto != FW_PROTO_UDP) return APP_UNKNOWN;
    switch (dst_port) {
    case 53:  return APP_DNS;
    case 80:  return APP_HTTP;
    case 443: return proto == FW_PROTO_TCP ? APP_TLS : APP_UNKNOWN;
    default:  return APP_UNKNOWN;
    }
}

/* ---- HTTP ------------------------------------------------------------------ */

static bool starts_with(const uint8_t *p, size_t n, const char *lit)
{
    const size_t l = strlen(lit);
    return n >= l && memcmp(p, lit, l) == 0;
}

/* "HTTP/1.0" / "HTTP/1.1" / "HTTP/2.0" at p? Returns its length (8) or 0. */
static size_t http_version(const uint8_t *p, size_t n)
{
    if (n >= 8 && memcmp(p, "HTTP/", 5) == 0 && p[6] == '.' &&
        ((p[5] == '1' && (p[7] == '0' || p[7] == '1')) || (p[5] == '2' && p[7] == '0')))
        return 8;
    return 0;
}

static bool http_request(const uint8_t *p, size_t n)
{
    static const char *const methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };
    size_t i = 0;
    bool found = false;
    for (size_t m = 0; m < sizeof methods / sizeof *methods && !found; m++)
        if (starts_with(p, n, methods[m])) { i = strlen(methods[m]); found = true; }
    if (!found) return false;
    /* request target: at least one visible, non-space character */
    const size_t target = i;
    while (i < n && p[i] > 0x20 && p[i] < 0x7f) i++;
    if (i == target || i >= n || p[i] != ' ') return false;
    return http_version(p + i + 1, n - i - 1) != 0;       /* the version must be in view */
}

static bool http_response(const uint8_t *p, size_t n)
{
    if (http_version(p, n) == 0 || n < 12 || p[8] != ' ') return false;
    for (int i = 9; i < 12; i++)
        if (p[i] < '0' || p[i] > '9') return false;
    return n == 12 || p[12] == ' ' || p[12] == '\r';
}

static bool is_http(const uint8_t *p, size_t n)
{
    return http_request(p, n) || http_response(p, n) ||
           starts_with(p, n, "PRI * HTTP/2.0\r\n");        /* HTTP/2 connection preface */
}

/* ---- TLS ------------------------------------------------------------------- */

static bool is_tls(const uint8_t *p, size_t n)
{
    if (n < 11) return false;
    if (p[0] != 0x16 || p[1] != 0x03 || p[2] > 0x04) return false;     /* handshake, SSL3..TLS1.3 */
    const size_t reclen = ((size_t)p[3] << 8) | p[4];
    if (reclen > 16384 + 2048) return false;                /* the hello check below also rules out tiny records */
    if (p[5] != 1 && p[5] != 2) return false;                            /* ClientHello / ServerHello */
    const size_t hslen = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | p[8];
    if (hslen + 4 > reclen) return false;                                /* must fit its record */
    return p[9] == 0x03 && p[10] <= 0x04;                                /* the hello's own version */
}

/* ---- DNS ------------------------------------------------------------------- */

static bool dns_name_char(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           c == '-' || c == '_' || c == '*';
}

/* A DNS message starts at p: valid header and exactly one well-formed question. */
static bool dns_message(const uint8_t *p, size_t n)
{
    if (n < 12 + 1 + 4) return false;
    const unsigned opcode = (p[2] >> 3) & 0x0f, qr = p[2] >> 7;
    if (opcode > 5 || opcode == 3) return false;
    if (p[3] & 0x40) return false;                       /* the reserved Z bit */
    if ((p[3] & 0x0f) > 10) return false;                /* response code */
    const unsigned qd = ((unsigned)p[4] << 8) | p[5], an = ((unsigned)p[6] << 8) | p[7];
    const unsigned ns = ((unsigned)p[8] << 8) | p[9], ar = ((unsigned)p[10] << 8) | p[11];
    if (qd != 1 || an + ns + ar > 100) return false;
    if (!qr && (an != 0 || ns != 0)) return false;       /* a query carries no answers */

    size_t i = 12, labels = 0, total = 0;
    for (;;) {
        if (i >= n) return false;
        const unsigned len = p[i++];
        if (len == 0) break;
        if (len > 63 || i + len > n) return false;       /* also refuses compression pointers */
        for (unsigned k = 0; k < len; k++)
            if (!dns_name_char(p[i + k])) return false;
        i += len;
        total += len + 1;
        labels++;
        if (total > 255) return false;
    }
    if (i + 4 > n) return false;
    const unsigned qtype = ((unsigned)p[i] << 8) | p[i + 1];
    const unsigned qclass = ((unsigned)p[i + 2] << 8) | p[i + 3];
    if (qtype < 1 || qtype > 260) return false;
    if (qclass != 1 && qclass != 3 && qclass != 4 && qclass != 255) return false;
    return labels > 0 || qtype == 2;                     /* only an NS query may ask about "." */
}

static bool is_dns_over_tcp(const uint8_t *p, size_t n)
{
    if (n < 2 + 12 + 1 + 4) return false;
    const size_t declared = ((size_t)p[0] << 8) | p[1];
    return declared >= 12 + 1 + 4 && declared <= n - 2 && dns_message(p + 2, declared);
}

/* ---- public ---------------------------------------------------------------- */

app_t appid_detect(uint8_t proto, const uint8_t *payload, size_t len)
{
    if (!payload || len == 0) return APP_UNKNOWN;
    if (proto == FW_PROTO_UDP)
        return dns_message(payload, len) ? APP_DNS : APP_UNKNOWN;
    if (proto == FW_PROTO_TCP) {
        if (is_tls(payload, len)) return APP_TLS;
        if (is_http(payload, len)) return APP_HTTP;
        if (is_dns_over_tcp(payload, len)) return APP_DNS;
    }
    return APP_UNKNOWN;
}

/*=============================================================================
 * File Name:   test_appid.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Tests for payload-based application identification: real-looking
 *              HTTP, TLS and DNS messages that must be recognized, near-misses
 *              that must not, every protocol on the wrong transport, and a fuzz
 *              run over exact-size heap buffers (so any read past len is caught
 *              by AddressSanitizer).
 =============================================================================*/

#include <stdlib.h>
#include <string.h>

#include "appid.h"
#include "engine.h"
#include "testutil.h"

#define TCP FW_PROTO_TCP
#define UDP FW_PROTO_UDP

static app_t detect_str(uint8_t proto, const char *s)
{
    return appid_detect(proto, (const uint8_t *)s, strlen(s));
}

/* ---- sample messages ------------------------------------------------------ */

/* A TLS ClientHello record (TLS 1.2 style) with a body of `body` bytes. */
static size_t tls_hello(uint8_t *b, uint8_t hs_type, uint8_t rec_minor, size_t body)
{
    const size_t hslen = body, reclen = hslen + 4;
    b[0] = 0x16; b[1] = 0x03; b[2] = rec_minor;
    b[3] = (uint8_t)(reclen >> 8); b[4] = (uint8_t)reclen;
    b[5] = hs_type;
    b[6] = (uint8_t)(hslen >> 16); b[7] = (uint8_t)(hslen >> 8); b[8] = (uint8_t)hslen;
    b[9] = 0x03; b[10] = 0x03;                          /* the hello's own version: TLS 1.2 */
    for (size_t i = 11; i < 9 + body; i++) b[i] = (uint8_t)(i * 7);
    return 9 + body;
}

/* A DNS message: id, flags, then one question for `name` (dotted) type/class. */
static size_t dns_msg(uint8_t *b, uint16_t flags, uint16_t an, const char *name,
                      uint16_t qtype, uint16_t qclass)
{
    b[0] = 0x12; b[1] = 0x34;
    b[2] = (uint8_t)(flags >> 8); b[3] = (uint8_t)flags;
    b[4] = 0; b[5] = 1; b[6] = (uint8_t)(an >> 8); b[7] = (uint8_t)an;
    memset(b + 8, 0, 4);
    size_t i = 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        const size_t l = dot ? (size_t)(dot - p) : strlen(p);
        b[i++] = (uint8_t)l;
        memcpy(b + i, p, l);
        i += l;
        p += l + (dot ? 1 : 0);
        if (!dot) break;
    }
    b[i++] = 0;
    b[i++] = (uint8_t)(qtype >> 8); b[i++] = (uint8_t)qtype;
    b[i++] = (uint8_t)(qclass >> 8); b[i++] = (uint8_t)qclass;
    return i;
}

/* ---- HTTP ------------------------------------------------------------------ */

static void test_http_requests_are_recognized_on_any_port_and_method(void)
{
    const char *ok[] = {
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /index.html?a=1&b=2 HTTP/1.0\r\n\r\n",
        "POST /api/v1/items HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata",
        "HEAD /x HTTP/1.1\r\n", "PUT /f HTTP/1.1\r\n", "DELETE /f HTTP/1.1\r\n",
        "OPTIONS * HTTP/1.1\r\n", "PATCH /f HTTP/1.1\r\n", "TRACE / HTTP/1.1\r\n",
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\n",
        "GET / HTTP/2.0\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",                      /* HTTP/2 preface */
    };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++)
        CHECK(detect_str(TCP, ok[i]) == APP_HTTP);
}

static void test_http_responses_are_recognized(void)
{
    CHECK(detect_str(TCP, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n") == APP_HTTP);
    CHECK(detect_str(TCP, "HTTP/1.0 404 Not Found\r\n") == APP_HTTP);
    CHECK(detect_str(TCP, "HTTP/1.1 301 Moved Permanently\r\n") == APP_HTTP);
    CHECK(detect_str(TCP, "HTTP/2.0 200\r\n") == APP_HTTP);
    CHECK(detect_str(TCP, "HTTP/1.1 200") == APP_HTTP);                /* status ends the payload */
}

static void test_near_misses_are_not_http(void)
{
    const char *no[] = {
        "GET", "GET ", "GET /", "GET / ", "GET / HTTP", "GET / HTTP/", "GET / HTTP/1.",
        "GET  / HTTP/1.1\r\n",                  /* two spaces: no target */
        "GETX / HTTP/1.1\r\n", "get / HTTP/1.1\r\n", "Get / HTTP/1.1\r\n",
        "GET / HTTP/3.1\r\n", "GET / HTTP/1.2\r\n", "GET / HTTP/9.9\r\n",
        "GET /a b HTTP/1.1\r\n",                /* a space inside the target */
        "GET /\x01 HTTP/1.1\r\n",               /* control byte in the target */
        "GET /\x01HTTP/1.1\r\n", "GET /a\tHTTP/1.1\r\n",   /* no space before the version */
        "POSTCARD / HTTP/1.1\r\n", " GET / HTTP/1.1\r\n",
        "HTTP/1.1", "HTTP/1.1 20", "HTTP/1.1 2x0 OK\r\n", "HTTP/1.1 200OK\r\n",
        "HTTP/1.5 200 OK\r\n", "HTTP 200 OK\r\n", "http/1.1 200 OK\r\n",
        "PRI * HTTP/2.0", "PRI * HTTP/1.1\r\n",
        "SSH-2.0-OpenSSH_9.6\r\n", "220 smtp.example.com ESMTP\r\n", "+OK POP3 ready\r\n",
        "hello world", "\r\n\r\n", "",
    };
    for (size_t i = 0; i < sizeof no / sizeof *no; i++)
        CHECK(detect_str(TCP, no[i]) == APP_UNKNOWN);
}

/* ---- TLS ------------------------------------------------------------------- */

static void test_tls_hellos_are_recognized(void)
{
    uint8_t b[600];
    size_t n = tls_hello(b, 1, 0x01, 190);                    /* ClientHello, record 3.1 */
    CHECK(appid_detect(TCP, b, n) == APP_TLS);
    n = tls_hello(b, 1, 0x03, 500);                           /* TLS 1.2/1.3 style record 3.3 */
    CHECK(appid_detect(TCP, b, n) == APP_TLS);
    n = tls_hello(b, 2, 0x03, 90);                            /* ServerHello */
    CHECK(appid_detect(TCP, b, n) == APP_TLS);
    n = tls_hello(b, 1, 0x00, 100);                           /* SSL 3.0 record */
    CHECK(appid_detect(TCP, b, n) == APP_TLS);
    n = tls_hello(b, 1, 0x04, 100);                           /* the highest minor accepted */
    CHECK(appid_detect(TCP, b, n) == APP_TLS);
    /* the first segment may carry only part of the hello: the header is enough */
    n = tls_hello(b, 1, 0x01, 500);
    CHECK(appid_detect(TCP, b, 11) == APP_TLS);
    CHECK(appid_detect(TCP, b, 60) == APP_TLS);
}

static void test_near_misses_are_not_tls(void)
{
    uint8_t b[600], c[600];
    size_t n = tls_hello(b, 1, 0x03, 190);
    CHECK(appid_detect(TCP, b, 10) == APP_UNKNOWN);          /* too short to be sure */
    memcpy(c, b, n); c[0] = 0x17;                            /* application data */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[0] = 0x15;                            /* alert */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[1] = 0x02;                            /* wrong major version */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[2] = 0x05;                            /* minor version too high */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[5] = 0x0b;                            /* a Certificate, not a hello */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[5] = 0x00;
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[3] = 0x00; c[4] = 0x03;               /* record length below a handshake header */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[3] = 0xff; c[4] = 0xff;               /* record length above the maximum */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[6] = 0x7f;                            /* handshake longer than its record */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[9] = 0x04;                            /* the hello's version is nonsense */
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[10] = 0x09;
    CHECK(appid_detect(TCP, c, n) == APP_UNKNOWN);
}

/* ---- DNS ------------------------------------------------------------------- */

static void test_dns_queries_and_responses_are_recognized(void)
{
    uint8_t b[300];
    size_t n = dns_msg(b, 0x0100, 0, "example.com", 1, 1);           /* A query, recursion desired */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x8180, 2, "www.example.com", 1, 1);              /* response with answers */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x0100, 0, "example.com", 28, 1);                 /* AAAA */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x0100, 0, "_dmarc.example.com", 16, 1);          /* TXT, underscore label */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x0100, 0, "a-b.example.com", 255, 1);            /* type ANY */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x0100, 0, "example.com", 1, 255);                /* class ANY */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x0100, 0, "", 2, 1);                             /* NS for the root */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x8183, 0, "nonexistent.example.com", 1, 1);      /* NXDOMAIN response */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    n = dns_msg(b, 0x2800, 0, "example.com", 6, 1);                  /* NOTIFY-ish opcode 5 */
    CHECK(appid_detect(UDP, b, n) == APP_DNS);
    /* trailing bytes after the question (EDNS records, answers) are fine */
    n = dns_msg(b, 0x8180, 1, "example.com", 1, 1);
    memset(b + n, 0xC0, 20);
    CHECK(appid_detect(UDP, b, n + 20) == APP_DNS);
}

static void test_dns_over_tcp_needs_its_length_prefix(void)
{
    uint8_t m[300], b[310];
    size_t n = dns_msg(m, 0x0100, 0, "example.com", 1, 1);
    b[0] = (uint8_t)(n >> 8); b[1] = (uint8_t)n;
    memcpy(b + 2, m, n);
    CHECK(appid_detect(TCP, b, n + 2) == APP_DNS);
    CHECK(appid_detect(TCP, m, n) == APP_UNKNOWN);                   /* no prefix: not DNS over TCP */
    b[1] = (uint8_t)(n + 5);                                         /* prefix longer than the data */
    CHECK(appid_detect(TCP, b, n + 2) == APP_UNKNOWN);
    b[0] = 0; b[1] = 3;                                              /* prefix too short for a message */
    CHECK(appid_detect(TCP, b, n + 2) == APP_UNKNOWN);
    /* a prefix only one or two bytes too long, in an EXACT-size buffer: it must
     * be refused without ever reading past the end (ASan checks that) */
    for (size_t extra = 1; extra <= 2; extra++) {
        uint8_t *x = malloc(n + 2);
        x[0] = 0; x[1] = (uint8_t)(n + extra);
        memcpy(x + 2, m, n);
        CHECK(appid_detect(TCP, x, n + 2) == APP_UNKNOWN);
        free(x);
    }
}

static void test_near_misses_are_not_dns(void)
{
    uint8_t b[300], c[300];
    size_t n = dns_msg(b, 0x0100, 0, "example.com", 1, 1);
    CHECK(appid_detect(UDP, b, 11) == APP_UNKNOWN);                  /* shorter than a header */
    CHECK(appid_detect(UDP, b, n - 1) == APP_UNKNOWN);               /* class cut off */
    CHECK(appid_detect(UDP, b, 20) == APP_UNKNOWN);                  /* name cut off */
    memcpy(c, b, n); c[2] = 0x18;                                    /* opcode 3 (unassigned) */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[2] = 0x40;                                    /* opcode 8 */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[3] = 0x40;                                    /* reserved Z bit set */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[3] = 0x0f;                                    /* response code 15 */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[5] = 2;                                       /* two questions */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[5] = 0;                                       /* none */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[7] = 1;                                       /* a QUERY with an answer */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[2] = 0x81; c[7] = 200;                        /* implausible record counts */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[12] = 64;                                     /* label length 64 */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[12] = 0xC0;                                   /* compression pointer in the question */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[13] = ' ';                                    /* a space in a label */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[n - 4] = 0; c[n - 3] = 0;                     /* qtype 0 */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[n - 4] = 0x40;                                /* qtype far above the known range */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    memcpy(c, b, n); c[n - 2] = 0; c[n - 1] = 9;                     /* class 9 */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    n = dns_msg(c, 0x0100, 0, "", 1, 1);                             /* root, but not an NS query */
    CHECK(appid_detect(UDP, c, n) == APP_UNKNOWN);
    /* a label of exactly 64 bytes is one too many, with the data really there;
     * 63 is the most allowed */
    uint8_t lab[200];
    for (int L = 63; L <= 64; L++) {
        memcpy(lab, b, 12);
        size_t k = 12;
        lab[k++] = (uint8_t)L; memset(lab + k, 'a', (size_t)L); k += (size_t)L;
        lab[k++] = 0; lab[k++] = 0; lab[k++] = 1; lab[k++] = 0; lab[k++] = 1;
        CHECK(appid_detect(UDP, lab, k) == (L == 63 ? APP_DNS : APP_UNKNOWN));
    }
    /* a name of 4 labels of 63 characters is over 255 bytes */
    uint8_t big[400];
    memcpy(big, b, 12);
    size_t i = 12;
    for (int l = 0; l < 4; l++) { big[i++] = 63; memset(big + i, 'a', 63); i += 63; }
    big[i++] = 0; big[i++] = 0; big[i++] = 1; big[i++] = 0; big[i++] = 1;
    CHECK(appid_detect(UDP, big, i) == APP_UNKNOWN);
}

/* ---- transports and plumbing ----------------------------------------------- */

static void test_each_protocol_only_counts_on_its_own_transport(void)
{
    uint8_t d[300], t[600];
    const size_t dn = dns_msg(d, 0x0100, 0, "example.com", 1, 1);
    const size_t tn = tls_hello(t, 1, 0x03, 190);
    CHECK(appid_detect(UDP, t, tn) == APP_UNKNOWN);                  /* TLS is not looked for over UDP */
    CHECK(detect_str(UDP, "GET / HTTP/1.1\r\n") == APP_UNKNOWN);     /* nor HTTP */
    CHECK(appid_detect(TCP, d, dn) == APP_UNKNOWN);                  /* bare DNS needs UDP (or a prefix) */
    CHECK(appid_detect(FW_PROTO_ICMP, d, dn) == APP_UNKNOWN);        /* ICMP carries no application */
    CHECK(appid_detect(47, d, dn) == APP_UNKNOWN);
}

static void test_empty_and_null_input_is_unknown(void)
{
    CHECK(appid_detect(TCP, NULL, 0) == APP_UNKNOWN);
    CHECK(appid_detect(UDP, NULL, 100) == APP_UNKNOWN);
    uint8_t b[4] = {0};
    CHECK(appid_detect(TCP, b, 0) == APP_UNKNOWN);
}

static void test_names_and_port_hints(void)
{
    CHECK(strcmp(app_name(APP_HTTP), "http") == 0);
    CHECK(strcmp(app_name(APP_TLS), "tls") == 0);
    CHECK(strcmp(app_name(APP_DNS), "dns") == 0);
    CHECK(strcmp(app_name(APP_OTHER), "other") == 0);
    CHECK(strcmp(app_name(APP_UNKNOWN), "-") == 0);
    CHECK(strcmp(app_name(APP_COUNT), "-") == 0);
    CHECK(appid_expected_for_port(TCP, 80) == APP_HTTP);
    CHECK(appid_expected_for_port(TCP, 443) == APP_TLS);
    CHECK(appid_expected_for_port(UDP, 53) == APP_DNS);
    CHECK(appid_expected_for_port(TCP, 53) == APP_DNS);
    CHECK(appid_expected_for_port(UDP, 80) == APP_HTTP);
    CHECK(appid_expected_for_port(UDP, 443) == APP_UNKNOWN);         /* QUIC is not TLS-over-TCP */
    CHECK(appid_expected_for_port(TCP, 8080) == APP_UNKNOWN);
    CHECK(appid_expected_for_port(TCP, 0) == APP_UNKNOWN);
    CHECK(appid_expected_for_port(FW_PROTO_ICMP, 80) == APP_UNKNOWN);
}

/* ---- fuzz ------------------------------------------------------------------ */

static uint32_t g_rng = 0x1badf00du;
static uint32_t rng(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5; return g_rng; }

static void test_fuzz_exact_size_buffers_never_overread(void)
{
    /* every prefix of valid samples, then random bytes and random mutations of
     * valid samples, each in an exact-size heap copy: an over-read is an ASan error */
    uint8_t samples[5][600];
    size_t lens[5];
    lens[0] = dns_msg(samples[0], 0x8180, 2, "www.example.com", 1, 1);
    lens[1] = tls_hello(samples[1], 1, 0x03, 190);
    static const char req[] = "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
    static const char rsp[] = "HTTP/1.1 200 OK\r\n\r\n";
    lens[2] = strlen(req); memcpy(samples[2], req, lens[2]);
    lens[3] = strlen(rsp); memcpy(samples[3], rsp, lens[3]);
    samples[4][0] = 0; samples[4][1] = 30;
    lens[4] = 2 + dns_msg(samples[4] + 2, 0x0100, 0, "example.com", 1, 1);
    samples[4][1] = (uint8_t)(lens[4] - 2);
    unsigned long recognized = 0;
    for (int s = 0; s < 5; s++)
        for (size_t l = 0; l <= lens[s]; l++)
            for (int proto = 0; proto < 2; proto++) {
                uint8_t *x = malloc(l ? l : 1);
                memcpy(x, samples[s], l);
                recognized += appid_detect(proto ? UDP : TCP, l ? x : NULL, l) != APP_UNKNOWN;
                free(x);
            }
    CHECK(recognized > 20);                                          /* the fuzz sees real hits */
    for (int i = 0; i < 100000; i++) {
        const size_t s = rng() % 5;
        size_t l = 1 + rng() % (lens[s] + 8);
        uint8_t *x = malloc(l);
        for (size_t k = 0; k < l; k++) x[k] = k < lens[s] && rng() % 8 ? samples[s][k] : (uint8_t)rng();
        if (rng() % 4 == 0) x[rng() % l] ^= (uint8_t)(1 + rng() % 255);
        const app_t a = appid_detect(rng() & 1 ? UDP : TCP, x, l);
        CHECK(a == APP_UNKNOWN || a == APP_HTTP || a == APP_TLS || a == APP_DNS);
        free(x);
    }
}

int main(void)
{
    RUN(test_http_requests_are_recognized_on_any_port_and_method);
    RUN(test_http_responses_are_recognized);
    RUN(test_near_misses_are_not_http);
    RUN(test_tls_hellos_are_recognized);
    RUN(test_near_misses_are_not_tls);
    RUN(test_dns_queries_and_responses_are_recognized);
    RUN(test_dns_over_tcp_needs_its_length_prefix);
    RUN(test_near_misses_are_not_dns);
    RUN(test_each_protocol_only_counts_on_its_own_transport);
    RUN(test_empty_and_null_input_is_unknown);
    RUN(test_names_and_port_hints);
    RUN(test_fuzz_exact_size_buffers_never_overread);
    TEST_DONE();
}

/* Minimal unit-test helpers: CHECK() counts failures, main returns non-zero. */
#ifndef FW_TESTUTIL_H
#define FW_TESTUTIL_H

#include <stdio.h>
#include <string.h>
#include "engine.h"

static int t_run, t_fail;

#define CHECK(c) do { t_run++; if (!(c)) { t_fail++; \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RUN(fn) do { int before = t_fail; fn(); \
    printf("%s %s\n", t_fail == before ? "ok  " : "FAIL", #fn); } while (0)

#define TEST_DONE() do { printf("%d checks, %d failed\n", t_run, t_fail); \
    return t_fail ? 1 : 0; } while (0)

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define SEC 1000000000ull

static inline pkt_t mk_tcp(uint32_t s, uint16_t sp, uint32_t d, uint16_t dp,
                           uint8_t flags)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    p.proto = FW_PROTO_TCP;
    p.src_ip = s; p.src_port = sp; p.dst_ip = d; p.dst_port = dp;
    p.tcp_flags = flags;
    p.ip_len = 60;
    return p;
}

static inline pkt_t mk_udp(uint32_t s, uint16_t sp, uint32_t d, uint16_t dp)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    p.proto = FW_PROTO_UDP;
    p.src_ip = s; p.src_port = sp; p.dst_ip = d; p.dst_port = dp;
    p.ip_len = 80;
    return p;
}

static inline pkt_t mk_icmp(uint32_t s, uint32_t d, uint8_t type, uint16_t id)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    p.proto = FW_PROTO_ICMP;
    p.src_ip = s; p.dst_ip = d; p.src_port = p.dst_port = id;
    p.icmp_type = type;
    p.ip_len = 84;
    return p;
}

#endif

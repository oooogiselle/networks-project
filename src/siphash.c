/*=============================================================================
 * File Name:   siphash.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: SipHash-2-4 (see siphash.h). Written from the public
 *              specification and checked against its published test vectors.
 =============================================================================*/

#include "siphash.h"

#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

#define SIPROUND                                                         \
    do {                                                                 \
        v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32);    \
        v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                         \
        v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                         \
        v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);    \
    } while (0)

uint64_t fw_siphash24(const uint8_t key[16], const uint8_t *in, size_t len)
{
    const uint64_t k0 = load_le64(key), k1 = load_le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ull ^ k0;
    uint64_t v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0;
    uint64_t v3 = 0x7465646279746573ull ^ k1;

    const uint8_t *end = in + (len - len % 8);
    for (; in != end; in += 8) {                 /* whole 8-byte words */
        const uint64_t m = load_le64(in);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }

    uint64_t b = (uint64_t)len << 56;            /* last word: tail bytes + length */
    for (size_t i = 0; i < len % 8; i++) b |= (uint64_t)in[i] << (8 * i);
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

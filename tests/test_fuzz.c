/*=============================================================================
 * File Name:   test_fuzz.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Robustness test: random and corrupted packets through the parser
 *              and engine, checking that nothing crashes and that the counters
 *              stay consistent.
 =============================================================================*/

/*
 * test_fuzz.c - "the program should never crash on bad input" (spec section 4).
 *
 * Phases, all deterministic from a seed so a failure can be replayed (phase D,
 * the rules-file parser, is described where it is defined):
 *   A. pure random bytes of random lengths           -> parse_packet (-> engine)
 *   B. valid packets, randomly corrupted/truncated   -> parse_packet (-> engine)
 *   C. random pkt_t structs straight into the engine (bypasses the parser, so
 *      the engine itself is proven robust, e.g. ICMP errors with junk payload)
 *   E. TCP conversations: handshakes, then segments that are mostly in order
 *      and sometimes off by a little or a lot, for the sequence checks
 *      (tcpseq.h; run on an engine with them on, and one with them off)
 *
 * Besides "did not crash" (run it under `make asan`), it checks invariants:
 * parse results are consistent, verdict and reason agree, counters add up,
 * and the flow table never exceeds its capacity.
 *
 *   FUZZ_SEED=<n> FUZZ_ITERS=<n> ./build/test_fuzz      (iterations per phase)
 */
#include <stdlib.h>

#include "engine.h"
#include "parser.h"
#include "pktbuild.h"
#include "rules.h"
#include "testutil.h"

#define DEFAULT_SEED  0x5eed1234abcdULL
#define DEFAULT_ITERS 100000UL
#define SMALL_TABLE   2

/* ---- deterministic PRNG (xorshift64*) ----------------------------------- */

static uint64_t rng;

static uint32_t rnd(void)
{
    rng ^= rng >> 12;
    rng ^= rng << 25;
    rng ^= rng >> 27;
    return (uint32_t)((rng * 0x2545F4914F6CDD1DULL) >> 32);
}

static uint32_t below(uint32_t n) { return n ? rnd() % n : 0; }
static int chance(uint32_t pct) { return below(100) < pct; }

/* Small pools so random packets collide into the same flows. */
static const uint32_t ADDRS[] = {
    IP(10,0,1,2), IP(10,0,1,3), IP(10,0,2,2), IP(10,0,2,3),
    IP(93,184,216,34), IP(8,8,8,8), IP(192,168,1,1), IP(127,0,0,1),
    IP(0,0,0,0), IP(255,255,255,255), IP(224,0,0,1),
};
static const uint16_t PORTS[] = { 0, 22, 53, 80, 443, 5000, 40000, 65535 };

static uint32_t pick_addr(void) { return ADDRS[below(sizeof ADDRS / sizeof *ADDRS)]; }
static uint16_t pick_port(void) { return PORTS[below(sizeof PORTS / sizeof *PORTS)]; }

/* ---- the engines under test --------------------------------------------- */

static const char *POLICY =
    "inside 10.0.1.0/24\n"
    "allow out tcp 10.0.1.0/24 any 80 app http\n"   /* cut once not HTTP (phase E) */
    "allow out tcp 10.0.1.0/24 any 443\n"
    "allow out udp 10.0.1.0/24 any 53\n"
    "allow out icmp 10.0.1.0/24 any echo\n"
    "deny  out udp any any 53\n"
    "allow in  tcp any 10.0.1.3 22\n";

static engine_t *make(const char *rules, size_t max_flows)
{
    char err[128];
    rules_t *r = rules_parse_string(rules, err, sizeof err);
    return max_flows ? engine_create_with_rules_sized(r, max_flows)
                     : engine_create_with_rules(r);
}

/* ---- bookkeeping --------------------------------------------------------- */

static unsigned long parse_seen[PARSE_RESULT_COUNT];
static unsigned long drop_seen[DROP_REASON_COUNT];
static unsigned long allowed_seen, related_seen;

static void check_stats(engine_t *e, size_t cap)
{
    engine_stats_t s;
    engine_get_stats(e, &s);
    uint64_t drops = 0, pfail = 0;
    for (int i = 0; i < DROP_REASON_COUNT; i++) drops += s.drops[i];
    for (int i = 0; i < ENGINE_PARSE_KINDS; i++) pfail += s.parse_fail[i];
    CHECK(s.pkts_allowed + s.pkts_dropped == s.pkts_total);
    CHECK(drops + pfail == s.pkts_dropped);
    CHECK(s.drops[DROP_NONE] == 0);
    CHECK(s.flows_active <= cap);
    CHECK(s.fastpath + s.slowpath <= s.pkts_total);
}

/* Feed a decoded packet to the engine and check the verdict contract. */
static void feed(engine_t *e, const pkt_t *p, dir_t dir, uint64_t now)
{
    drop_reason_t why = DROP_REASON_COUNT;
    verdict_t v = engine_decide(e, p, dir, now, &why);
    if (v == VERDICT_ALLOW) {
        CHECK(why == DROP_NONE);
        allowed_seen++;
    } else {
        CHECK(v == VERDICT_DROP);
        CHECK(why > DROP_NONE && why < DROP_REASON_COUNT);
        if (why > DROP_NONE && why < DROP_REASON_COUNT) drop_seen[why]++;
    }
}

/* Parse raw bytes; on success check the parser's promises and run the engine. */
static void parse_and_feed(engine_t *e, const uint8_t *buf, size_t len,
                           dir_t dir, uint64_t now)
{
    pkt_t p;
    memset(&p, 0xAA, sizeof p);              /* "undefined on failure" */
    parse_result_t r = parse_packet(buf, len, &p);
    CHECK((unsigned)r < PARSE_RESULT_COUNT);
    if ((unsigned)r < PARSE_RESULT_COUNT) parse_seen[r]++;

    if (r != PARSE_OK) {
        engine_parse_failed(e, r, dir, len, now);
        return;
    }
    CHECK(p.ip_len == len);
    CHECK(p.proto == FW_PROTO_TCP || p.proto == FW_PROTO_UDP ||
          p.proto == FW_PROTO_ICMP);
    if (p.proto != FW_PROTO_ICMP) CHECK(p.src_port != 0 && p.dst_port != 0);
    if (p.payload_len == 0) CHECK(p.payload == NULL);
    if (p.payload_len > 0)
        CHECK(p.payload >= buf && p.payload + p.payload_len <= buf + len);
    if (p.proto == FW_PROTO_ICMP && icmp_is_error(p.icmp_type)) {
        pkt_t in;
        (void)parse_icmp_inner(&p, &in);     /* must also be safe to call */
    }
    feed(e, &p, dir, now);
}

/* Time moves forward, usually a little, sometimes by hours (to hit expiry). */
static uint64_t advance(uint64_t now)
{
    if (chance(2)) return now + (uint64_t)(1 + below(7200)) * SEC;
    return now + (uint64_t)below(3000) * 1000000ull;
}

/* ---- phase A: random bytes ----------------------------------------------- */

static void phase_random_bytes(engine_t *e, unsigned long iters)
{
    uint8_t buf[2048];
    uint64_t now = SEC;
    for (unsigned long i = 0; i < iters; i++) {
        size_t len = chance(30) ? below(40) : below(sizeof buf);
        for (size_t k = 0; k < len; k++) buf[k] = (uint8_t)rnd();
        if (len >= 20 && chance(60)) {        /* look vaguely like IPv4 */
            buf[0] = 0x40 | (chance(80) ? 5 : below(16));
            pb_wr16(buf + 2, (uint16_t)len);
            static const uint8_t protos[] = { 1, 6, 17, 47 };
            buf[9] = protos[below(4)];
            pb_wr16(buf + 6, chance(80) ? 0 : (uint16_t)rnd());
            if (chance(50)) pb_fix_csums(buf, len);
        }
        now = advance(now);
        parse_and_feed(e, buf, len, below(2) ? DIR_IN : DIR_OUT, now);
        if (chance(1)) engine_expire(e, now);
    }
}

/* ---- phase B: corrupted valid packets ------------------------------------ */

static size_t build_valid(uint8_t *buf, size_t cap)
{
    uint32_t s = pick_addr(), d = pick_addr();
    uint16_t sp = pick_port(), dp = pick_port();
    uint8_t payload[120];
    size_t plen = below(sizeof payload);
    for (size_t k = 0; k < plen; k++) payload[k] = (uint8_t)rnd();

    struct pb_opts o = { 0 };
    if (chance(15)) o.ip_opt_len = (uint8_t)(4 * below(11));
    if (chance(15)) o.tcp_opt_len = (uint8_t)(4 * below(11));
    if (chance(10)) o.udp_no_csum = 1;

    switch (below(5)) {
    case 0: {
        static const uint8_t flags[] = { TCP_SYN, TCP_SYN|TCP_ACK, TCP_ACK,
            TCP_ACK|TCP_PSH, TCP_FIN|TCP_ACK, TCP_RST, 0, 0x3f, TCP_SYN|TCP_FIN };
        return pb_tcp(buf, cap, &o, s, sp, d, dp, flags[below(9)], payload, plen);
    }
    case 1:
        return pb_udp(buf, cap, &o, s, sp, d, dp, payload, plen);
    case 2:
        return pb_icmp_echo(buf, cap, &o, s, d,
                            chance(50) ? ICMP_ECHO_REQUEST : ICMP_ECHO_REPLY,
                            pick_port(), (uint16_t)rnd(), payload, plen);
    default: {                                /* ICMP error embedding a packet */
        uint8_t inner[128];
        size_t n = pb_tcp(inner, sizeof inner, NULL, d, dp, s, sp, TCP_SYN, NULL, 0);
        static const uint8_t types[] = { ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED,
                                         ICMP_PARAM_PROBLEM };
        size_t embed = n ? 1 + below((uint32_t)(n > 28 ? 28 : n)) : 0;
        return pb_icmp_error(buf, cap, &o, s, d, types[below(3)], (uint8_t)below(16),
                             inner, embed);
    }
    }
}

static void mutate(uint8_t *buf, size_t *len)
{
    for (uint32_t m = below(5); m > 0 && *len > 0; m--) {
        switch (below(4)) {
        case 0: buf[below((uint32_t)*len)] ^= (uint8_t)(1u << below(8)); break;
        case 1: buf[below((uint32_t)*len)] = (uint8_t)rnd(); break;
        case 2: *len = below((uint32_t)*len + 1); break;           /* truncate */
        case 3: {                                                   /* grow */
            size_t extra = 1 + below(16);
            for (size_t k = 0; k < extra && *len < 600; k++)
                buf[(*len)++] = (uint8_t)rnd();
            break;
        }
        }
    }
}

static void phase_mutated(engine_t *e, unsigned long iters)
{
    uint8_t buf[1024];
    uint64_t now = SEC;
    for (unsigned long i = 0; i < iters; i++) {
        size_t len = build_valid(buf, sizeof buf);
        if (len == 0) continue;
        if (chance(70)) mutate(buf, &len);
        /* Half the time repair the checksums, so corruption gets past them
         * and reaches the deeper validation instead of dying at the CSUM. */
        if (chance(50)) pb_fix_csums(buf, len);
        now = advance(now);
        parse_and_feed(e, buf, len, below(2) ? DIR_IN : DIR_OUT, now);
        if (chance(1)) engine_expire(e, now);
    }
}

/* ---- phase C: arbitrary pkt_t straight into the engine -------------------- */

static void phase_random_pkts(engine_t *e, unsigned long iters)
{
    uint8_t junk[96];
    uint64_t now = SEC;
    static const uint8_t protos[] = { 1, 6, 17, 6, 17, 0, 47, 255 };
    static const uint8_t icmp_types[] = { 0, 8, 3, 11, 12, 5, 13, 255 };
    for (unsigned long i = 0; i < iters; i++) {
        for (size_t k = 0; k < sizeof junk; k++) junk[k] = (uint8_t)rnd();
        if (chance(50)) junk[0] = 0x45;       /* often a plausible inner header */
        pkt_t p;
        memset(&p, 0, sizeof p);
        p.proto = protos[below(sizeof protos)];
        p.src_ip = pick_addr();  p.dst_ip = pick_addr();
        p.src_port = pick_port(); p.dst_port = pick_port();
        p.tcp_flags = chance(70) ? (uint8_t)(1u << below(6)) : (uint8_t)rnd();
        /* Sequence numbers from a small pool, so the window checks see
         * handshakes that line up as well as ones that don't. */
        static const uint32_t seqs[] = { 0, 1, 1000, 1001, 5000, 5001, 0xffffffffu, 0x80000000u };
        static const uint8_t wscales[] = { TCP_NO_WSCALE, 0, 7, 14, TCP_NO_WSCALE, 3 };
        p.tcp_seq = chance(80) ? seqs[below(sizeof seqs / sizeof *seqs)] : (uint32_t)rnd();
        p.tcp_ack = chance(80) ? seqs[below(sizeof seqs / sizeof *seqs)] : (uint32_t)rnd();
        p.tcp_win = chance(50) ? 64240 : (uint16_t)rnd();
        p.tcp_wscale = wscales[below(sizeof wscales)];
        if (p.proto == FW_PROTO_ICMP) {
            p.icmp_type = icmp_types[below(sizeof icmp_types)];
            p.dst_port = p.src_port;          /* echo id lives in both */
        }
        p.ip_len = (uint16_t)rnd();
        if (chance(60)) {
            p.payload_len = (uint16_t)below(sizeof junk + 1);
            p.payload = p.payload_len ? junk : NULL;
        }
        now = advance(now);
        feed(e, &p, below(2) ? DIR_IN : DIR_OUT, now);
        if (chance(1)) engine_expire(e, now);
    }
}

/* ---- phase E: TCP conversations ------------------------------------------ */

/* A segment of the conversation between 10.0.1.2:sport and 93.184.216.34:80. */
static pkt_t conv_seg(bool from_client, uint16_t sport, uint8_t flags, uint32_t seq,
                      uint32_t ack, uint16_t len)
{
    pkt_t p;
    memset(&p, 0, sizeof p);
    p.proto = FW_PROTO_TCP;
    p.src_ip = from_client ? IP(10,0,1,2) : IP(93,184,216,34);
    p.dst_ip = from_client ? IP(93,184,216,34) : IP(10,0,1,2);
    p.src_port = from_client ? sport : 80;
    p.dst_port = from_client ? 80 : sport;
    p.tcp_flags = flags;
    p.tcp_seq = seq;
    p.tcp_ack = ack;
    p.tcp_win = chance(70) ? 64240 : (uint16_t)rnd();
    p.tcp_wscale = (flags & TCP_SYN) && chance(50) ? (uint8_t)below(16) : TCP_NO_WSCALE;
    p.payload_len = len;
    p.ip_len = (uint16_t)(40 + len);
    return p;
}

/* Handshakes followed by segments that are mostly right and sometimes not
 * (off by a little, off by a lot, random flags), so the sequence checks see
 * both sides of every comparison. Phases A-C rarely hit an existing flow. */
static void phase_tcp_conversations(engine_t *e, unsigned long iters)
{
    static const uint8_t flags[] = { TCP_ACK, TCP_ACK | TCP_PSH, TCP_ACK | TCP_PSH,
                                     TCP_FIN | TCP_ACK, TCP_RST, TCP_RST | TCP_ACK, TCP_SYN,
                                     TCP_SYN | TCP_ACK };
    uint64_t now = SEC;
    for (unsigned long i = 0; i < iters; i++) {
        const uint16_t sport = (uint16_t)(1024 + i % 60000);
        uint32_t c = (uint32_t)rnd(), s = (uint32_t)rnd();     /* next seq of each side */
        now = advance(now);
        const pkt_t syn = conv_seg(true, sport, TCP_SYN, c, 0, 0);
        feed(e, &syn, DIR_IN, now);
        c++;
        const pkt_t synack = conv_seg(false, sport, TCP_SYN | TCP_ACK, s,
                                      chance(90) ? c : (uint32_t)rnd(), 0);
        feed(e, &synack, DIR_OUT, now);
        s++;
        for (int k = 0; k < 12; k++) {
            const bool cl = below(2);
            const uint16_t len = chance(50) ? 0 : (uint16_t)below(1461);
            uint32_t seq = cl ? c : s, ack = cl ? s : c;
            if (chance(15)) seq += (uint32_t)below(200000) - 100000;  /* near misses */
            if (chance(5))  seq = (uint32_t)rnd();                     /* blind guesses */
            if (chance(10)) ack += (uint32_t)below(200000) - 100000;
            const uint8_t fl = chance(85) ? flags[below(3)] : flags[below(sizeof flags)];
            const pkt_t p = conv_seg(cl, sport, fl, seq, ack, len);
            drop_reason_t why = DROP_REASON_COUNT;
            const verdict_t v = engine_decide(e, &p, cl ? DIR_IN : DIR_OUT, now, &why);
            if (v == VERDICT_ALLOW) {
                allowed_seen++;
                const uint32_t end = seq + len + (fl & TCP_SYN ? 1 : 0) + (fl & TCP_FIN ? 1 : 0);
                if (cl && (int32_t)(end - c) > 0) c = end;
                if (!cl && (int32_t)(end - s) > 0) s = end;
            } else {
                CHECK(v == VERDICT_DROP && why > DROP_NONE && why < DROP_REASON_COUNT);
                if (why > DROP_NONE && why < DROP_REASON_COUNT) drop_seen[why]++;
            }
        }
        if (chance(1)) engine_expire(e, now);
    }
}

/* ---- main ---------------------------------------------------------------- */

static unsigned long env_ul(const char *name, unsigned long dflt)
{
    const char *v = getenv(name);
    return v && *v ? strtoul(v, NULL, 0) : dflt;
}

static unsigned long kinds_seen(const unsigned long *a, int n)
{
    unsigned long k = 0;
    for (int i = 0; i < n; i++) k += a[i] != 0;
    return k;
}

/* ---- phase D: the rules-file parser ---------------------------------------- */

static const char *RULE_SEEDS[] = {
    "inside 10.0.1.0/24\n", "inside 192.168.0.0/16\n",
    "allow out tcp 10.0.1.0/24 any 80,443\n", "deny in udp any 10.0.1.3 53\n",
    "allow tcp from any port 1024-65535 to 10.0.0.0/8 port 22\n",
    "allow out icmp 10.0.1.0/24 any echo\n", "allow any from any to any\n",
    "deny out any 10.0.1.0/24 any\n", "# a comment\n\n", "allow in tcp any 10.0.1.3 22,8000-8100\n",
};

/* Random and mutated rule text must be refused with a message or accepted
 * cleanly, never crash or read out of bounds (the text is an exact-size heap
 * copy, so AddressSanitizer sees any over-read). */
static void phase_rules(unsigned long iters)
{
    const size_t nseed = sizeof RULE_SEEDS / sizeof *RULE_SEEDS;
    for (unsigned long i = 0; i < iters; i++) {
        char text[2048];
        size_t len = 0;
        for (unsigned k = 1 + below(6); k > 0; k--) {
            const char *seed = RULE_SEEDS[below((uint32_t)nseed)];
            const size_t sl = strlen(seed);
            if (len + sl < sizeof text - 1) { memcpy(text + len, seed, sl); len += sl; }
        }
        for (unsigned m = below(8); m > 0 && len; m--) {         /* mutate a few bytes */
            const size_t at = below((uint32_t)len);
            switch (below(4)) {
            case 0: text[at] = (char)(1 + below(255)); break;     /* any byte but NUL */
            case 1: text[at] = " \t\r\n#,-/:+x9"[below(13)]; break;
            case 2: if (len > 1) { memmove(text + at, text + at + 1, len - at - 1); len--; } break;
            default: if (len < sizeof text - 2) { memmove(text + at + 1, text + at, len - at); text[at] = "0:/,-"[below(5)]; len++; }
            }
        }
        if (chance(3)) {                                          /* occasionally a huge line */
            const size_t extra = sizeof text - 1 - len;
            memset(text + len, 'a' + (int)below(26), extra);
            len += extra;
        }
        char *exact = malloc(len + 1);
        memcpy(exact, text, len);
        exact[len] = '\0';
        char err[128] = "";
        rules_t *r = rules_parse_string(exact, err, sizeof err);
        CHECK(r != NULL || err[0] != '\0');                       /* a refusal always says why */
        if (r) {
            CHECK(r->n <= len);
            rules_free(r);
        }
        free(exact);
    }
}

static void fuzz_all(void)
{
    const unsigned long iters = env_ul("FUZZ_ITERS", DEFAULT_ITERS);
    /* a big table (the default) and a tiny one that is always full */
    engine_t *big = make(POLICY, 0);
    /* a 2-slot table with no caps and an allow-everything policy: flows that
     * start inside and go outside fill it at once and it stays under pressure */
    engine_t *small = make("inside 10.0.1.0/24\nallow any any any\nallow in any any any\n", SMALL_TABLE);
    /* the default policy with TCP sequence-number checks on, as tunwall runs */
    engine_t *strict = make(POLICY, 0);
    CHECK(big != NULL && small != NULL && strict != NULL);
    if (!big || !small || !strict) {
        engine_destroy(big); engine_destroy(small); engine_destroy(strict);
        return;
    }
    engine_set_tcp_window(strict, true);

    phase_random_bytes(big, iters);
    phase_mutated(big, iters);
    phase_random_pkts(big, iters);
    phase_random_bytes(small, iters / 4);
    phase_mutated(small, iters / 4);
    phase_random_pkts(small, iters / 4);
    phase_mutated(strict, iters / 2);
    phase_random_pkts(strict, iters / 2);
    phase_tcp_conversations(strict, iters / 10);
    phase_tcp_conversations(big, iters / 20);          /* checks off: same traffic */

    phase_rules(iters / 5);
    check_stats(big, FW_DEFAULT_MAX_FLOWS);
    check_stats(small, SMALL_TABLE);
    check_stats(strict, FW_DEFAULT_MAX_FLOWS);

    engine_stats_t s;
    engine_get_stats(small, &s);
    printf("   (small table: %llu flows created, %llu table-full drops)\n",
           (unsigned long long)s.flows_created,
           (unsigned long long)s.drops[DROP_TABLE_FULL]);
    engine_get_stats(strict, &s);
    printf("   (sequence checks: %llu out-of-window drops)\n",
           (unsigned long long)s.drops[DROP_TCP_WINDOW]);
    engine_destroy(big);
    engine_destroy(small);
    engine_destroy(strict);
}

/* The default run must actually reach the interesting code, or it proves
 * nothing. Only enforced for the default seed/iterations. */
static void check_coverage(void)
{
    CHECK(parse_seen[PARSE_OK] > 1000);
    CHECK(kinds_seen(parse_seen, PARSE_RESULT_COUNT) == PARSE_RESULT_COUNT);
    CHECK(allowed_seen > 1000);
    CHECK(kinds_seen(drop_seen, DROP_REASON_COUNT) >= 8);
    CHECK(drop_seen[DROP_TABLE_FULL] > 0);
    CHECK(drop_seen[DROP_BAD_SRC] > 0);
    CHECK(drop_seen[DROP_ICMP_ERR] > 0);
    CHECK(drop_seen[DROP_TCP_WINDOW] > 0);
    CHECK(drop_seen[DROP_APP_BLOCKED] > 0);
    (void)related_seen;
}

int main(void)
{
    rng = env_ul("FUZZ_SEED", DEFAULT_SEED);
    if (!rng) rng = DEFAULT_SEED;
    const int defaults = !getenv("FUZZ_SEED") && !getenv("FUZZ_ITERS");
    printf("   fuzz seed=0x%llx iters=%lu per phase\n",
           (unsigned long long)rng, env_ul("FUZZ_ITERS", DEFAULT_ITERS));

    RUN(fuzz_all);
    if (defaults) RUN(check_coverage);
    TEST_DONE();
}

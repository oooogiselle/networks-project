/*=============================================================================
 * File Name:   nat.h
 * Author:      Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 19, 2026
 *
 * Description: Source NAT with port translation (the requirements spec's
 *              first optional feature). Connections started from the inside
 *              leave with the firewall's outside address and a port the NAT
 *              picks; replies to that address and port are translated back
 *              to the inside host. Checksums are updated incrementally
 *              (RFC 1624) instead of being recomputed.
 =============================================================================*/

/*
 * HOW IT FITS THE FIREWALL
 *   The engine and the rules only ever see real inside addresses:
 *     - inside -> outside: engine_decide() first, then nat_outbound() rewrites
 *       the allowed packet's source on its way out;
 *     - outside -> inside: nat_inbound() rewrites a packet aimed at the NAT
 *       address back to the inside host, then it is parsed again and
 *       decided like any other reply.
 *   So anti-spoofing, flow tracking and rule matching are unchanged.
 *
 * MAPPINGS
 *   One mapping per connection (5-tuple): (proto, inside ip:port, remote
 *   ip:port) <-> NAT port. A reply must come from the same remote ip:port it
 *   was sent to (endpoint-dependent, "symmetric" NAT), which also means a
 *   mapping lives exactly as long as its engine flow: nat_sweep() frees the
 *   mappings whose flow is gone. For ICMP echo the "port" is the echo
 *   identifier. All mappings are allocated up front; nothing is allocated
 *   per packet.
 *
 * PORT FORWARDING (destination NAT)
 *   nat_set_forwards() installs the rules file's `forward` lines. A new
 *   connection from the outside to addr:ext_port (a TCP SYN or a UDP
 *   datagram) gets a mapping like any other, with ext_port as its NAT port
 *   and the forward's target as the inside endpoint, and is rewritten to the
 *   target. Its replies are then found by nat_outbound() exactly like replies
 *   of a source-NAT connection. External ports must lie outside the
 *   source-NAT port range, so the two never compete for a port.
 *
 * ICMP ERRORS
 *   An error about a translated connection is translated too: the outer
 *   address and the embedded original header (address, port, and their
 *   checksums), so traceroute and path-MTU discovery work through the NAT.
 *
 * Addresses and ports are in HOST byte order. Not thread safe.
 */
#ifndef FW_NAT_H
#define FW_NAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "engine.h"
#include "rules.h"

#define NAT_PORT_LO_DEFAULT 20000
#define NAT_PORT_HI_DEFAULT 59999
#define NAT_MAX_MAPPINGS    65536u

typedef enum {
    NAT_PASS = 0,      /* not a NAT packet: forward it unchanged            */
    NAT_TRANSLATED,    /* buf was rewritten (checksums included)            */
    NAT_NO_MAPPING,    /* aimed at the NAT address, no connection: drop     */
    NAT_FULL           /* no free port / mapping for a new connection: drop */
} nat_result_t;

typedef struct nat_stats {
    uint64_t mappings_active, mappings_created, mappings_freed;
    uint64_t translated_out, translated_in;   /* packets rewritten each way */
    uint64_t icmp_errors_translated;          /* of those, ICMP errors      */
    uint64_t drop_no_mapping, drop_full;
    uint64_t forwarded;                       /* port-forward connections made */
} nat_stats_t;

typedef struct nat nat_t;

/*
 * addr is the outside address connections leave with; NAT ports are picked
 * from [port_lo, port_hi] (each protocol has its own space). NULL on bad
 * arguments (addr 0, port_lo 0 or > port_hi) or out of memory.
 */
nat_t   *nat_create(uint32_t addr, uint16_t port_lo, uint16_t port_hi);
void     nat_destroy(nat_t *n);
uint32_t nat_addr(const nat_t *n);

/*
 * Translate a packet leaving through the outside interface. buf/p are the
 * raw packet and its successful parse (p is not updated). For TCP/UDP/echo:
 * an existing mapping is used; otherwise one is created if may_create
 * (the caller passes true only for connections started from the inside),
 * else NAT_PASS. For an ICMP error: translated if it is about a mapped
 * connection, else NAT_PASS. NAT_FULL if a mapping was needed but none free.
 */
nat_result_t nat_outbound(nat_t *n, uint8_t *buf, const pkt_t *p,
                          bool may_create, uint64_t now_ns);

/*
 * Translate a packet arriving from the outside. Packets not addressed to
 * the NAT address: NAT_PASS. Addressed to it with a matching mapping (same
 * remote endpoint): rewritten to the inside host, NAT_TRANSLATED. Otherwise
 * NAT_NO_MAPPING. buf must then be parsed again before engine_decide().
 */
nat_result_t nat_inbound(nat_t *n, uint8_t *buf, const pkt_t *p, uint64_t now_ns);

/*
 * Undo the mapping the last nat_inbound() call created for a forwarded
 * connection, if it did: call it when that packet is then not delivered (the
 * engine refused it, or the write failed), so nothing is left behind.
 */
void nat_undo_inbound(nat_t *n);

/*
 * Port forwarding. nat_check_forwards() refuses (false, err names the line)
 * a forward whose external port is in the source-NAT port range.
 * nat_set_forwards() replaces the forwards with a copy of f[0..nf): new
 * connections use the new list, existing ones keep their mappings. Call
 * check first; set cannot fail (nf > MAX_FORWARDS is truncated).
 */
bool nat_check_forwards(const nat_t *n, const forward_t *f, size_t nf,
                        char *err, size_t errlen);
void nat_set_forwards(nat_t *n, const forward_t *f, size_t nf);

/*
 * Free every mapping whose connection is over. alive(ud, t) is asked about
 * each mapping with t = the connection's tuple as the inside host sent it
 * (src = inside ip:port, dst = remote ip:port, proto); return false to free.
 * Returns the number freed. Call about once a second, after engine_expire().
 */
typedef bool (*nat_alive_fn)(void *ud, const pkt_t *tuple);
size_t nat_sweep(nat_t *n, nat_alive_fn alive, void *ud);

void nat_get_stats(const nat_t *n, nat_stats_t *out);
void nat_stats_print(const nat_t *n, FILE *out);

/*
 * RFC 1624 incremental checksum update, eqn. 3: HC' = ~(~HC + ~m + m'),
 * for a 16-bit word m -> m' (and a 32-bit value as two words). Exposed for
 * the unit tests.
 */
uint16_t nat_csum_adjust16(uint16_t csum, uint16_t old_word, uint16_t new_word);
uint16_t nat_csum_adjust32(uint16_t csum, uint32_t old_val, uint32_t new_val);

#endif /* FW_NAT_H */

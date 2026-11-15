/*=============================================================================
 * File Name:   siphash.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: SipHash-2-4, a keyed hash, used for the flow table so an
 *              attacker who does not know the key cannot choose flows that
 *              all land in one bucket.
 =============================================================================*/

#ifndef FW_SIPHASH_H
#define FW_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

/* SipHash-2-4 of len bytes at in, with a 128-bit key (Aumasson & Bernstein). */
uint64_t fw_siphash24(const uint8_t key[16], const uint8_t *in, size_t len);

#endif

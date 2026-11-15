/*=============================================================================
 * File Name:   tun_io.h
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Opening a Linux tun device: a network interface with no
 *              hardware, whose read() returns the raw IP packets the kernel
 *              routed to it and whose write() injects raw IP packets.
 =============================================================================*/

#ifndef FW_TUN_IO_H
#define FW_TUN_IO_H

#include <stddef.h>

/*
 * Open the existing tun device `name` (IFF_TUN | IFF_NO_PI: raw IPv4, no
 * packet-info header) and return its non-blocking file descriptor, or -1 with
 * a message in err.
 *
 * The device must already exist (scripts/netns.sh creates them as persistent
 * devices). That is deliberate: a device created on the fly would have no
 * routes or addresses, so the firewall would start and quietly pass nothing,
 * and a persistent device is what makes traffic stop when the firewall dies
 * (the kernel drops packets for a tun device nobody has open).
 */
int tun_open(const char *name, char *err, size_t errlen);

#endif

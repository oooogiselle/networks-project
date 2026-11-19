/* tun_io.h - attach to a persistent Linux TUN device (Linux only). */
#ifndef FW_TUN_IO_H
#define FW_TUN_IO_H

/*
 * Attach to the existing TUN device `name` (created by scripts/ns_setup.sh
 * with `ip tuntap add ... mode tun`), in raw-IP mode (IFF_NO_PI: each read()
 * returns exactly one IPv4/IPv6 packet, no extra header). The fd is
 * non-blocking. Returns the fd, or -1 after printing why to stderr.
 */
int tun_open(const char *name);

#endif

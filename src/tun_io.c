/*=============================================================================
 * File Name:   tun_io.c
 * Author:      Eva Tate and Giselle Wu, assisted by Claude Code
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Opens a Linux tun device (see tun_io.h). Linux only.
 =============================================================================*/

#include "tun_io.h"

#ifndef __linux__
#error "tun_io.c uses the Linux tun driver"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

static void fail(char *err, size_t errlen, const char *name, const char *what)
{
    if (err && errlen)
        snprintf(err, errlen, "%s: %s: %s", name, what, strerror(errno));
}

/* True if an interface called name exists in this network namespace. */
static bool device_exists(const char *name)
{
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return true;                    /* cannot tell: let TUNSETIFF decide */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    const bool found = ioctl(s, SIOCGIFINDEX, &ifr) == 0;
    close(s);
    return found;
}

int tun_open(const char *name, char *err, size_t errlen)
{
    if (!name || !*name || strlen(name) >= IFNAMSIZ) {
        if (err && errlen) snprintf(err, errlen, "bad tun device name");
        return -1;
    }
    if (!device_exists(name)) {
        if (err && errlen)
            snprintf(err, errlen, "%s: no such device in this network namespace "
                     "(create it first, e.g. with scripts/netns.sh up)", name);
        return -1;
    }

    const int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { fail(err, errlen, name, "cannot open /dev/net/tun"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        fail(err, errlen, name, "cannot attach (needs root)");
        close(fd);
        return -1;
    }
    return fd;
}

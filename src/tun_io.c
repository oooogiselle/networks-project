/* tun_io.c - attach to a persistent Linux TUN device. See tun_io.h. */
#include "tun_io.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tun_open(const char *name)
{
    if (strlen(name) >= IFNAMSIZ) {
        fprintf(stderr, "tun_open: interface name too long: %s\n", name);
        return -1;
    }

    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "tun_open: /dev/net/tun: %s (is the tun module "
                        "loaded? are you root?)\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    memcpy(ifr.ifr_name, name, strlen(name));

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        fprintf(stderr, "tun_open: attach %s: %s\n", name, strerror(e));
        if (e == EPERM)
            fprintf(stderr, "  hint: run as root\n");
        else if (e == EINVAL || e == EBUSY)
            fprintf(stderr, "  hint: %s exists with other flags, or another "
                            "tunwall is attached\n", name);
        fprintf(stderr, "  hint: run inside the firewall namespace "
                        "(sudo ip netns exec fw ./tunwall ...) after "
                        "sudo scripts/ns_setup.sh\n");
        close(fd);
        return -1;
    }

    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        fprintf(stderr, "tun_open: O_NONBLOCK on %s: %s\n", name,
                strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

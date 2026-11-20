#!/usr/bin/env python3
# ============================================================================
# File Name:   dns_forwarder.py
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: A tiny DNS relay for the demo topology. The example rules let
#              the inside use exactly one resolver, 10.0.2.2. This listens
#              there (inside the "outside" namespace) and forwards each query
#              to a real upstream resolver over the NAT path, so inside hosts
#              can resolve real names. Plain UDP only, one thread per query.
# Usage:       sudo ip netns exec outside python3 scripts/dns_forwarder.py \
#                  [bind-ip=10.0.2.2] [upstream-ip=1.1.1.1]
# ============================================================================
import socket
import sys
import threading

BIND = sys.argv[1] if len(sys.argv) > 1 else "10.0.2.2"
UPSTREAM = sys.argv[2] if len(sys.argv) > 2 else "1.1.1.1"


def answer(server, query, client):
    """Ask the upstream resolver (twice at most) and relay its reply."""
    for _ in range(2):
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(3)
        try:
            up.sendto(query, (UPSTREAM, 53))
            server.sendto(up.recv(4096), client)
            return
        except OSError:
            pass                      # timed out or unreachable: try once more
        finally:
            up.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((BIND, 53))
    print("dns_forwarder: %s:53 -> %s:53" % (BIND, UPSTREAM), file=sys.stderr, flush=True)
    while True:
        query, client = server.recvfrom(4096)
        threading.Thread(target=answer, args=(server, query, client), daemon=True).start()


if __name__ == "__main__":
    main()

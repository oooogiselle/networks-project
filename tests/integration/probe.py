#!/usr/bin/env python3
# ============================================================================
# File Name:   probe.py
# Author:      Eva Tate and Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Sends one TCP connect or UDP datagram and prints how the
#              network answered, so tests can tell a silent drop from a
#              refusal (RST / ICMP unreachable) from a success:
#                open | reply        the peer answered
#                refused             RST or ICMP port unreachable came back
#                unreachable         ICMP host/net unreachable or admin-prohibited
#                timeout             nothing came back (a silent drop)
# Usage: probe.py tcp <ip> <port> | probe.py udp <ip> <port>
# ============================================================================
import errno
import socket
import sys


def classify(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if getattr(exc, "errno", None) in (errno.EHOSTUNREACH, errno.ENETUNREACH,
                                       errno.EACCES, errno.EPERM):
        return "unreachable"
    return "error:%s" % exc


def main():
    kind, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    try:
        if kind == "tcp":
            s = socket.create_connection((ip, port), timeout=3)
            s.close()
            print("open")
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ip, port))  # connected socket: ICMP errors surface
            s.send(b"probe")
            s.recv(64)
            print("reply")
    except OSError as exc:
        print(classify(exc))


main()

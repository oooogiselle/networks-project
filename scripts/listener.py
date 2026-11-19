#!/usr/bin/env python3
"""listener.py ADDR PORT - accept TCP connections forever, send "hello\n",
close. Stands in for a real service (e.g. SSH) in the integration tests."""
import socket
import sys

addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
s.listen(64)
while True:
    conn, _ = s.accept()
    try:
        conn.sendall(b"hello\n")
    except OSError:
        pass
    conn.close()

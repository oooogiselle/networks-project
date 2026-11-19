#!/usr/bin/env python3
"""probe.py SRC DST PORT [TIMEOUT] - connect from SRC to DST:PORT and expect
the listener's "hello". Exit 0 on success, 1 on refusal/timeout/anything
else (prints the reason)."""
import socket
import sys

src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0
try:
    s = socket.create_connection((dst, port), timeout=timeout,
                                 source_address=(src, 0))
    data = s.recv(16)
    s.close()
except OSError as e:
    print(f"probe {src} -> {dst}:{port}: {e.__class__.__name__}: {e}")
    sys.exit(1)
if data != b"hello\n":
    print(f"probe {src} -> {dst}:{port}: unexpected reply {data!r}")
    sys.exit(1)
sys.exit(0)

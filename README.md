# Tunwall: a userspace stateful firewall

CS 60 final project (Giselle Wu, Eva Tate). A default-deny stateful IPv4
firewall written in C that sits between an inside and an outside network
using two Linux TUN devices. See `requirements-spec.pdf`.

## Layout

```
src/common.h   shared enums: dir, verdict, drop reasons, protocol/flag constants
src/packet.[ch] zero-copy IPv4/TCP/UDP/ICMP parser + RFC 1071 checksums
src/fw.h       decision engine interface (fw_decide, fw_sweep, stats)
tests/pktbuild.[ch] build valid test packets (correct checksums), then corrupt them
tests/unit/    dependency-free unit tests (test.h harness)
```

The core (`packet`, `rules`, `flow`, `tcp_fsm`, `fw`) is pure C with no I/O:
`fw_decide()` takes the current time as an argument, so all policy logic is
unit-testable on any machine. Only `src/tun.c` and `src/main.c` are Linux-specific.

## Build and test

```sh
make test          # unit tests (macOS or Linux)
make asan          # unit tests under AddressSanitizer + UBSan
make               # build ./tunwall (Linux only)
```

On macOS, use `make CC=clang asan`: Homebrew gcc has no ASan runtime.

## Adding a unit test suite

1. Create `tests/unit/test_<name>.c` with `TEST(...)` functions and a
   `void suite_<name>(void)` that calls `RUN(...)` on each.
2. Declare it in `tests/unit/suites.h` and call it from `tests/unit/test_main.c`.

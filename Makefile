# ============================================================================
# File Name:   Makefile
# Author:      Eva Tate and Giselle Wu, assisted by Claude Code
# Course:      CS60: Computer Networks
# Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
# Date:        November 15, 2026
#
# Description: Build, test, and AddressSanitizer targets for the firewall
#              library and its unit tests.
# ============================================================================

CC       ?= cc
CFLAGS   ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wshadow
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE

BUILD := build

# Objects and binaries are rebuilt whenever the compiler or its flags change
# (for example after `make asan`, which leaves sanitizer-instrumented objects
# that a plain `make tunwall` would otherwise silently link).
FLAGS_STAMP := $(BUILD)/.flags

# Firewall core library: packet parser + decision engine (flow table, TCP
# state, rules, engine, logging). tun I/O and main() link against this.
LIB_SRC := src/parser.c src/flowtable.c src/tcpstate.c src/rules.c \
           src/engine.c src/log.c src/fwalloc.c src/siphash.c src/forwarder.c
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/%.o)
LIB     := $(BUILD)/libfwengine.a

TESTS := test_parser test_flowtable test_tcpstate test_rules test_engine test_fuzz test_log test_alloc_fail test_forwarder
# tun_open() uses the Linux tun driver, so its tests only run on Linux.
ifeq ($(shell uname -s),Linux)
TESTS += test_tun_io
endif
TEST_BINS := $(TESTS:%=$(BUILD)/%)

.PHONY: all test asan clean tunwall
all: $(LIB)

.PHONY: FORCE
FORCE:
$(FLAGS_STAMP): FORCE | $(BUILD)
	@echo "$(CC) $(CPPFLAGS) $(CFLAGS)" | cmp -s - $@ || echo "$(CC) $(CPPFLAGS) $(CFLAGS)" > $@

$(BUILD)/%.o: src/%.c $(wildcard include/*.h) $(FLAGS_STAMP) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

# The firewall program itself (Linux only: it opens tun devices).
tunwall: $(BUILD)/tunwall
$(BUILD)/tunwall: src/main.c src/tun_io.c include/tun_io.h $(LIB) $(FLAGS_STAMP) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/tun_io.c $(LIB) -o $@

# The parser, engine and fuzz tests also need the test packet builder.
$(BUILD)/test_parser $(BUILD)/test_engine $(BUILD)/test_fuzz $(BUILD)/test_forwarder: $(BUILD)/%: tests/%.c tests/pktbuild.c tests/pktbuild.h tests/testutil.h $(LIB) $(FLAGS_STAMP)
	$(CC) $(CPPFLAGS) -Itests $(CFLAGS) tests/$*.c tests/pktbuild.c $(LIB) -o $@

$(BUILD)/test_tun_io: tests/test_tun_io.c src/tun_io.c include/tun_io.h tests/testutil.h $(FLAGS_STAMP) | $(BUILD)
	$(CC) $(CPPFLAGS) -Itests $(CFLAGS) tests/test_tun_io.c src/tun_io.c -o $@

$(BUILD)/test_%: tests/test_%.c tests/testutil.h $(LIB) $(FLAGS_STAMP)
	$(CC) $(CPPFLAGS) -Itests $(CFLAGS) $< $(LIB) -o $@

$(BUILD):
	mkdir -p $(BUILD)

test: $(TEST_BINS)
	@fail=0; for t in $(TEST_BINS); do echo "== $$t"; ./$$t || fail=1; done; \
	  if [ $$fail -ne 0 ]; then echo "SOME TESTS FAILED"; exit 1; fi; echo "ALL TESTS PASSED"

# Same tests under AddressSanitizer + UBSan.
# (On macOS use clang: `make CC=clang asan`. Homebrew gcc has no ASan runtime.)
asan:
	$(MAKE) clean
	$(MAKE) test CFLAGS="-std=c11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"

clean:
	rm -rf $(BUILD)

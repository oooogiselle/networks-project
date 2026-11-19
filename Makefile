CC       ?= cc
CFLAGS   ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wshadow
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE

BUILD := build

# Firewall core library: packet parser + decision engine (flow table, TCP
# state, rules, engine, logging) + the per-packet pipeline. Portable; the
# Linux-only tun I/O and main() link against this to make ./tunwall.
LIB_SRC := src/parser.c src/pipeline.c src/flowtable.c src/tcpstate.c \
           src/rules.c src/engine.c src/log.c
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/%.o)
LIB     := $(BUILD)/libfwengine.a

TESTS := test_parser test_pipeline test_flowtable test_tcpstate test_rules \
         test_engine
TEST_BINS := $(TESTS:%=$(BUILD)/%)

.PHONY: all test asan clean

# ./tunwall needs Linux (TUN devices); elsewhere `all` builds just the library.
ifeq ($(shell uname -s),Linux)
all: $(LIB) tunwall
else
all: $(LIB)
endif

tunwall: src/main.c src/tun_io.c $(wildcard include/*.h) $(LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/tun_io.c $(LIB) -o $@

$(BUILD)/%.o: src/%.c $(wildcard include/*.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

# Tests that build real wire packets also link the test packet builder.
$(BUILD)/test_parser $(BUILD)/test_pipeline: $(BUILD)/test_%: tests/test_%.c tests/pktbuild.c tests/pktbuild.h tests/testutil.h $(LIB)
	$(CC) $(CPPFLAGS) -Itests $(CFLAGS) $< tests/pktbuild.c $(LIB) -o $@

$(BUILD)/test_%: tests/test_%.c tests/testutil.h $(LIB)
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
	$(MAKE) test CFLAGS="-std=c11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -rf $(BUILD) tunwall

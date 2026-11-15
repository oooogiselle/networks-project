# Tunwall Makefile (works with GNU make 3.81+)
#
#   make           build ./tunwall (Linux only)
#   make test      build and run unit tests (any POSIX system)
#   make asan      unit tests under AddressSanitizer + UBSan
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Wshadow \
           -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes
SAN     := -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all

UNAME_S := $(shell uname -s)
BUILD   := build

# Portable core: everything in src/ except the Linux I/O shell.
IO_SRCS   := src/main.c src/tun.c
CORE_SRCS := $(filter-out $(IO_SRCS),$(wildcard src/*.c))
TEST_SRCS := $(wildcard tests/unit/*.c) $(wildcard tests/pktbuild.c)

.PHONY: all test asan clean

ifeq ($(UNAME_S),Linux)
ifneq ($(wildcard src/main.c),)
all: tunwall
else
all:
	@echo "src/main.c not written yet; nothing to build. Run 'make test'."
endif
else
all:
	@echo "tunwall needs Linux (TUN devices). On $(UNAME_S), run 'make test'."
endif

tunwall: $(CORE_SRCS) $(wildcard $(IO_SRCS)) $(wildcard src/*.h)
	$(CC) $(CFLAGS) -o $@ $(CORE_SRCS) $(wildcard $(IO_SRCS))

$(BUILD)/unit_tests: $(CORE_SRCS) $(TEST_SRCS) $(wildcard src/*.h tests/*.h tests/unit/*.h)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -Itests -o $@ $(CORE_SRCS) $(TEST_SRCS)

$(BUILD)/unit_tests_asan: $(CORE_SRCS) $(TEST_SRCS) $(wildcard src/*.h tests/*.h tests/unit/*.h)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -O1 $(SAN) -Isrc -Itests -o $@ $(CORE_SRCS) $(TEST_SRCS)

test: $(BUILD)/unit_tests
	./$(BUILD)/unit_tests

asan: $(BUILD)/unit_tests_asan
	./$(BUILD)/unit_tests_asan

clean:
	rm -rf $(BUILD) tunwall

# Build the bip388 C library + test runner.
#
#   make            # regenerate spec tables, build libbip388.a, link tests
#   make test       # build and run the test suite
#   make clean      # remove build artifacts
#   make gen        # regenerate the codegen output

CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter
CPPFLAGS += -Iinclude -Isrc -Isrc/gen

SRC_DIR := src
GEN_DIR := src/gen
TEST_DIR := tests
BUILD_DIR := build

LIB_SOURCES := \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/sha256.c \
	$(SRC_DIR)/base58.c \
	$(SRC_DIR)/xpub.c \
	$(SRC_DIR)/time_fmt.c \
	$(SRC_DIR)/descriptor.c \
	$(SRC_DIR)/keyinfo.c \
	$(SRC_DIR)/wallet_policy.c \
	$(SRC_DIR)/cleartext.c \
	$(GEN_DIR)/cleartext_gen.c

TEST_SOURCES := \
	$(TEST_DIR)/test_main.c \
	$(TEST_DIR)/test_time.c \
	$(TEST_DIR)/test_descriptor.c \
	$(TEST_DIR)/test_wallet_policy.c \
	$(TEST_DIR)/test_cleartext.c \
	$(GEN_DIR)/test_vectors_gen.c

LIB_OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(LIB_SOURCES))
TEST_OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TEST_SOURCES))

GEN_SOURCES := \
	$(GEN_DIR)/cleartext_gen.c \
	$(GEN_DIR)/test_vectors_gen.c \
	$(GEN_DIR)/test_vectors_gen.h

.PHONY: all test gen clean

all: $(BUILD_DIR)/libbip388.a $(BUILD_DIR)/test_runner

gen $(GEN_SOURCES):
	python3 tools/gen.py

$(BUILD_DIR)/%.o: %.c $(GEN_SOURCES)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/libbip388.a: $(LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BUILD_DIR)/test_runner: $(TEST_OBJECTS) $(BUILD_DIR)/libbip388.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_OBJECTS) -L$(BUILD_DIR) -lbip388

test: $(BUILD_DIR)/test_runner
	$(BUILD_DIR)/test_runner

clean:
	rm -rf $(BUILD_DIR)

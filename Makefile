# Native host unit tests for the hardware-independent artemisz_core library.
#
#   make test     build and run the suite (default)
#   make clean    remove build artifacts
#
# Requires only a C++11 compiler (clang++ or g++). No PlatformIO needed; the
# same sources also build under `pio test` on the ESP32 host environment.

CXX      ?= c++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wextra -Wpedantic
CORE_DIR := lib/artemisz_core
TEST_DIR := test
BUILD_DIR := .build

INCLUDES := -I$(CORE_DIR) -I$(TEST_DIR)

CORE_SRCS := $(wildcard $(CORE_DIR)/*.cpp)
TEST_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
SRCS := $(CORE_SRCS) $(TEST_SRCS)

BIN := $(BUILD_DIR)/artemisz_tests

.PHONY: test clean

test: $(BIN)
	@echo "=============================="
	@$(BIN)

$(BIN): $(SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRCS) -o $(BIN)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR)

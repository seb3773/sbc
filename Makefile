CC ?= gcc
CFLAGS ?= -O3 -flto -fomit-frame-pointer -Wall -Wextra -Isrc
LDFLAGS ?= -lm
BUILD_DIR ?= build
LINUX_DIR = $(BUILD_DIR)/linux
WIN64_DIR = $(BUILD_DIR)/win64

TARGET_LINUX = $(LINUX_DIR)/sbc
TARGET_WIN64 = $(WIN64_DIR)/sbc.exe
TARGET = $(TARGET_LINUX)

CROSS_WIN64_CC ?= x86_64-w64-mingw32-gcc

PREFIX ?= /usr/local
DESTDIR ?=

SRC_FILES = src/sbc.c
SRC_HEADERS = $(wildcard src/*.h)

.PHONY: all linux win64 all-platforms clean install uninstall test help debug

all: linux

linux: $(TARGET_LINUX)
	@ln -sf build/linux/sbc sbc

win64: $(TARGET_WIN64)

all-platforms: linux win64

$(LINUX_DIR):
	mkdir -p $(LINUX_DIR)

$(WIN64_DIR):
	mkdir -p $(WIN64_DIR)

$(TARGET_LINUX): $(SRC_FILES) $(SRC_HEADERS) | $(LINUX_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS)
	@ln -sf linux/sbc $(BUILD_DIR)/sbc
	@ln -sf build/linux/sbc sbc

$(TARGET_WIN64): $(SRC_FILES) $(SRC_HEADERS) | $(WIN64_DIR)
	$(CROSS_WIN64_CC) $(CFLAGS) -static -o $@ $(SRC_FILES) $(LDFLAGS)

debug: CFLAGS = -g -O0 -Wall -Wextra -Isrc
debug: clean $(TARGET_LINUX)
	@ln -sf build/linux/sbc sbc

test: $(TARGET_LINUX)
	@ln -sf build/linux/sbc sbc
	@echo "=== Running internal self-tests ==="
	./$(TARGET_LINUX) --selftest
	@echo "=== Running decompression verification on reference corpus ==="
	python3 tests/verify_all.py ./$(TARGET_LINUX)
	@echo "=== Running bit-exact encoder parity on standard corpus ==="
	python3 tests/vendor_parity.py
	@echo "All tests passed successfully."

clean:
	rm -rf $(BUILD_DIR) sbc

install: $(TARGET_LINUX)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET_LINUX) $(DESTDIR)$(PREFIX)/bin/sbc

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sbc

help:
	@echo "Available build targets:"
	@echo "  make linux         - Build native Linux binary (default)"
	@echo "  make win64         - Cross-compile static Windows 64-bit binary (MinGW)"
	@echo "  make all-platforms - Build both Linux and Windows 64-bit binaries"
	@echo "  make debug         - Build Linux binary with debug symbols (-g -O0)"
	@echo "  make test          - Run self-test and verification test suite"
	@echo "  make install       - Install sbc to $(DESTDIR)$(PREFIX)/bin"
	@echo "  make uninstall     - Remove sbc from $(DESTDIR)$(PREFIX)/bin"
	@echo "  make clean         - Remove build artifacts"

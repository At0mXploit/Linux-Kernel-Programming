# Makefile for Rootkit Detection
#
# All programs are DEFENSIVE DETECTION TOOLS.
# No offensive tools are included.
#
# For maximum security, compile with -static to produce statically linked
# binaries that are immune to LD_PRELOAD-based rootkit interference.
#
# Usage:
#   make              - Build all tools (dynamically linked)
#   make static       - Build all tools (statically linked - recommended)
#   make clean        - Remove all compiled binaries
#   make help         - Show this help
#
# Note: Static compilation requires glibc-static or musl-tools.
#       If static linking fails, fall back to dynamic: make all

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -D_GNU_SOURCE
CFLAGS_STATIC = $(CFLAGS) -static

# List of all detection tools
TARGETS = detect_preload \
          detect_hidden_procs \
          detect_hidden_modules \
          syscall_table_checker \
          proc_integrity \
          network_anomaly \
          file_integrity_checker \
          module_info_dump \
          boot_verify

# Default target: build all dynamically linked
all: $(TARGETS)
	@echo ""
	@echo "================================================"
	@echo "  All rootkit detection tools built successfully"
	@echo "================================================"
	@echo ""
	@echo "  Tools built (dynamic linking):"
	@for t in $(TARGETS); do echo "    ./$$t"; done
	@echo ""
	@echo "  NOTE: For rootkit-resistant builds, use: make static"
	@echo "  Static builds are immune to LD_PRELOAD interference."
	@echo ""

# Static target: build all statically linked (recommended for security)
static: CFLAGS = $(CFLAGS_STATIC)
static: clean $(TARGETS)
	@echo ""
	@echo "================================================"
	@echo "  All tools built with STATIC linking"
	@echo "  These binaries are immune to LD_PRELOAD rootkits"
	@echo "================================================"
	@echo ""

# Individual build rules
detect_preload: detect_preload.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Detects LD_PRELOAD-based library injection"

detect_hidden_procs: detect_hidden_procs.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Detects hidden processes via cross-view analysis"

detect_hidden_modules: detect_hidden_modules.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Detects hidden kernel modules"

syscall_table_checker: syscall_table_checker.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Checks for syscall table anomalies"

proc_integrity: proc_integrity.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Verifies /proc filesystem integrity"

network_anomaly: network_anomaly.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Detects hidden network connections"

file_integrity_checker: file_integrity_checker.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - SHA-256 file integrity monitoring"

module_info_dump: module_info_dump.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Dumps detailed kernel module information"

boot_verify: boot_verify.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  Built: $@ - Checks Secure Boot and boot integrity"

# Clean all binaries
clean:
	rm -f $(TARGETS)
	@echo "  Cleaned all binaries"

# Help target
help:
	@echo ""
	@echo "Rootkit Detection - Build System"
	@echo "============================================================"
	@echo ""
	@echo "Available targets:"
	@echo "  make              Build all tools (dynamic linking)"
	@echo "  make static       Build all tools (static linking - RECOMMENDED)"
	@echo "  make clean        Remove all compiled binaries"
	@echo "  make help         Show this help message"
	@echo ""
	@echo "Individual tools:"
	@echo "  detect_preload         - Detect LD_PRELOAD abuse"
	@echo "  detect_hidden_procs    - Find hidden processes"
	@echo "  detect_hidden_modules  - Find hidden kernel modules"
	@echo "  syscall_table_checker  - Check syscall table integrity"
	@echo "  proc_integrity         - Verify /proc data consistency"
	@echo "  network_anomaly        - Detect hidden network connections"
	@echo "  file_integrity_checker - SHA-256 file integrity monitoring"
	@echo "  module_info_dump       - Detailed kernel module analysis"
	@echo "  boot_verify            - Check Secure Boot configuration"
	@echo ""
	@echo "Usage notes:"
	@echo "  - Most tools require root (sudo) for full functionality"
	@echo "  - Static linking (-static) is recommended for security"
	@echo "  - All tools are DEFENSIVE - no offensive capabilities"
	@echo ""

.PHONY: all static clean help

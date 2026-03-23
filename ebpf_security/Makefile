# =============================================================================
# Makefile for eBPF Security
# =============================================================================
#
# This Makefile builds all defensive security tools in the eBPF security category.
# All tools are focused on DETECTION and MONITORING, not offensive capability.
#
# PREREQUISITES:
#   - GCC (build-essential)
#   - clang/llvm (for BPF compilation)
#   - libbpf-dev (for BPF userspace library)
#   - libelf-dev (ELF parsing)
#   - libssl-dev (OpenSSL for hashing) [optional]
#   - linux-headers (kernel headers)
#
# INSTALL DEPENDENCIES (Debian/Ubuntu):
#   sudo apt install build-essential clang llvm libbpf-dev libelf-dev \
#                    libssl-dev linux-headers-$(uname -r) bpfcc-tools
#
# USAGE:
#   make all              - Build all userspace tools
#   make bpf              - Build BPF kernel-side programs
#   make clean            - Remove build artifacts
#   make help             - Show this help
#
# =============================================================================

# Compiler settings
CC       = gcc
CLANG    = clang
CFLAGS   = -O2 -Wall -Wextra -g
LDFLAGS  =

# BPF compilation settings
BPF_CFLAGS = -O2 -target bpf -g
ARCH       = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel headers
KERNEL_VERSION = $(shell uname -r)
KERNEL_HEADERS = /usr/src/linux-headers-$(KERNEL_VERSION)

# libbpf include paths
LIBBPF_INCLUDES = -I/usr/include
BPF_INCLUDES    = $(LIBBPF_INCLUDES) -I$(KERNEL_HEADERS)/include

# Check for optional dependencies
HAS_OPENSSL := $(shell pkg-config --exists openssl 2>/dev/null && echo yes || echo no)
HAS_LIBBPF  := $(shell pkg-config --exists libbpf 2>/dev/null && echo yes || echo no)
HAS_CLANG   := $(shell command -v $(CLANG) 2>/dev/null && echo yes || echo no)

# =============================================================================
# Targets
# =============================================================================

# Default: build all userspace tools
.PHONY: all
all: userspace

# Userspace tools (always buildable)
.PHONY: userspace
userspace: bpf_prog_lister bpf_map_inspector detect_bpf_hooks \
           ebpf_baseline ringbuf_monitor

# Tools requiring OpenSSL
ifeq ($(HAS_OPENSSL),yes)
userspace: supply_chain_verify
else
userspace: supply_chain_verify_noopenssl
endif

# BPF kernel-side programs (require clang)
.PHONY: bpf
ifeq ($(HAS_CLANG),yes)
bpf: kfunc_monitor.bpf.o
else
bpf:
	@echo "WARNING: clang not found. Cannot compile BPF programs."
	@echo "Install with: sudo apt install clang llvm"
endif

# =============================================================================
# Userspace Tool Compilation
# =============================================================================

# bpf_prog_lister - List all loaded BPF programs
bpf_prog_lister: bpf_prog_lister.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@ (BPF program enumerator)"

# bpf_map_inspector - Inspect BPF map contents
bpf_map_inspector: bpf_map_inspector.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@ (BPF map inspector)"

# detect_bpf_hooks - Detect BPF hooks on sensitive functions
detect_bpf_hooks: detect_bpf_hooks.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@ (BPF hook detector)"

# supply_chain_verify - With OpenSSL support
supply_chain_verify: supply_chain_verify.c
	$(CC) $(CFLAGS) -o $@ $< $(shell pkg-config --cflags --libs openssl)
	@echo "Built: $@ (with OpenSSL hashing)"

# supply_chain_verify - Without OpenSSL (fallback)
supply_chain_verify_noopenssl: supply_chain_verify.c
	$(CC) $(CFLAGS) -DNO_OPENSSL -o supply_chain_verify $<
	@echo "Built: supply_chain_verify (without OpenSSL, using sha256sum fallback)"

# ebpf_baseline - BPF program baseline and verification
ebpf_baseline: ebpf_baseline.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@ (BPF baseline manager)"

# ringbuf_monitor - Ring buffer event consumer
ringbuf_monitor: ringbuf_monitor.c
ifeq ($(HAS_LIBBPF),yes)
	$(CC) $(CFLAGS) -DHAS_LIBBPF -o $@ $< -lbpf -lelf -lz
	@echo "Built: $@ (with libbpf support)"
else
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@ (demo mode only - install libbpf-dev for full support)"
endif

# =============================================================================
# BPF Program Compilation
# =============================================================================

# kfunc_monitor.bpf.o - Kernel-side BPF security monitor
kfunc_monitor.bpf.o: kfunc_monitor.bpf.c
	$(CLANG) $(BPF_CFLAGS) \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_INCLUDES) \
		-c $< -o $@
	@echo "Built: $@ (BPF kernel-side program)"

# Generate skeleton header (for advanced users with bpftool)
.PHONY: skeleton
skeleton: kfunc_monitor.bpf.o
	@if command -v bpftool > /dev/null 2>&1; then \
		bpftool gen skeleton $< > kfunc_monitor.skel.h; \
		echo "Generated: kfunc_monitor.skel.h"; \
	else \
		echo "WARNING: bpftool not found. Cannot generate skeleton."; \
		echo "Install with: sudo apt install linux-tools-$(KERNEL_VERSION)"; \
	fi

# =============================================================================
# Script Permissions
# =============================================================================

.PHONY: scripts
scripts:
	chmod +x persistence_scanner.sh
	chmod +x ebpf_monitor.py
	@echo "Scripts made executable"

# =============================================================================
# Utility Targets
# =============================================================================

.PHONY: clean
clean:
	rm -f bpf_prog_lister bpf_map_inspector detect_bpf_hooks
	rm -f supply_chain_verify ebpf_baseline ringbuf_monitor
	rm -f kfunc_monitor.bpf.o kfunc_monitor.skel.h
	rm -f *.o
	@echo "Cleaned build artifacts"

.PHONY: check-deps
check-deps:
	@echo "Checking build dependencies..."
	@echo ""
	@echo "  GCC:        $(shell $(CC) --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
	@echo "  Clang:      $(shell $(CLANG) --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
	@echo "  OpenSSL:    $(HAS_OPENSSL)"
	@echo "  libbpf:     $(HAS_LIBBPF)"
	@echo "  bpftool:    $(shell command -v bpftool 2>/dev/null || echo 'NOT FOUND')"
	@echo "  Kernel:     $(KERNEL_VERSION)"
	@echo "  Headers:    $(shell test -d $(KERNEL_HEADERS) && echo 'Found' || echo 'NOT FOUND')"
	@echo ""
	@echo "To install all dependencies (Debian/Ubuntu):"
	@echo "  sudo apt install build-essential clang llvm libbpf-dev \\"
	@echo "    libelf-dev libssl-dev linux-headers-\$$(uname -r) \\"
	@echo "    linux-tools-\$$(uname -r) bpfcc-tools python3-bpfcc"

.PHONY: help
help:
	@echo "============================================================"
	@echo "  eBPF Security Tools"
	@echo "============================================================"
	@echo ""
	@echo "  Targets:"
	@echo "    make all           Build all userspace tools"
	@echo "    make bpf           Build BPF kernel-side programs"
	@echo "    make scripts       Make scripts executable"
	@echo "    make skeleton      Generate BPF skeleton header"
	@echo "    make check-deps    Check build dependencies"
	@echo "    make clean         Remove build artifacts"
	@echo "    make help          Show this help"
	@echo ""
	@echo "  Individual tools:"
	@echo "    bpf_prog_lister    List all loaded BPF programs"
	@echo "    bpf_map_inspector  Inspect BPF maps and contents"
	@echo "    detect_bpf_hooks   Detect BPF hooks on sensitive functions"
	@echo "    supply_chain_verify  Verify kernel module signatures"
	@echo "    ebpf_baseline      BPF program baseline management"
	@echo "    ringbuf_monitor    Ring buffer security event consumer"
	@echo ""
	@echo "  Scripts (no compilation needed):"
	@echo "    ebpf_monitor.py       Python BPF monitor (requires BCC)"
	@echo "    persistence_scanner.sh  Persistence mechanism scanner"
	@echo ""
	@echo "  All tools are DEFENSIVE and require root privileges."
	@echo "============================================================"

# =============================================================================
# Test target (run basic sanity checks)
# =============================================================================

.PHONY: test
test: all scripts
	@echo ""
	@echo "Running basic sanity checks..."
	@echo ""
	@echo "1. bpf_prog_lister:"
	@./bpf_prog_lister -h 2>&1 | head -3 || true
	@echo ""
	@echo "2. bpf_map_inspector:"
	@./bpf_map_inspector -h 2>&1 | head -3 || true
	@echo ""
	@echo "3. detect_bpf_hooks:"
	@./detect_bpf_hooks -h 2>&1 | head -3 || true
	@echo ""
	@echo "4. ebpf_baseline:"
	@./ebpf_baseline --help 2>&1 | head -3 || true
	@echo ""
	@echo "5. ringbuf_monitor (demo):"
	@timeout 3 ./ringbuf_monitor -d 2>&1 | head -10 || true
	@echo ""
	@echo "6. persistence_scanner.sh:"
	@bash persistence_scanner.sh -h 2>&1 | head -3 || true
	@echo ""
	@echo "Sanity checks complete."

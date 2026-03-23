# Makefile for Kernel Subsystems
#
# This Makefile builds:
#   - Kernel modules: simple_fs, netfilter_hook, kprobe_example,
#                     kretprobe_example, skb_parser
#   - Userspace programs: lsm_check, vfs_walker
#   - eBPF programs: ebpf_hello.bpf.o and ebpf_hello (loader)
#
# Usage:
#   make              - Build all targets
#   make modules      - Build only kernel modules
#   make userspace    - Build only userspace programs
#   make ebpf         - Build only eBPF programs
#   make clean        - Remove all generated files
#
# Prerequisites:
#   - Kernel headers: apt install linux-headers-$(uname -r)
#   - Build tools: apt install build-essential
#   - For eBPF: apt install clang llvm libbpf-dev bpftool
#   - For libbpf loader: apt install libelf-dev zlib1g-dev
#

# ──────────────── Configuration ──────────────────

# Detect kernel version and headers
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

# Compilers
CC       = gcc
CLANG    = clang
LLC      = llc
BPFTOOL  = bpftool

# Flags
CFLAGS   = -O2 -Wall -Wextra -g
LDFLAGS  =

# eBPF compilation flags
BPF_CFLAGS = -target bpf -O2 -g -Wall

# Detect architecture for eBPF
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
endif

# ──────────────── Kernel Module Objects ──────────────────

# List of kernel modules to build
obj-m += simple_fs.o
obj-m += netfilter_hook.o
obj-m += kprobe_example.o
obj-m += kretprobe_example.o
obj-m += skb_parser.o

# ──────────────── Userspace Targets ──────────────────

USERSPACE_TARGETS = lsm_check vfs_walker

# eBPF Targets
BPF_TARGETS = ebpf_hello.bpf.o
BPF_LOADER  = ebpf_hello

# ──────────────── Top-level Targets ──────────────────

.PHONY: all modules userspace ebpf clean help

all: modules userspace ebpf
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║        Kernel Subsystems - Build Complete               ║"
	@echo "╠══════════════════════════════════════════════════════════╣"
	@echo "║                                                          ║"
	@echo "║   Kernel Modules (.ko):                                 ║"
	@echo "║     simple_fs.ko        - Minimal in-memory filesystem  ║"
	@echo "║     netfilter_hook.ko   - Netfilter packet logger       ║"
	@echo "║     kprobe_example.ko   - Kprobe on do_sys_openat2     ║"
	@echo "║     kretprobe_example.ko- Kretprobe on vfs_read        ║"
	@echo "║     skb_parser.ko       - sk_buff packet inspector     ║"
	@echo "║                                                          ║"
	@echo "║   Userspace Programs:                                   ║"
	@echo "║     lsm_check           - LSM status checker            ║"
	@echo "║     vfs_walker           - VFS fd table walker          ║"
	@echo "║                                                          ║"
	@echo "║   eBPF Programs:                                        ║"
	@echo "║     ebpf_hello.bpf.o    - BPF syscall tracer           ║"
	@echo "║     ebpf_hello          - Userspace BPF loader         ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""

# ──────────────── Kernel Modules ──────────────────

modules:
	@echo "[*] Building kernel modules..."
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) modules; \
	else \
		echo "WARNING: Kernel headers not found at $(KDIR)"; \
		echo "Install with: apt install linux-headers-$(KVER)"; \
		echo "Skipping kernel module build."; \
	fi

# ──────────────── Userspace Programs ──────────────────

userspace: $(USERSPACE_TARGETS)
	@echo "[*] Userspace programs built successfully."

lsm_check: lsm_check.c
	@echo "[CC] $@"
	$(CC) $(CFLAGS) -o $@ $<

vfs_walker: vfs_walker.c
	@echo "[CC] $@"
	$(CC) $(CFLAGS) -o $@ $<

# ──────────────── eBPF Programs ──────────────────

ebpf: $(BPF_TARGETS) $(BPF_LOADER)
	@echo "[*] eBPF programs built successfully."

# Generate vmlinux.h from BTF (if available)
vmlinux.h:
	@echo "[BTF] Generating vmlinux.h..."
	@if command -v $(BPFTOOL) >/dev/null 2>&1 && \
	    [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
		echo "  Generated vmlinux.h from kernel BTF"; \
	else \
		echo "  WARNING: bpftool or /sys/kernel/btf/vmlinux not available"; \
		echo "  Using minimal type definitions in ebpf_hello.bpf.c"; \
		touch $@; \
	fi

# Compile BPF program
ebpf_hello.bpf.o: ebpf_hello.bpf.c
	@echo "[BPF] $@"
	@if command -v $(CLANG) >/dev/null 2>&1; then \
		$(CLANG) $(BPF_CFLAGS) -c $< -o $@; \
	else \
		echo "WARNING: clang not found. Cannot compile BPF program."; \
		echo "Install with: apt install clang"; \
	fi

# Compile BPF userspace loader
ebpf_hello: ebpf_hello.c
	@echo "[CC] $@ (libbpf loader)"
	@if pkg-config --exists libbpf 2>/dev/null; then \
		$(CC) $(CFLAGS) -o $@ $< $$(pkg-config --cflags --libs libbpf) -lelf -lz; \
	elif [ -f /usr/include/bpf/libbpf.h ]; then \
		$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz; \
	else \
		echo "WARNING: libbpf not found. Cannot compile BPF loader."; \
		echo "Install with: apt install libbpf-dev libelf-dev zlib1g-dev"; \
	fi

# ──────────────── Clean ──────────────────

clean:
	@echo "[*] Cleaning build artifacts..."
	@# Clean kernel module artifacts
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true; \
	fi
	@# Clean userspace programs
	rm -f $(USERSPACE_TARGETS)
	@# Clean eBPF artifacts
	rm -f $(BPF_TARGETS) $(BPF_LOADER) vmlinux.h
	@# Clean misc artifacts
	rm -f *.o *.ko *.mod *.mod.c *.mod.o *.symvers *.order .*.cmd
	rm -rf .tmp_versions
	@echo "[*] Clean complete."

# ──────────────── Help ──────────────────

help:
	@echo "Kernel Subsystems - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (default)"
	@echo "  modules    - Build kernel modules only"
	@echo "  userspace  - Build userspace programs only"
	@echo "  ebpf       - Build eBPF programs only"
	@echo "  clean      - Remove all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Individual targets:"
	@echo "  lsm_check           - LSM status checker (userspace)"
	@echo "  vfs_walker           - VFS fd walker (userspace)"
	@echo "  ebpf_hello.bpf.o    - eBPF program (BPF bytecode)"
	@echo "  ebpf_hello          - eBPF loader (userspace)"
	@echo ""
	@echo "Kernel module loading (requires root):"
	@echo "  sudo insmod simple_fs.ko"
	@echo "  sudo insmod netfilter_hook.ko"
	@echo "  sudo insmod kprobe_example.ko"
	@echo "  sudo insmod kretprobe_example.ko"
	@echo "  sudo insmod skb_parser.ko"
	@echo ""
	@echo "Prerequisites:"
	@echo "  Kernel modules: linux-headers-$$(uname -r) build-essential"
	@echo "  eBPF programs:  clang llvm libbpf-dev bpftool"
	@echo "  eBPF loader:    libelf-dev zlib1g-dev"

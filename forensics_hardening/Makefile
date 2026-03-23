#
# Makefile for Forensics and Hardening
#
# Build all C programs for the detection and hardening toolkit.
#
# Usage:
#   make              - Build all programs
#   make clean        - Remove all built binaries
#   make install      - Install to /usr/local/bin (requires root)
#   make <target>     - Build a specific program
#
# Programs:
#   rootkit_detector     - Comprehensive rootkit detection tool
#   kernel_integrity_check - Kernel integrity verification
#   module_analyzer      - Kernel module analysis tool
#   bpf_auditor          - BPF program audit tool
#   memory_scanner       - Memory forensics demonstrator
#   baseline_creator     - System security baseline generator
#

CC        = gcc
CFLAGS    = -O2 -Wall -Wextra -Wpedantic -D_GNU_SOURCE
LDFLAGS   =

# Optional: link with OpenSSL for SHA-256 support
# Uncomment the following to enable OpenSSL:
# CFLAGS += -DUSE_OPENSSL
# LDFLAGS += -lcrypto

# All C programs
PROGRAMS  = rootkit_detector \
            kernel_integrity_check \
            module_analyzer \
            bpf_auditor \
            memory_scanner \
            baseline_creator

# Shell scripts (no compilation needed, but included for reference)
SCRIPTS   = ima_policy_gen.sh \
            sysctl_hardening.sh \
            audit_config.sh \
            hardening_verifier.sh

INSTALL_DIR = /usr/local/bin

# ── Targets ─────────────────────────────────────────────────────

.PHONY: all clean install scripts help

all: $(PROGRAMS) scripts
	@echo ""
	@echo "============================================================"
	@echo "  Forensics and Hardening Build Complete"
	@echo "============================================================"
	@echo ""
	@echo "  C Programs built:"
	@for prog in $(PROGRAMS); do echo "    ./$$prog"; done
	@echo ""
	@echo "  Shell scripts:"
	@for script in $(SCRIPTS); do echo "    ./$$script"; done
	@echo ""
	@echo "  Most tools require root privileges to run."
	@echo "  Run 'make install' to install to $(INSTALL_DIR)"
	@echo "============================================================"

# ── Individual program targets ──────────────────────────────────

rootkit_detector: rootkit_detector.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

kernel_integrity_check: kernel_integrity_check.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

module_analyzer: module_analyzer.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

bpf_auditor: bpf_auditor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

memory_scanner: memory_scanner.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

baseline_creator: baseline_creator.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@"

# ── Shell scripts ───────────────────────────────────────────────

scripts:
	@chmod +x $(SCRIPTS) 2>/dev/null || true
	@echo "  Shell scripts marked executable"

# ── Installation ────────────────────────────────────────────────

install: all
	@echo "Installing to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@for prog in $(PROGRAMS); do \
		install -m 0755 $$prog $(INSTALL_DIR)/$$prog; \
		echo "  Installed: $(INSTALL_DIR)/$$prog"; \
	done
	@for script in $(SCRIPTS); do \
		install -m 0755 $$script $(INSTALL_DIR)/$$script; \
		echo "  Installed: $(INSTALL_DIR)/$$script"; \
	done
	@echo "Installation complete."

uninstall:
	@echo "Removing from $(INSTALL_DIR)..."
	@for prog in $(PROGRAMS); do \
		rm -f $(INSTALL_DIR)/$$prog; \
	done
	@for script in $(SCRIPTS); do \
		rm -f $(INSTALL_DIR)/$$script; \
	done
	@echo "Uninstallation complete."

# ── Cleanup ─────────────────────────────────────────────────────

clean:
	rm -f $(PROGRAMS)
	rm -f *.o
	@echo "  Cleaned build artifacts"

# ── Help ────────────────────────────────────────────────────────

help:
	@echo "Forensics and Hardening - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build all programs (default)"
	@echo "  clean     - Remove built binaries"
	@echo "  install   - Install to $(INSTALL_DIR) (requires root)"
	@echo "  uninstall - Remove from $(INSTALL_DIR)"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Individual programs:"
	@echo "  rootkit_detector       - Multi-layer rootkit detection"
	@echo "  kernel_integrity_check - Kernel code integrity verification"
	@echo "  module_analyzer        - Kernel module analysis and hidden detection"
	@echo "  bpf_auditor            - eBPF program and map enumeration"
	@echo "  memory_scanner         - Memory forensics via /proc/kcore"
	@echo "  baseline_creator       - System security baseline creation/verification"
	@echo ""
	@echo "Shell scripts (no compilation):"
	@echo "  ima_policy_gen.sh      - IMA policy rule generator"
	@echo "  sysctl_hardening.sh    - Sysctl security hardening"
	@echo "  audit_config.sh        - auditd security rule deployment"
	@echo "  hardening_verifier.sh  - CIS-inspired hardening verification"
	@echo ""
	@echo "For OpenSSL SHA-256 support, uncomment the CFLAGS/LDFLAGS"
	@echo "lines in the Makefile and rebuild."

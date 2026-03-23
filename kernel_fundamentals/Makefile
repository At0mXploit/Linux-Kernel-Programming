# Makefile for Kernel Fundamentals
#
# This Makefile compiles all userspace programs in the
# kernel fundamentals category.
#
# Usage:
#   make              - Build all programs
#   make <target>     - Build a specific program
#   make clean        - Remove all compiled binaries
#   make run-all      - Build and run all programs sequentially
#   make help         - Show available targets
#
# Requirements:
#   - GCC (or compatible C compiler)
#   - GNU Make
#   - Linux headers (for syscall numbers, ptrace, etc.)
#   - pthreads library

# Compiler and flags
CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=gnu11 -O2 -g
LDFLAGS =

# Individual program targets
TARGETS = syscall_tracer \
          process_info \
          memory_layout \
          context_switch_measure \
          scheduler_test \
          page_fault_counter \
          custom_syscall_user \
          boot_info

# Programs that require specific libraries
process_info_LIBS    = -lpthread
scheduler_test_LIBS  = -lpthread

# Default target: build everything
.PHONY: all
all: $(TARGETS)
	@echo ""
	@echo "=== All kernel fundamentals programs built successfully ==="
	@echo ""
	@echo "Programs:"
	@for t in $(TARGETS); do echo "  ./$$t"; done
	@echo ""

# === Individual build rules ===

# Lesson 4: Syscall tracer using ptrace
syscall_tracer: syscall_tracer.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (trace syscalls of a child process)"

# Lesson 5: Process information from /proc
process_info: process_info.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(process_info_LIBS)
	@echo "  Built: $@ (display process info from /proc)"

# Lesson 3: Virtual memory layout demonstration
memory_layout: memory_layout.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (show virtual memory layout)"

# Lesson 6: Context switch time measurement
context_switch_measure: context_switch_measure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (benchmark context switch latency)"

# Lesson 6: Scheduler policy demonstration
scheduler_test: scheduler_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(scheduler_test_LIBS)
	@echo "  Built: $@ (test different scheduling policies)"

# Lesson 7: Page fault counter and analyzer
page_fault_counter: page_fault_counter.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (monitor and count page faults)"

# Lesson 4: Direct syscall invocation
custom_syscall_user: custom_syscall_user.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (invoke syscalls directly)"

# Lesson 2: Boot information reader
boot_info: boot_info.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built: $@ (display boot information)"

# === Utility targets ===

# Clean all built binaries
.PHONY: clean
clean:
	rm -f $(TARGETS)
	rm -f *.o
	@echo "Cleaned all binaries."

# Run all programs (some may need root)
.PHONY: run-all
run-all: all
	@echo ""
	@echo "=== Running all kernel fundamentals programs ==="
	@echo ""
	@echo ">>> boot_info"
	@echo "---"
	-./boot_info
	@echo ""
	@echo ">>> memory_layout"
	@echo "---"
	-./memory_layout < /dev/null
	@echo ""
	@echo ">>> process_info"
	@echo "---"
	-./process_info
	@echo ""
	@echo ">>> custom_syscall_user"
	@echo "---"
	-./custom_syscall_user
	@echo ""
	@echo ">>> page_fault_counter (16 MB)"
	@echo "---"
	-./page_fault_counter 16
	@echo ""
	@echo ">>> context_switch_measure (10000 iterations)"
	@echo "---"
	-./context_switch_measure 10000
	@echo ""
	@echo ">>> syscall_tracer (trace /bin/echo)"
	@echo "---"
	-./syscall_tracer /bin/echo "Hello from traced process"
	@echo ""
	@echo "=== All programs executed ==="
	@echo ""
	@echo "Note: scheduler_test requires root for RT tests."
	@echo "Run: sudo ./scheduler_test"

# Help
.PHONY: help
help:
	@echo "Kernel Fundamentals - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all                    Build all programs (default)"
	@echo "  clean                  Remove all binaries"
	@echo "  run-all                Build and run all programs"
	@echo "  help                   Show this help"
	@echo ""
	@echo "Individual programs:"
	@echo "  syscall_tracer         Trace syscalls using ptrace (Lesson 4)"
	@echo "  process_info           Read process info from /proc (Lesson 5)"
	@echo "  memory_layout          Show virtual memory layout (Lesson 3)"
	@echo "  context_switch_measure Benchmark context switch time (Lesson 6)"
	@echo "  scheduler_test         Test scheduling policies (Lesson 6)"
	@echo "  page_fault_counter     Monitor page faults (Lesson 7)"
	@echo "  custom_syscall_user    Direct syscall invocation (Lesson 4)"
	@echo "  boot_info              Display boot information (Lesson 2)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                           # Build all"
	@echo "  make memory_layout             # Build one program"
	@echo "  ./syscall_tracer /bin/ls -la   # Trace ls"
	@echo "  sudo ./scheduler_test          # Need root for RT"
	@echo "  ./page_fault_counter 128       # 128 MB test"
	@echo "  ./context_switch_measure 50000 1  # 50K iters, pinned"

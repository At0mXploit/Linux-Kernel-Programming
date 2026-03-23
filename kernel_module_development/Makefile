# SPDX-License-Identifier: GPL-2.0
#
# Kbuild Makefile for Kernel Module Development
#
# This Makefile builds all kernel modules in the
# kernel module development category.
#
# Prerequisites:
#   - Linux kernel headers installed:
#     Debian/Ubuntu: sudo apt install linux-headers-$(uname -r)
#     Fedora/RHEL:   sudo dnf install kernel-devel
#     Arch:          sudo pacman -S linux-headers
#
# Usage:
#   make                    Build all kernel modules
#   make clean              Remove build artifacts
#   make help               Show this help
#   make modules_install    Install modules (requires root)
#   make netlink_user       Build the userspace netlink client
#
# Individual modules:
#   make hello              Build hello_module.ko only
#   make proc               Build proc_interface.ko only
#   make sysfs              Build sysfs_interface.ko only
#   make netlink            Build netlink_module.ko only
#   make sync               Build sync_demo.ko only
#   make list               Build list_demo.ko only
#   make chardev            Build char_device.ko only
#   make tracepoint         Build tracepoint_demo.ko only
#
# Loading/Unloading (requires root):
#   sudo insmod <module>.ko
#   sudo rmmod <module>
#   lsmod | grep <module>
#   dmesg | tail -20

# ============================================================================
# Kernel Module Objects
# ============================================================================

# List of kernel modules to build
obj-m += hello_module.o
obj-m += proc_interface.o
obj-m += sysfs_interface.o
obj-m += netlink_module.o
obj-m += sync_demo.o
obj-m += list_demo.o
obj-m += char_device.o
obj-m += tracepoint_demo.o

# For multi-file modules, you would use:
# obj-m += mydriver.o
# mydriver-objs := mydriver_core.o mydriver_io.o mydriver_utils.o

# ============================================================================
# Build Configuration
# ============================================================================

# Kernel build directory (override with KDIR=...)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# C compiler for userspace programs
CC := gcc
CFLAGS := -Wall -Wextra -O2

# Extra CFLAGS for kernel modules (optional)
# ccflags-y := -DDEBUG
# ccflags-y += -Werror

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean help modules_install
.PHONY: hello proc sysfs netlink sync list chardev tracepoint
.PHONY: netlink_user

# Default target: build all kernel modules
all: modules netlink_user

# Build all kernel modules
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean all build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f netlink_user
	rm -f Module.symvers modules.order

# Install modules to /lib/modules/$(uname -r)/extra/
modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# ============================================================================
# Individual Module Targets
# ============================================================================

hello:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=hello_module.o modules

proc:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=proc_interface.o modules

sysfs:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=sysfs_interface.o modules

netlink:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=netlink_module.o modules

sync:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=sync_demo.o modules

list:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=list_demo.o modules

chardev:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=char_device.o modules

tracepoint:
	$(MAKE) -C $(KDIR) M=$(PWD) obj-m=tracepoint_demo.o modules

# ============================================================================
# Userspace Programs
# ============================================================================

# Build the netlink userspace client
netlink_user: netlink_user.c
	$(CC) $(CFLAGS) -o $@ $<

# ============================================================================
# Help
# ============================================================================

help:
	@echo "Kernel Module Development - Build System"
	@echo ""
	@echo "Kernel modules:"
	@echo "  make all        - Build all modules and userspace programs"
	@echo "  make modules    - Build all kernel modules"
	@echo "  make clean      - Remove all build artifacts"
	@echo "  make hello      - Build hello_module.ko"
	@echo "  make proc       - Build proc_interface.ko"
	@echo "  make sysfs      - Build sysfs_interface.ko"
	@echo "  make netlink    - Build netlink_module.ko"
	@echo "  make sync       - Build sync_demo.ko"
	@echo "  make list       - Build list_demo.ko"
	@echo "  make chardev    - Build char_device.ko"
	@echo "  make tracepoint - Build tracepoint_demo.ko"
	@echo ""
	@echo "Userspace programs:"
	@echo "  make netlink_user - Build netlink userspace client"
	@echo ""
	@echo "Installation:"
	@echo "  make modules_install - Install to /lib/modules/"
	@echo ""
	@echo "Environment:"
	@echo "  KDIR=$(KDIR)"
	@echo "  PWD=$(PWD)"

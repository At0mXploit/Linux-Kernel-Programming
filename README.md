# Linux Kernel Programming

Linux kernel programming and security codes.

## Categories

- `kernel_fundamentals/`: userspace programs for syscalls, process inspection, memory layout, scheduling, boot info, and page faults
- `kernel_module_development/`: kernel module basics such as procfs, sysfs, netlink, tracepoints, synchronization, lists, and char devices
- `kernel_subsystems/`: examples for VFS, netfilter, kprobes, sk_buffs, LSM checks, and related subsystem work
- `rootkit_detection/`: defensive tools for hidden process, hidden module, syscall table, network, and boot checks
- `ebpf_security/`: eBPF auditing, monitoring, baselining, and related helper scripts
- `forensics_hardening/`: forensics, integrity checks, baselines, auditd, sysctl, IMA, and hardening utilities

Each category keeps its own `Makefile` when applicable.

/*
 * ebpf_hello.bpf.c - Simple eBPF program that traces syscall entries
 *
 * Demonstrates a basic eBPF tracing program that
 * attaches to the sys_enter tracepoint and logs information about
 * each system call.
 *
 * This program demonstrates:
 *   - BPF program structure (SEC annotations)
 *   - BPF map usage (hash map for per-PID syscall counting)
 *   - BPF ring buffer for event output
 *   - BPF helper function calls
 *   - CO-RE field access patterns
 *
 * Compile:
 *   clang -target bpf -D__TARGET_ARCH_x86 -O2 -g \
 *         -c ebpf_hello.bpf.c -o ebpf_hello.bpf.o
 *
 * Or use the provided Makefile.
 *
 * License: GPL (required for BPF programs using GPL-only helpers)
 */

/* vmlinux.h provides all kernel type definitions from BTF */
/* If vmlinux.h is not available, use these minimal definitions */
#ifndef __VMLINUX_H__

/* Minimal type definitions for standalone compilation */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;

/* Tracepoint context for sys_enter */
struct trace_event_raw_sys_enter {
    __u64 __pad0[2];      /* common fields              */
    long id;               /* syscall number             */
    unsigned long args[6]; /* syscall arguments          */
};

#endif /* __VMLINUX_H__ */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* ──────────────── Shared data structures ──────────────── */

/*
 * Event structure sent to user space via ring buffer.
 * Keep this structure definition synchronized with the
 * user-space loader (ebpf_hello.c).
 */
struct event {
    __u32 pid;                  /* process ID                     */
    __u32 tid;                  /* thread ID                      */
    __u32 uid;                  /* user ID                        */
    __s32 syscall_nr;           /* system call number             */
    __u64 timestamp_ns;         /* event timestamp (nanoseconds)  */
    char  comm[16];             /* process command name            */
};

/* ──────────────── BPF Maps ──────────────── */

/*
 * syscall_count: Per-PID syscall counter.
 * Key:   PID (u32)
 * Value: count (u64)
 *
 * This hash map accumulates the total number of system calls
 * made by each process. User space can read this map to see
 * which processes are most active.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

/*
 * events: Ring buffer for sending events to user space.
 *
 * Ring buffer advantages over perf buffer:
 *   - Single shared buffer (not per-CPU)
 *   - No data loss from per-CPU buffer overflow
 *   - More memory efficient
 *   - Better ordering guarantees
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    /* 256 KB ring buffer */
} events SEC(".maps");

/*
 * target_pid: Optional filter -- if non-zero, only trace this PID.
 * This is a global variable that user space can set before loading
 * the program (via skeleton's .rodata or .bss section).
 */
const volatile __u32 target_pid = 0;

/* ──────────────── BPF Program ──────────────── */

/*
 * handle_sys_enter - Tracepoint handler for sys_enter
 *
 * This BPF program runs every time any process makes a system call.
 * It demonstrates several BPF concepts:
 *
 * 1. Context access: reading tracepoint arguments
 * 2. Helper calls: bpf_get_current_pid_tgid(), bpf_ktime_get_ns()
 * 3. Map operations: lookup, update
 * 4. Ring buffer output: bpf_ringbuf_reserve/submit
 * 5. Filtering: optional PID-based filtering
 *
 * SEC("tp/raw_syscalls/sys_enter") tells libbpf to attach this
 * program to the raw_syscalls:sys_enter tracepoint.
 */
SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid;
    __u32 pid, tid;
    __u64 *count_ptr;
    __u64 count;
    struct event *evt;

    /*
     * bpf_get_current_pid_tgid() returns:
     *   upper 32 bits: tgid (what user space calls PID)
     *   lower 32 bits: pid  (what user space calls TID)
     */
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    tid = (__u32)pid_tgid;

    /* Optional PID filtering */
    if (target_pid != 0 && pid != target_pid)
        return 0;

    /* ── Update per-PID syscall counter ── */

    count_ptr = bpf_map_lookup_elem(&syscall_count, &pid);
    if (count_ptr) {
        /* Key exists: increment */
        __sync_fetch_and_add(count_ptr, 1);
    } else {
        /* Key does not exist: initialize to 1 */
        count = 1;
        bpf_map_update_elem(&syscall_count, &pid, &count, BPF_ANY);
    }

    /* ── Send event to user space via ring buffer ── */

    /*
     * bpf_ringbuf_reserve() allocates space in the ring buffer.
     * If the buffer is full, it returns NULL (we must check!).
     *
     * This is preferred over bpf_ringbuf_output() because it avoids
     * an extra copy -- we write directly into the ring buffer memory.
     */
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;    /* ring buffer full, drop event */

    /* Fill in event data */
    evt->pid = pid;
    evt->tid = tid;
    evt->uid = (__u32)bpf_get_current_uid_gid();
    evt->syscall_nr = (__s32)ctx->id;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /*
     * bpf_ringbuf_submit() makes the event visible to user space.
     * After this call, the event memory is no longer ours to modify.
     */
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

/*
 * License declaration -- REQUIRED for BPF programs.
 * Many BPF helpers (bpf_probe_read_kernel, bpf_get_current_comm, etc.)
 * are GPL-only. Without this declaration, the verifier rejects the program.
 */
char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/*
 * kfunc_monitor.bpf.c - eBPF Program for Monitoring Sensitive Kernel Functions
 * ==============================================================================
 *
 * This eBPF program monitors sensitive kernel function calls for anomaly
 * detection. It attaches to security-relevant kernel functions and reports
 * suspicious activity to userspace via a ring buffer.
 *
 *
 * COMPILATION:
 *   clang -O2 -target bpf -g -c kfunc_monitor.bpf.c -o kfunc_monitor.bpf.o
 *
 * NOTE:
 *   This file is the BPF (kernel-side) component. It requires a userspace
 *   loader program (see ringbuf_monitor.c for the consumer side).
 *   In a production setup, use libbpf's skeleton auto-generation:
 *     bpftool gen skeleton kfunc_monitor.bpf.o > kfunc_monitor.skel.h
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Maximum entries for tracking */
#define MAX_ENTRIES 10240

/* Event types for classification */
#define EVENT_TYPE_CRED_CHANGE    1
#define EVENT_TYPE_MODULE_LOAD    2
#define EVENT_TYPE_EXEC           3
#define EVENT_TYPE_BPF_LOAD       4
#define EVENT_TYPE_SUSPICIOUS     5
#define EVENT_TYPE_SETUID         6

/* Security event structure shared with userspace */
struct security_event {
    __u64  timestamp_ns;
    __u32  event_type;
    __u32  pid;
    __u32  tgid;
    __u32  uid;
    __u32  gid;
    __u32  old_uid;        /* For credential change events */
    __u32  new_uid;        /* For credential change events */
    __s32  ret_value;      /* Return value (for exit probes) */
    char   comm[16];       /* Process name */
    char   filename[128];  /* Filename for exec events */
};

/* Ring buffer for streaming events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} events SEC(".maps");

/* Hash map for tracking process credentials (detect changes) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);              /* PID */
    __type(value, __u32);            /* UID */
} pid_uid_map SEC(".maps");

/* Per-CPU array for BPF syscall statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);         /* One per BPF command */
    __type(key, __u32);
    __type(value, __u64);
} bpf_cmd_stats SEC(".maps");

/* Configuration map (userspace can write to control behavior) */
struct config {
    __u32 monitor_enabled;
    __u32 alert_on_uid_change;
    __u32 alert_on_bpf_load;
    __u32 target_pid;              /* 0 = all, >0 = specific PID */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

/* Helper: Get configuration */
static __always_inline struct config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

/* Helper: Check if monitoring is enabled and PID matches filter */
static __always_inline int should_monitor(void)
{
    struct config *cfg = get_config();
    if (!cfg || !cfg->monitor_enabled)
        return 0;

    if (cfg->target_pid) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != cfg->target_pid)
            return 0;
    }

    return 1;
}

/* Helper: Submit a security event to the ring buffer */
static __always_inline int submit_event(struct security_event *evt)
{
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->tgid = bpf_get_current_pid_tgid() >> 32;
    evt->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt->gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    return bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

/*
 * Monitor: bpf() syscall
 *
 * This is the most critical monitor for detecting eBPF-based threats.
 * Every BPF program load, map creation, and attachment goes through
 * this syscall.
 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor())
        return 0;

    __u32 cmd = (__u32)ctx->args[0];

    /* Count BPF commands */
    if (cmd < 64) {
        __u64 *count = bpf_map_lookup_elem(&bpf_cmd_stats, &cmd);
        if (count)
            __sync_fetch_and_add(count, 1);
    }

    /* Alert on program loads (cmd == 5 == BPF_PROG_LOAD) */
    if (cmd == 5) {
        struct config *cfg = get_config();
        if (cfg && cfg->alert_on_bpf_load) {
            struct security_event *evt;
            evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                __builtin_memset(evt, 0, sizeof(*evt));
                evt->event_type = EVENT_TYPE_BPF_LOAD;
                evt->ret_value = cmd;
                submit_event(evt);
                /* Note: submit_event calls bpf_ringbuf_output internally,
                   but we already reserved. Let's use submit pattern instead */
            }
            /* Alternative: use output pattern */
            struct security_event evt_stack = {};
            evt_stack.event_type = EVENT_TYPE_BPF_LOAD;
            evt_stack.ret_value = cmd;
            evt_stack.timestamp_ns = bpf_ktime_get_ns();
            evt_stack.tgid = bpf_get_current_pid_tgid() >> 32;
            evt_stack.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            evt_stack.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            bpf_get_current_comm(&evt_stack.comm, sizeof(evt_stack.comm));
            bpf_ringbuf_output(&events, &evt_stack, sizeof(evt_stack), 0);

            if (evt)
                bpf_ringbuf_discard(evt, 0);
        }
    }

    return 0;
}

/*
 * Monitor: Process execution
 *
 * Track all process executions. This provides visibility into what
 * binaries are being launched, essential for detecting execution of
 * malicious tools.
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!should_monitor())
        return 0;

    struct security_event evt = {};
    evt.event_type = EVENT_TYPE_EXEC;

    /* Read filename from the tracepoint context */
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&evt.filename, sizeof(evt.filename),
                        (void *)ctx + fname_off);

    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);

    return 0;
}

/*
 * Monitor: Module loading
 *
 * Track kernel module load events. This is critical for detecting
 * unauthorized module insertion.
 */
SEC("tracepoint/module/module_load")
int trace_module_load(struct trace_event_raw_module_load *ctx)
{
    struct security_event evt = {};
    evt.event_type = EVENT_TYPE_MODULE_LOAD;

    /* Read module name */
    unsigned short name_off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_str(&evt.filename, sizeof(evt.filename),
                        (void *)ctx + name_off);

    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);

    return 0;
}

/*
 * Monitor: UID changes (detect privilege escalation)
 *
 * Track when processes change their UID. A transition from non-root
 * to root (UID 0) is always noteworthy.
 */
SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_setuid_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!should_monitor())
        return 0;

    __s64 ret = ctx->ret;
    if (ret != 0)
        return 0;  /* Only care about successful setuid */

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 new_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Check if UID changed */
    __u32 *old_uid = bpf_map_lookup_elem(&pid_uid_map, &pid);

    struct security_event evt = {};
    evt.event_type = EVENT_TYPE_SETUID;
    evt.new_uid = new_uid;
    evt.old_uid = old_uid ? *old_uid : 0xFFFFFFFF;
    evt.ret_value = (__s32)ret;

    /* Update tracking */
    bpf_map_update_elem(&pid_uid_map, &pid, &new_uid, BPF_ANY);

    /* Alert if escalation to root */
    if (new_uid == 0 && old_uid && *old_uid != 0) {
        evt.event_type = EVENT_TYPE_SUSPICIOUS;
    }

    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = new_uid;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);

    return 0;
}

/*
 * Monitor: Process exit (cleanup tracking)
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&pid_uid_map, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

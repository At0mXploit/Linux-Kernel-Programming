/*
 * ebpf_hello.c - Userspace loader for the eBPF syscall tracer
 *
 * Demonstrates using libbpf to load, attach, and
 * interact with an eBPF program. This is the user-space counterpart
 * to ebpf_hello.bpf.c.
 *
 * This program demonstrates:
 *   - Opening and loading a BPF object file
 *   - Attaching BPF programs to tracepoints
 *   - Reading BPF maps from user space
 *   - Consuming ring buffer events
 *   - Proper cleanup on exit
 *
 * Compile:
 *   gcc -O2 -o ebpf_hello ebpf_hello.c -lbpf -lelf -lz
 *
 * Run (requires root or CAP_BPF + CAP_PERFMON):
 *   sudo ./ebpf_hello
 *
 * License: GPL v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Must match the event structure in ebpf_hello.bpf.c */
struct event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __s32 syscall_nr;
    __u64 timestamp_ns;
    char  comm[16];
};

/* Common syscall numbers for x86_64 (for human-readable output) */
static const char *syscall_name(__s32 nr)
{
    switch (nr) {
    case 0:   return "read";
    case 1:   return "write";
    case 2:   return "open";
    case 3:   return "close";
    case 4:   return "stat";
    case 5:   return "fstat";
    case 9:   return "mmap";
    case 10:  return "mprotect";
    case 12:  return "brk";
    case 21:  return "access";
    case 39:  return "getpid";
    case 56:  return "clone";
    case 57:  return "fork";
    case 59:  return "execve";
    case 60:  return "exit";
    case 62:  return "kill";
    case 80:  return "chdir";
    case 87:  return "unlink";
    case 257: return "openat";
    case 262: return "newfstatat";
    case 435: return "clone3";
    default:  return NULL;
    }
}

/* ──────────────── Signal handling for clean exit ──────────────── */

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

/* ──────────────── Ring buffer event callback ──────────────── */

/*
 * handle_event - Called by ring_buffer__poll for each event
 *
 * This function is called in user space for every event that the
 * BPF program writes to the ring buffer. We format and print the
 * event information.
 *
 * @ctx:  User-provided context (unused here)
 * @data: Pointer to the event data
 * @size: Size of the event data
 *
 * Returns: 0 on success (ring buffer processing continues)
 */
static int handle_event(void *ctx, void *data, size_t size)
{
    struct event *evt = data;
    const char *name;
    struct timespec ts;
    double time_s;

    if (size < sizeof(*evt)) {
        fprintf(stderr, "Warning: event too small (%zu < %zu)\n",
                size, sizeof(*evt));
        return 0;
    }

    /* Convert nanosecond timestamp to seconds (relative to boot) */
    time_s = (double)evt->timestamp_ns / 1e9;

    /* Try to get a human-readable syscall name */
    name = syscall_name(evt->syscall_nr);

    if (name) {
        printf("[%12.6f] %-16s pid=%-6u tid=%-6u uid=%-5u syscall=%-12s (%d)\n",
               time_s, evt->comm, evt->pid, evt->tid,
               evt->uid, name, evt->syscall_nr);
    } else {
        printf("[%12.6f] %-16s pid=%-6u tid=%-6u uid=%-5u syscall=%-12d\n",
               time_s, evt->comm, evt->pid, evt->tid,
               evt->uid, evt->syscall_nr);
    }

    return 0;
}

/* ──────────────── Map dumping ──────────────── */

/*
 * dump_syscall_counts - Print the per-PID syscall count map
 *
 * This demonstrates iterating over a BPF hash map from user space
 * using bpf_map_get_next_key().
 */
static void dump_syscall_counts(int map_fd)
{
    __u32 key = 0, next_key;
    __u64 value;
    int count = 0;

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║          Per-PID Syscall Counts                  ║\n");
    printf("╠══════════════╦═══════════════════════════════════╣\n");
    printf("║     PID      ║      Syscall Count                ║\n");
    printf("╠══════════════╬═══════════════════════════════════╣\n");

    /* Iterate over all keys in the hash map */
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("║ %12u ║ %33llu ║\n", next_key, value);
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("║           (no data collected)                    ║\n");
    }

    printf("╚══════════════╩═══════════════════════════════════╝\n");
    printf("Total: %d processes tracked\n\n", count);
}

/* ──────────────── libbpf debug output callback ──────────────── */

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    /* Only print warnings and errors; suppress debug output */
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/* ──────────────── Main ──────────────── */

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *count_map = NULL;
    struct bpf_map *events_map = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int count_map_fd;
    int err;

    /* Set up libbpf logging */
    libbpf_set_print(libbpf_print_fn);

    /* Set up signal handlers for clean exit */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("eBPF Syscall Tracer - Kernel Subsystems Lab\n");
    printf("==================================\n");
    printf("Press Ctrl+C to stop and show statistics.\n\n");

    /* ── Step 1: Open the BPF object file ── */
    obj = bpf_object__open_file("ebpf_hello.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        err = libbpf_get_error(obj);
        fprintf(stderr, "Error: failed to open BPF object: %d (%s)\n",
                err, strerror(-err));
        fprintf(stderr, "Make sure ebpf_hello.bpf.o is in the current directory.\n");
        return 1;
    }

    /* ── Step 2: Load the BPF object (creates maps, verifies programs) ── */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: failed to load BPF object: %d (%s)\n",
                err, strerror(-err));
        fprintf(stderr, "Check dmesg for verifier errors.\n");
        goto cleanup;
    }

    printf("BPF object loaded successfully.\n");

    /* ── Step 3: Find the BPF program by section name ── */
    prog = bpf_object__find_program_by_name(obj, "handle_sys_enter");
    if (!prog) {
        fprintf(stderr, "Error: BPF program 'handle_sys_enter' not found\n");
        err = -ENOENT;
        goto cleanup;
    }

    /* ── Step 4: Find BPF maps ── */
    count_map = bpf_object__find_map_by_name(obj, "syscall_count");
    events_map = bpf_object__find_map_by_name(obj, "events");

    if (!count_map || !events_map) {
        fprintf(stderr, "Error: BPF maps not found\n");
        err = -ENOENT;
        goto cleanup;
    }

    count_map_fd = bpf_map__fd(count_map);

    /* ── Step 5: Attach the BPF program to the tracepoint ── */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        err = libbpf_get_error(link);
        fprintf(stderr, "Error: failed to attach BPF program: %d (%s)\n",
                err, strerror(-err));
        link = NULL;
        goto cleanup;
    }

    printf("BPF program attached to tracepoint.\n");

    /* ── Step 6: Set up ring buffer consumer ── */
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        err = libbpf_get_error(rb);
        fprintf(stderr, "Error: failed to create ring buffer: %d\n", err);
        rb = NULL;
        goto cleanup;
    }

    printf("Ring buffer consumer ready. Tracing syscalls...\n\n");

    printf("%-14s %-16s %-10s %-10s %-9s %-12s\n",
           "TIMESTAMP", "COMM", "PID", "TID", "UID", "SYSCALL");
    printf("─────────────────────────────────────────────────────────────"
           "─────────────────\n");

    /* ── Step 7: Main event loop ── */
    while (!exiting) {
        /*
         * ring_buffer__poll() blocks for up to timeout_ms,
         * calling handle_event() for each available event.
         *
         * Returns: number of events consumed, or negative on error
         */
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            /* Interrupted by signal -- check exiting flag */
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    /* ── Step 8: Print final statistics ── */
    printf("\n\nShutting down...\n");
    dump_syscall_counts(count_map_fd);

cleanup:
    /* ── Step 9: Clean up all BPF resources ── */
    if (rb)
        ring_buffer__free(rb);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);

    printf("eBPF tracer exited.\n");
    return err != 0 ? 1 : 0;
}

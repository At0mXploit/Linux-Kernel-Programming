/*
 * ringbuf_monitor.c - Userspace BPF Ring Buffer Consumer for Security Events
 * ============================================================================
 *
 * This program demonstrates consuming security events from a BPF ring buffer.
 * It is designed as the userspace counterpart to kfunc_monitor.bpf.c, but can
 * also be used as a standalone reference for ring buffer consumption patterns.
 *
 *
 * COMPILATION:
 *   gcc -O2 -o ringbuf_monitor ringbuf_monitor.c -lbpf -lelf -lz
 *
 * USAGE:
 *   sudo ./ringbuf_monitor [-v] [-l logfile]
 *
 * NOTE:
 *   This program requires kfunc_monitor.bpf.o to be compiled and
 *   loaded. In a production setup, the skeleton header would be
 *   auto-generated. This file demonstrates the consumption pattern
 *   and can be adapted for any BPF ring buffer source.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <getopt.h>

/*
 * Note: In a full build with libbpf, you would include:
 *   #include <bpf/libbpf.h>
 *   #include <bpf/bpf.h>
 *   #include "kfunc_monitor.skel.h"
 *
 * For this reference implementation, we define the structures
 * and demonstrate the pattern without requiring libbpf at compile time.
 */

/* Event types - must match kfunc_monitor.bpf.c */
#define EVENT_TYPE_CRED_CHANGE    1
#define EVENT_TYPE_MODULE_LOAD    2
#define EVENT_TYPE_EXEC           3
#define EVENT_TYPE_BPF_LOAD       4
#define EVENT_TYPE_SUSPICIOUS     5
#define EVENT_TYPE_SETUID         6

/* Security event structure - must match kfunc_monitor.bpf.c */
struct security_event {
    __u64  timestamp_ns;
    __u32  event_type;
    __u32  pid;
    __u32  tgid;
    __u32  uid;
    __u32  gid;
    __u32  old_uid;
    __u32  new_uid;
    __s32  ret_value;
    char   comm[16];
    char   filename[128];
};

/* Global state */
static volatile int running = 1;
static FILE *log_fp = NULL;
static int verbose = 0;
static unsigned long long event_count = 0;
static unsigned long long alert_count = 0;

/* Event type names */
static const char *event_type_str(int type)
{
    switch (type) {
    case EVENT_TYPE_CRED_CHANGE: return "CRED_CHANGE";
    case EVENT_TYPE_MODULE_LOAD: return "MODULE_LOAD";
    case EVENT_TYPE_EXEC:        return "EXEC";
    case EVENT_TYPE_BPF_LOAD:    return "BPF_LOAD";
    case EVENT_TYPE_SUSPICIOUS:  return "SUSPICIOUS";
    case EVENT_TYPE_SETUID:      return "SETUID";
    default:                     return "UNKNOWN";
    }
}

/* Severity classification */
static const char *event_severity(int type)
{
    switch (type) {
    case EVENT_TYPE_SUSPICIOUS:  return "CRITICAL";
    case EVENT_TYPE_BPF_LOAD:    return "HIGH";
    case EVENT_TYPE_MODULE_LOAD: return "HIGH";
    case EVENT_TYPE_CRED_CHANGE: return "MEDIUM";
    case EVENT_TYPE_SETUID:      return "MEDIUM";
    case EVENT_TYPE_EXEC:        return "LOW";
    default:                     return "INFO";
    }
}

/* Format timestamp from nanoseconds */
static void format_timestamp(unsigned long long ns, char *buf, size_t len)
{
    time_t secs = ns / 1000000000ULL;
    unsigned long msecs = (ns % 1000000000ULL) / 1000000ULL;
    struct tm *tm = localtime(&secs);

    if (tm) {
        snprintf(buf, len, "%02d:%02d:%02d.%03lu",
                 tm->tm_hour, tm->tm_min, tm->tm_sec, msecs);
    } else {
        snprintf(buf, len, "%llu.%03lu", (unsigned long long)secs, msecs);
    }
}

/* Log a message to stdout and optionally to log file */
static void log_message(const char *fmt, ...)
{
    va_list args;
    char buf[4096];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    printf("%s", buf);

    if (log_fp) {
        fprintf(log_fp, "%s", buf);
        fflush(log_fp);
    }
}

/*
 * Process a single security event from the ring buffer.
 * This is the callback function that would be passed to
 * ring_buffer__poll() or ring_buffer__consume() in libbpf.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct security_event *evt = data;
    char ts_buf[32];
    const char *type_str;
    const char *severity;

    if (data_sz < sizeof(*evt)) {
        log_message("WARNING: Received truncated event (%zu < %zu)\n",
                    data_sz, sizeof(*evt));
        return 0;
    }

    event_count++;

    type_str = event_type_str(evt->event_type);
    severity = event_severity(evt->event_type);
    format_timestamp(evt->timestamp_ns, ts_buf, sizeof(ts_buf));

    /* Format based on event type */
    switch (evt->event_type) {
    case EVENT_TYPE_EXEC:
        if (verbose) {
            log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s "
                        "FILE=%s\n",
                        ts_buf, severity, type_str,
                        evt->tgid, evt->uid, evt->comm, evt->filename);
        }
        break;

    case EVENT_TYPE_BPF_LOAD:
        alert_count++;
        log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s "
                    "BPF_CMD=%d\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->uid, evt->comm, evt->ret_value);
        log_message("  >> ALERT: BPF program load detected from "
                    "process '%s' (PID %u)\n",
                    evt->comm, evt->tgid);
        break;

    case EVENT_TYPE_MODULE_LOAD:
        alert_count++;
        log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s "
                    "MODULE=%s\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->uid, evt->comm, evt->filename);
        log_message("  >> ALERT: Kernel module '%s' loaded by '%s' "
                    "(PID %u)\n",
                    evt->filename, evt->comm, evt->tgid);
        break;

    case EVENT_TYPE_SUSPICIOUS:
        alert_count++;
        log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->uid, evt->comm);
        log_message("  >> CRITICAL: Suspicious privilege escalation! "
                    "UID %u -> %u by '%s' (PID %u)\n",
                    evt->old_uid, evt->new_uid,
                    evt->comm, evt->tgid);
        break;

    case EVENT_TYPE_SETUID:
        log_message("[%s] %-8s %-10s PID=%-6u COMM=%-16s "
                    "UID: %u -> %u\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->comm,
                    evt->old_uid, evt->new_uid);
        break;

    case EVENT_TYPE_CRED_CHANGE:
        log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s "
                    "OLD_UID=%u NEW_UID=%u\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->uid, evt->comm,
                    evt->old_uid, evt->new_uid);
        break;

    default:
        log_message("[%s] %-8s %-10s PID=%-6u UID=%-5u COMM=%-16s\n",
                    ts_buf, severity, type_str,
                    evt->tgid, evt->uid, evt->comm);
        break;
    }

    return 0;
}

/* Signal handler for graceful shutdown */
static void sig_handler(int sig)
{
    running = 0;
}

/* Print session statistics */
static void print_stats(void)
{
    log_message("\n================================================\n");
    log_message("  Session Statistics\n");
    log_message("================================================\n");
    log_message("  Total events processed: %llu\n", event_count);
    log_message("  Alerts generated:       %llu\n", alert_count);
    log_message("================================================\n");
}

/*
 * Demonstration mode: Simulate events for testing the processing pipeline
 * when the BPF program is not loaded.
 */
static void run_demo_mode(void)
{
    log_message("\n");
    log_message("NOTE: Running in demonstration mode.\n");
    log_message("No BPF program is loaded. Simulating events for pipeline testing.\n");
    log_message("\n");

    /* Simulated events */
    struct security_event demo_events[] = {
        {
            .timestamp_ns = 0,  /* Will be filled */
            .event_type = EVENT_TYPE_EXEC,
            .pid = 1234, .tgid = 1234,
            .uid = 1000, .gid = 1000,
            .comm = "bash",
            .filename = "/usr/bin/ls"
        },
        {
            .timestamp_ns = 0,
            .event_type = EVENT_TYPE_BPF_LOAD,
            .pid = 5678, .tgid = 5678,
            .uid = 0, .gid = 0,
            .ret_value = 5,  /* BPF_PROG_LOAD */
            .comm = "unknown_tool",
            .filename = ""
        },
        {
            .timestamp_ns = 0,
            .event_type = EVENT_TYPE_MODULE_LOAD,
            .pid = 1, .tgid = 1,
            .uid = 0, .gid = 0,
            .comm = "systemd",
            .filename = "suspicious_module"
        },
        {
            .timestamp_ns = 0,
            .event_type = EVENT_TYPE_SUSPICIOUS,
            .pid = 9999, .tgid = 9999,
            .uid = 0, .gid = 0,
            .old_uid = 1000,
            .new_uid = 0,
            .comm = "exploit_demo",
            .filename = ""
        },
        {
            .timestamp_ns = 0,
            .event_type = EVENT_TYPE_SETUID,
            .pid = 2345, .tgid = 2345,
            .uid = 0, .gid = 0,
            .old_uid = 1000,
            .new_uid = 0,
            .ret_value = 0,
            .comm = "sudo",
            .filename = ""
        },
    };

    int num_events = sizeof(demo_events) / sizeof(demo_events[0]);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long base_ns = (unsigned long long)ts.tv_sec * 1000000000ULL
                                  + ts.tv_nsec;

    log_message("Simulating %d security events...\n\n", num_events);

    log_message("%-12s %-8s %-10s %-8s %-7s %-16s Details\n",
                "Timestamp", "Severity", "Type", "PID", "UID", "Command");
    log_message("---------------------------------------------------"
                "-----------------------------------------\n");

    for (int i = 0; i < num_events && running; i++) {
        demo_events[i].timestamp_ns = base_ns + (i * 100000000ULL);
        handle_event(NULL, &demo_events[i], sizeof(demo_events[i]));
        usleep(500000);  /* 500ms between events for visual effect */
    }
}

#ifdef HAS_LIBBPF
/*
 * Production mode: Load BPF program and consume from real ring buffer.
 * This requires libbpf and the compiled kfunc_monitor.bpf.o.
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
/* #include "kfunc_monitor.skel.h" -- would be auto-generated */

static void run_production_mode(void)
{
    /* This would use the auto-generated skeleton:
     *
     * struct kfunc_monitor_bpf *skel;
     * struct ring_buffer *rb;
     *
     * skel = kfunc_monitor_bpf__open_and_load();
     * kfunc_monitor_bpf__attach(skel);
     *
     * rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
     *                       handle_event, NULL, NULL);
     *
     * while (running) {
     *     ring_buffer__poll(rb, 100);
     * }
     *
     * ring_buffer__free(rb);
     * kfunc_monitor_bpf__destroy(skel);
     */
    log_message("Production mode requires libbpf and skeleton header.\n");
    log_message("See comments in source for implementation.\n");
}
#endif

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-l logfile] [-d]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v          Verbose mode (show all events)\n");
    fprintf(stderr, "  -l logfile  Write events to log file\n");
    fprintf(stderr, "  -d          Demo mode (simulate events)\n");
    fprintf(stderr, "\nDefensive Tool: Consumes BPF ring buffer security events.\n");
    fprintf(stderr, "\nThis is the userspace companion to kfunc_monitor.bpf.c.\n");
    fprintf(stderr, "In demo mode (-d), it simulates events for pipeline testing.\n");
}

int main(int argc, char **argv)
{
    int opt;
    int demo_mode = 0;
    const char *log_file = NULL;

    while ((opt = getopt(argc, argv, "vl:dh")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'l': log_file = optarg; break;
        case 'd': demo_mode = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    /* Setup signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open log file if specified */
    if (log_file) {
        log_fp = fopen(log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "ERROR: Cannot open log file: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    log_message("================================================\n");
    log_message("  Ring Buffer Security Event Monitor\n");
    log_message("  eBPF Security Tool\n");
    log_message("================================================\n");
    log_message("  Start time: ");
    {
        time_t t = time(NULL);
        log_message("%s", ctime(&t));
    }
    log_message("  Verbose:    %s\n", verbose ? "yes" : "no");
    log_message("  Log file:   %s\n", log_file ? log_file : "none");
    log_message("  Mode:       %s\n", demo_mode ? "demo" : "production");
    log_message("================================================\n");

    if (demo_mode) {
        run_demo_mode();
    } else {
#ifdef HAS_LIBBPF
        if (geteuid() != 0) {
            fprintf(stderr, "ERROR: Production mode requires root.\n");
            return 1;
        }
        run_production_mode();
#else
        log_message("\nProduction mode requires compilation with libbpf.\n");
        log_message("Compile with: gcc -DHAS_LIBBPF -o ringbuf_monitor "
                    "ringbuf_monitor.c -lbpf -lelf -lz\n\n");
        log_message("Running demo mode instead...\n");
        demo_mode = 1;
        run_demo_mode();
#endif
    }

    print_stats();

    if (log_fp)
        fclose(log_fp);

    return 0;
}

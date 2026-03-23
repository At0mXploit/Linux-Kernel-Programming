/*
 * bpf_prog_lister.c - List All Loaded BPF Programs
 * ==================================================
 *
 * This program uses the bpf() syscall to enumerate all loaded BPF programs
 * on the system. It provides detailed information about each program,
 * including type, name, loaded time, and associated maps.
 *
 *
 * COMPILATION:
 *   gcc -O2 -o bpf_prog_lister bpf_prog_lister.c -lbpf
 *
 * USAGE:
 *   sudo ./bpf_prog_lister [-v] [-j] [-t type_filter]
 *
 *   -v  Verbose mode (show map IDs, JIT info)
 *   -j  JSON output
 *   -t  Filter by program type (e.g., kprobe, tracepoint, xdp)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <getopt.h>

/* Direct bpf() syscall wrapper (avoids libbpf dependency for basic enum) */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                           unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* BPF program type names */
static const char *prog_type_name(enum bpf_prog_type type)
{
    static const char *names[] = {
        [BPF_PROG_TYPE_UNSPEC]                = "unspec",
        [BPF_PROG_TYPE_SOCKET_FILTER]         = "socket_filter",
        [BPF_PROG_TYPE_KPROBE]                = "kprobe",
        [BPF_PROG_TYPE_SCHED_CLS]             = "sched_cls",
        [BPF_PROG_TYPE_SCHED_ACT]             = "sched_act",
        [BPF_PROG_TYPE_TRACEPOINT]            = "tracepoint",
        [BPF_PROG_TYPE_XDP]                   = "xdp",
        [BPF_PROG_TYPE_PERF_EVENT]            = "perf_event",
        [BPF_PROG_TYPE_CGROUP_SKB]            = "cgroup_skb",
        [BPF_PROG_TYPE_CGROUP_SOCK]           = "cgroup_sock",
        [BPF_PROG_TYPE_LWT_IN]               = "lwt_in",
        [BPF_PROG_TYPE_LWT_OUT]              = "lwt_out",
        [BPF_PROG_TYPE_LWT_XMIT]            = "lwt_xmit",
        [BPF_PROG_TYPE_SOCK_OPS]              = "sock_ops",
        [BPF_PROG_TYPE_SK_SKB]                = "sk_skb",
        [BPF_PROG_TYPE_CGROUP_DEVICE]         = "cgroup_device",
        [BPF_PROG_TYPE_SK_MSG]                = "sk_msg",
        [BPF_PROG_TYPE_RAW_TRACEPOINT]        = "raw_tracepoint",
        [BPF_PROG_TYPE_CGROUP_SOCK_ADDR]      = "cgroup_sock_addr",
        [BPF_PROG_TYPE_LWT_SEG6LOCAL]        = "lwt_seg6local",
        [BPF_PROG_TYPE_SK_REUSEPORT]          = "sk_reuseport",
        [BPF_PROG_TYPE_FLOW_DISSECTOR]        = "flow_dissector",
        [BPF_PROG_TYPE_CGROUP_SYSCTL]         = "cgroup_sysctl",
        [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tp_writable",
        [BPF_PROG_TYPE_CGROUP_SOCKOPT]        = "cgroup_sockopt",
        [BPF_PROG_TYPE_TRACING]               = "tracing",
        [BPF_PROG_TYPE_STRUCT_OPS]            = "struct_ops",
        [BPF_PROG_TYPE_EXT]                   = "ext",
        [BPF_PROG_TYPE_LSM]                   = "lsm",
        [BPF_PROG_TYPE_SK_LOOKUP]             = "sk_lookup",
        [BPF_PROG_TYPE_SYSCALL]               = "syscall",
    };

    if (type < sizeof(names)/sizeof(names[0]) && names[type])
        return names[type];
    return "unknown";
}

/* Security risk assessment for program types */
static const char *risk_level(enum bpf_prog_type type)
{
    switch (type) {
    case BPF_PROG_TYPE_KPROBE:
    case BPF_PROG_TYPE_TRACING:
    case BPF_PROG_TYPE_LSM:
        return "HIGH";
    case BPF_PROG_TYPE_XDP:
    case BPF_PROG_TYPE_SCHED_CLS:
    case BPF_PROG_TYPE_SCHED_ACT:
        return "HIGH";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
        return "MEDIUM";
    case BPF_PROG_TYPE_TRACEPOINT:
    case BPF_PROG_TYPE_PERF_EVENT:
        return "MEDIUM";
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
        return "MEDIUM";
    default:
        return "LOW";
    }
}

/* Get program info by file descriptor */
static int get_prog_info(int fd, struct bpf_prog_info *info)
{
    union bpf_attr attr;
    int err;

    memset(&attr, 0, sizeof(attr));
    memset(info, 0, sizeof(*info));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (unsigned long)info;

    err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    return err;
}

/* Get program FD by ID */
static int get_prog_fd(unsigned int id)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.prog_id = id;

    return sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

/* Get next program ID */
static int get_next_prog_id(unsigned int *id)
{
    union bpf_attr attr;
    int err;

    memset(&attr, 0, sizeof(attr));
    attr.start_id = *id;

    err = sys_bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
    if (err == 0)
        *id = attr.next_id;

    return err;
}

/* Format nanosecond timestamp */
static void format_ns_time(unsigned long long ns, char *buf, size_t len)
{
    time_t secs = ns / 1000000000ULL;
    struct tm *tm = localtime(&secs);
    if (tm)
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm);
    else
        snprintf(buf, len, "%llu", ns);
}

/* Print program info in text format */
static void print_prog_text(struct bpf_prog_info *info, int verbose)
{
    const char *type_str = prog_type_name(info->type);
    const char *risk = risk_level(info->type);
    char loaded_at[64] = "N/A";

    if (info->load_time)
        format_ns_time(info->load_time, loaded_at, sizeof(loaded_at));

    printf("  ID: %-6u  Type: %-20s  Name: %-16s  Risk: %s\n",
           info->id, type_str, info->name[0] ? info->name : "(unnamed)", risk);

    if (verbose) {
        printf("    Tag: %02x%02x%02x%02x%02x%02x%02x%02x  "
               "Loaded: %s\n",
               info->tag[0], info->tag[1], info->tag[2], info->tag[3],
               info->tag[4], info->tag[5], info->tag[6], info->tag[7],
               loaded_at);
        printf("    Insns: %-6u  JIT: %-3s  Run count: %llu  "
               "Run time: %llu ns\n",
               info->xlated_prog_len / 8,
               info->jited_prog_len > 0 ? "yes" : "no",
               (unsigned long long)info->run_cnt,
               (unsigned long long)info->run_time_ns);

        if (info->nr_map_ids > 0)
            printf("    Maps: %u associated map(s)\n", info->nr_map_ids);
    }
}

/* Print program info in JSON format */
static void print_prog_json(struct bpf_prog_info *info, int first)
{
    char loaded_at[64] = "N/A";

    if (info->load_time)
        format_ns_time(info->load_time, loaded_at, sizeof(loaded_at));

    if (!first)
        printf(",\n");

    printf("    {\n");
    printf("      \"id\": %u,\n", info->id);
    printf("      \"type\": \"%s\",\n", prog_type_name(info->type));
    printf("      \"name\": \"%s\",\n", info->name[0] ? info->name : "");
    printf("      \"risk\": \"%s\",\n", risk_level(info->type));
    printf("      \"tag\": \"%02x%02x%02x%02x%02x%02x%02x%02x\",\n",
           info->tag[0], info->tag[1], info->tag[2], info->tag[3],
           info->tag[4], info->tag[5], info->tag[6], info->tag[7]);
    printf("      \"loaded_at\": \"%s\",\n", loaded_at);
    printf("      \"insn_count\": %u,\n", info->xlated_prog_len / 8);
    printf("      \"jited\": %s,\n",
           info->jited_prog_len > 0 ? "true" : "false");
    printf("      \"run_count\": %llu,\n", (unsigned long long)info->run_cnt);
    printf("      \"run_time_ns\": %llu,\n",
           (unsigned long long)info->run_time_ns);
    printf("      \"nr_maps\": %u\n", info->nr_map_ids);
    printf("    }");
}

/* Check if program type matches filter */
static int type_matches_filter(enum bpf_prog_type type, const char *filter)
{
    if (!filter)
        return 1;
    return strcmp(prog_type_name(type), filter) == 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-j] [-t type_filter]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v  Verbose mode (show detailed program info)\n");
    fprintf(stderr, "  -j  JSON output format\n");
    fprintf(stderr, "  -t  Filter by program type (e.g., kprobe, xdp, lsm)\n");
    fprintf(stderr, "\nDefensive Security Tool: Lists all loaded BPF programs\n");
    fprintf(stderr, "for security auditing and anomaly detection.\n");
}

int main(int argc, char **argv)
{
    int verbose = 0, json_output = 0;
    const char *type_filter = NULL;
    int opt;
    unsigned int id = 0;
    int count = 0, high_risk_count = 0;
    int first_json = 1;

    while ((opt = getopt(argc, argv, "vjt:h")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'j':
            json_output = 1;
            break;
        case 't':
            type_filter = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges.\n");
        fprintf(stderr, "Run with: sudo %s\n", argv[0]);
        return 1;
    }

    if (json_output) {
        printf("{\n  \"bpf_programs\": [\n");
    } else {
        printf("=========================================="
               "==============================\n");
        printf("  BPF Program Lister - Defensive Security Audit Tool\n");
        printf("=========================================="
               "==============================\n");
        printf("  Scan time: ");
        time_t now = time(NULL);
        printf("%s", ctime(&now));
        if (type_filter)
            printf("  Filter: type=%s\n", type_filter);
        printf("=========================================="
               "==============================\n\n");
    }

    /* Enumerate all BPF programs */
    while (get_next_prog_id(&id) == 0) {
        int fd;
        struct bpf_prog_info info;

        fd = get_prog_fd(id);
        if (fd < 0) {
            if (!json_output)
                fprintf(stderr, "  WARNING: Cannot get FD for program ID %u: %s\n",
                        id, strerror(errno));
            continue;
        }

        if (get_prog_info(fd, &info) != 0) {
            if (!json_output)
                fprintf(stderr, "  WARNING: Cannot get info for program ID %u: %s\n",
                        id, strerror(errno));
            close(fd);
            continue;
        }

        close(fd);

        /* Apply type filter */
        if (!type_matches_filter(info.type, type_filter))
            continue;

        if (json_output) {
            print_prog_json(&info, first_json);
            first_json = 0;
        } else {
            print_prog_text(&info, verbose);
            if (verbose)
                printf("\n");
        }

        count++;
        if (strcmp(risk_level(info.type), "HIGH") == 0)
            high_risk_count++;
    }

    if (json_output) {
        printf("\n  ],\n");
        printf("  \"summary\": {\n");
        printf("    \"total\": %d,\n", count);
        printf("    \"high_risk\": %d\n", high_risk_count);
        printf("  }\n");
        printf("}\n");
    } else {
        printf("\n=========================================="
               "==============================\n");
        printf("  Summary: %d programs found", count);
        if (type_filter)
            printf(" (filtered by: %s)", type_filter);
        printf("\n");
        if (high_risk_count > 0)
            printf("  WARNING: %d HIGH-RISK program(s) detected\n",
                   high_risk_count);
        printf("=========================================="
               "==============================\n");
    }

    return 0;
}

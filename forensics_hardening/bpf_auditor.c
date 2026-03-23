/*
 * bpf_auditor.c - BPF Program Audit Tool
 *
 *
 * Audits all loaded BPF programs and their attachment points by:
 *   1. Enumerating BPF programs via bpf() syscall
 *   2. Retrieving program info (type, name, tag, load time)
 *   3. Enumerating BPF maps
 *   4. Checking /sys/fs/bpf for pinned objects
 *   5. Comparing with a known-good baseline
 *
 * Build: gcc -O2 -Wall -Wextra -o bpf_auditor bpf_auditor.c
 * Usage: sudo ./bpf_auditor [--baseline|--verify|--list]
 *
 * MUST be run as root (BPF operations require CAP_SYS_ADMIN).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/bpf.h>

#define MAX_PROGS       256
#define MAX_MAPS        256
#define MAX_LINE_LEN    1024
#define BASELINE_FILE   "/var/lib/bpf_audit/baseline.dat"
#define BASELINE_DIR    "/var/lib/bpf_audit"

/* ── BPF syscall wrapper ───────────────────────────────────────── */

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                          unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* ── BPF program type names ────────────────────────────────────── */

static const char *bpf_prog_type_name(enum bpf_prog_type type)
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
        [BPF_PROG_TYPE_SOCK_OPS]             = "sock_ops",
        [BPF_PROG_TYPE_SK_SKB]               = "sk_skb",
        [BPF_PROG_TYPE_CGROUP_DEVICE]        = "cgroup_device",
        [BPF_PROG_TYPE_SK_MSG]               = "sk_msg",
        [BPF_PROG_TYPE_RAW_TRACEPOINT]       = "raw_tracepoint",
        [BPF_PROG_TYPE_CGROUP_SOCK_ADDR]     = "cgroup_sock_addr",
        [BPF_PROG_TYPE_LWT_SEG6LOCAL]        = "lwt_seg6local",
#ifdef BPF_PROG_TYPE_LIRC_MODE2
        [BPF_PROG_TYPE_LIRC_MODE2]           = "lirc_mode2",
#endif
        [BPF_PROG_TYPE_SK_REUSEPORT]         = "sk_reuseport",
        [BPF_PROG_TYPE_FLOW_DISSECTOR]       = "flow_dissector",
#ifdef BPF_PROG_TYPE_CGROUP_SYSCTL
        [BPF_PROG_TYPE_CGROUP_SYSCTL]        = "cgroup_sysctl",
#endif
#ifdef BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
        [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tp_writable",
#endif
#ifdef BPF_PROG_TYPE_TRACING
        [BPF_PROG_TYPE_TRACING]              = "tracing",
#endif
#ifdef BPF_PROG_TYPE_STRUCT_OPS
        [BPF_PROG_TYPE_STRUCT_OPS]           = "struct_ops",
#endif
#ifdef BPF_PROG_TYPE_EXT
        [BPF_PROG_TYPE_EXT]                  = "ext",
#endif
#ifdef BPF_PROG_TYPE_LSM
        [BPF_PROG_TYPE_LSM]                  = "lsm",
#endif
    };

    if (type < sizeof(names) / sizeof(names[0]) && names[type])
        return names[type];
    return "unknown";
}

/* ── BPF map type names ────────────────────────────────────────── */

static const char *bpf_map_type_name(enum bpf_map_type type)
{
    static const char *names[] = {
        [BPF_MAP_TYPE_UNSPEC]              = "unspec",
        [BPF_MAP_TYPE_HASH]               = "hash",
        [BPF_MAP_TYPE_ARRAY]              = "array",
        [BPF_MAP_TYPE_PROG_ARRAY]         = "prog_array",
        [BPF_MAP_TYPE_PERF_EVENT_ARRAY]   = "perf_event_array",
        [BPF_MAP_TYPE_PERCPU_HASH]        = "percpu_hash",
        [BPF_MAP_TYPE_PERCPU_ARRAY]       = "percpu_array",
        [BPF_MAP_TYPE_STACK_TRACE]        = "stack_trace",
        [BPF_MAP_TYPE_CGROUP_ARRAY]       = "cgroup_array",
        [BPF_MAP_TYPE_LRU_HASH]           = "lru_hash",
        [BPF_MAP_TYPE_LRU_PERCPU_HASH]    = "lru_percpu_hash",
        [BPF_MAP_TYPE_LPM_TRIE]           = "lpm_trie",
        [BPF_MAP_TYPE_ARRAY_OF_MAPS]      = "array_of_maps",
        [BPF_MAP_TYPE_HASH_OF_MAPS]       = "hash_of_maps",
#ifdef BPF_MAP_TYPE_DEVMAP
        [BPF_MAP_TYPE_DEVMAP]             = "devmap",
#endif
#ifdef BPF_MAP_TYPE_SOCKMAP
        [BPF_MAP_TYPE_SOCKMAP]            = "sockmap",
#endif
#ifdef BPF_MAP_TYPE_CPUMAP
        [BPF_MAP_TYPE_CPUMAP]             = "cpumap",
#endif
#ifdef BPF_MAP_TYPE_XSKMAP
        [BPF_MAP_TYPE_XSKMAP]             = "xskmap",
#endif
#ifdef BPF_MAP_TYPE_SOCKHASH
        [BPF_MAP_TYPE_SOCKHASH]           = "sockhash",
#endif
#ifdef BPF_MAP_TYPE_RINGBUF
        [BPF_MAP_TYPE_RINGBUF]            = "ringbuf",
#endif
    };

    if (type < sizeof(names) / sizeof(names[0]) && names[type])
        return names[type];
    return "unknown";
}

/* ── Data structures for tracking ──────────────────────────────── */

typedef struct {
    __u32  id;
    __u32  type;
    char   name[BPF_OBJ_NAME_LEN];
    char   tag[17];     /* 8 bytes hex = 16 chars + null */
    __u32  loaded_at;   /* seconds since boot */
    __u32  uid;
    __u32  xlated_len;
    __u32  jited_len;
    int    is_suspicious;
} bpf_prog_info_t;

typedef struct {
    __u32  id;
    __u32  type;
    char   name[BPF_OBJ_NAME_LEN];
    __u32  key_size;
    __u32  value_size;
    __u32  max_entries;
} bpf_map_info_t;

static bpf_prog_info_t progs[MAX_PROGS];
static int prog_count = 0;

static bpf_map_info_t maps[MAX_MAPS];
static int map_count = 0;

/* ── Enumerate BPF programs ────────────────────────────────────── */

static void enumerate_programs(void)
{
    union bpf_attr attr;
    __u32 id = 0;

    printf("=== BPF Program Enumeration ===\n\n");

    while (prog_count < MAX_PROGS) {
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;

        if (sys_bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) != 0) {
            if (errno == ENOENT)
                break;
            break;
        }

        id = attr.next_id;

        /* Get program fd */
        memset(&attr, 0, sizeof(attr));
        attr.prog_id = id;

        int fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0)
            continue;

        /* Get program info */
        struct bpf_prog_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (__u64)(unsigned long)&info;

        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
            bpf_prog_info_t *p = &progs[prog_count];
            p->id = info.id;
            p->type = info.type;
            strncpy(p->name, info.name, BPF_OBJ_NAME_LEN - 1);
            p->loaded_at = info.load_time / 1000000000ULL; /* ns to s */
            p->uid = info.created_by_uid;
            p->xlated_len = info.xlated_prog_len;
            p->jited_len = info.jited_prog_len;

            /* Format tag as hex */
            for (int i = 0; i < 8; i++)
                snprintf(p->tag + i * 2, 3, "%02x", info.tag[i]);

            /* Check for suspicious program types */
            p->is_suspicious = 0;
#ifdef BPF_PROG_TYPE_TRACING
            if (info.type == BPF_PROG_TYPE_TRACING ||
                info.type == BPF_PROG_TYPE_KPROBE ||
                info.type == BPF_PROG_TYPE_RAW_TRACEPOINT) {
                /* Tracing programs can intercept kernel functions */
                /* Mark for review (not necessarily malicious) */
                p->is_suspicious = 1;
            }
#endif

            prog_count++;
        }

        close(fd);
    }

    printf("Found %d BPF programs:\n\n", prog_count);
    printf("%-6s %-20s %-20s %-18s %-6s %8s %8s %s\n",
           "ID", "TYPE", "NAME", "TAG", "UID", "XLATED", "JITED", "FLAGS");
    printf("%-6s %-20s %-20s %-18s %-6s %8s %8s %s\n",
           "------", "--------------------", "--------------------",
           "------------------", "------", "--------", "--------", "-----");

    for (int i = 0; i < prog_count; i++) {
        bpf_prog_info_t *p = &progs[i];
        printf("%-6u %-20s %-20s %-18s %-6u %8u %8u %s\n",
               p->id,
               bpf_prog_type_name(p->type),
               p->name[0] ? p->name : "(unnamed)",
               p->tag,
               p->uid,
               p->xlated_len,
               p->jited_len,
               p->is_suspicious ? "REVIEW" : "");
    }
}

/* ── Enumerate BPF maps ────────────────────────────────────────── */

static void enumerate_maps(void)
{
    union bpf_attr attr;
    __u32 id = 0;

    printf("\n=== BPF Map Enumeration ===\n\n");

    while (map_count < MAX_MAPS) {
        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;

        if (sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) != 0) {
            if (errno == ENOENT)
                break;
            break;
        }

        id = attr.next_id;

        /* Get map fd */
        memset(&attr, 0, sizeof(attr));
        attr.map_id = id;

        int fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0)
            continue;

        /* Get map info */
        struct bpf_map_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (__u64)(unsigned long)&info;

        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
            bpf_map_info_t *m = &maps[map_count];
            m->id = info.id;
            m->type = info.type;
            strncpy(m->name, info.name, BPF_OBJ_NAME_LEN - 1);
            m->key_size = info.key_size;
            m->value_size = info.value_size;
            m->max_entries = info.max_entries;
            map_count++;
        }

        close(fd);
    }

    printf("Found %d BPF maps:\n\n", map_count);
    printf("%-6s %-22s %-20s %8s %8s %10s\n",
           "ID", "TYPE", "NAME", "KEY_SZ", "VAL_SZ", "MAX_ENTRY");
    printf("%-6s %-22s %-20s %8s %8s %10s\n",
           "------", "----------------------", "--------------------",
           "--------", "--------", "----------");

    for (int i = 0; i < map_count; i++) {
        bpf_map_info_t *m = &maps[i];
        printf("%-6u %-22s %-20s %8u %8u %10u\n",
               m->id,
               bpf_map_type_name(m->type),
               m->name[0] ? m->name : "(unnamed)",
               m->key_size,
               m->value_size,
               m->max_entries);
    }
}

/* ── Check pinned objects ──────────────────────────────────────── */

static void check_pinned_objects(void)
{
    printf("\n=== Pinned BPF Objects (/sys/fs/bpf) ===\n\n");

    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        printf("  /sys/fs/bpf not mounted or not accessible.\n");
        return;
    }

    DIR *dir = opendir("/sys/fs/bpf");
    if (!dir) {
        printf("  Cannot open /sys/fs/bpf (permission denied?)\n");
        return;
    }

    struct dirent *entry;
    int pinned_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char path[512];
        snprintf(path, sizeof(path), "/sys/fs/bpf/%s", entry->d_name);

        if (stat(path, &st) == 0) {
            printf("  Pinned: %s (mode: %o, size: %ld)\n",
                   path, st.st_mode & 07777, (long)st.st_size);
            pinned_count++;
        }
    }
    closedir(dir);

    if (pinned_count == 0)
        printf("  No pinned objects found.\n");
    else
        printf("\n  Total pinned objects: %d\n", pinned_count);

    if (pinned_count > 0) {
        printf("  NOTE: Pinned BPF objects persist without a process.\n");
        printf("        Verify each pinned object is expected.\n");
    }
}

/* ── Security analysis ─────────────────────────────────────────── */

static void security_analysis(void)
{
    printf("\n=== Security Analysis ===\n\n");

    int suspicious = 0;

    /* Check for tracing programs (kprobe, tracepoint) */
    for (int i = 0; i < prog_count; i++) {
        if (progs[i].type == BPF_PROG_TYPE_KPROBE) {
            printf("  REVIEW: Program ID %u (%s) is a KPROBE - "
                   "can intercept kernel functions\n",
                   progs[i].id, progs[i].name);
            suspicious++;
        }
        if (progs[i].type == BPF_PROG_TYPE_RAW_TRACEPOINT) {
            printf("  REVIEW: Program ID %u (%s) is a RAW_TRACEPOINT - "
                   "has raw kernel event access\n",
                   progs[i].id, progs[i].name);
            suspicious++;
        }
        if (progs[i].type == BPF_PROG_TYPE_XDP) {
            printf("  REVIEW: Program ID %u (%s) is XDP - "
                   "can modify/drop packets at NIC level\n",
                   progs[i].id, progs[i].name);
            suspicious++;
        }
#ifdef BPF_PROG_TYPE_LSM
        if (progs[i].type == BPF_PROG_TYPE_LSM) {
            printf("  REVIEW: Program ID %u (%s) is BPF LSM - "
                   "can override security decisions\n",
                   progs[i].id, progs[i].name);
            suspicious++;
        }
#endif
        /* Unnamed programs are more suspicious */
        if (progs[i].name[0] == '\0') {
            printf("  REVIEW: Program ID %u has no name (harder to identify)\n",
                   progs[i].id);
        }
    }

    /* Check for suspicious map types */
    for (int i = 0; i < map_count; i++) {
        if (maps[i].type == BPF_MAP_TYPE_PROG_ARRAY) {
            printf("  REVIEW: Map ID %u (%s) is PROG_ARRAY - "
                   "enables tail calls (control flow obfuscation)\n",
                   maps[i].id, maps[i].name);
        }
#ifdef BPF_MAP_TYPE_SOCKMAP
        if (maps[i].type == BPF_MAP_TYPE_SOCKMAP) {
            printf("  REVIEW: Map ID %u (%s) is SOCKMAP - "
                   "can redirect socket traffic\n",
                   maps[i].id, maps[i].name);
        }
#endif
    }

    printf("\n  Total items flagged for review: %d\n", suspicious);
    if (suspicious == 0)
        printf("  No high-risk BPF programs detected.\n");
}

/* ── Baseline operations ───────────────────────────────────────── */

static int create_baseline(void)
{
    printf("\n=== Creating BPF Baseline ===\n");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", BASELINE_DIR);
    if (system(cmd) != 0) {
        fprintf(stderr, "Cannot create %s\n", BASELINE_DIR);
        return -1;
    }

    FILE *fp = fopen(BASELINE_FILE, "w");
    if (!fp) {
        fprintf(stderr, "Cannot create %s\n", BASELINE_FILE);
        return -1;
    }

    time_t now = time(NULL);
    fprintf(fp, "# BPF Audit Baseline\n");
    fprintf(fp, "# Date: %s", ctime(&now));
    fprintf(fp, "# Programs: %d\n", prog_count);
    fprintf(fp, "# Maps: %d\n", map_count);
    fprintf(fp, "#\n");

    for (int i = 0; i < prog_count; i++) {
        fprintf(fp, "PROG %u %s %s %s %u\n",
                progs[i].id,
                bpf_prog_type_name(progs[i].type),
                progs[i].name[0] ? progs[i].name : "(unnamed)",
                progs[i].tag,
                progs[i].uid);
    }

    for (int i = 0; i < map_count; i++) {
        fprintf(fp, "MAP %u %s %s %u %u %u\n",
                maps[i].id,
                bpf_map_type_name(maps[i].type),
                maps[i].name[0] ? maps[i].name : "(unnamed)",
                maps[i].key_size,
                maps[i].value_size,
                maps[i].max_entries);
    }

    fclose(fp);
    printf("  Baseline saved to: %s\n", BASELINE_FILE);
    return 0;
}

static void verify_baseline(void)
{
    printf("\n=== Verifying Against Baseline ===\n");

    FILE *fp = fopen(BASELINE_FILE, "r");
    if (!fp) {
        fprintf(stderr, "No baseline found at %s\n", BASELINE_FILE);
        fprintf(stderr, "Create one with: bpf_auditor --baseline\n");
        return;
    }

    char line[MAX_LINE_LEN];
    int baseline_progs = 0;
    int baseline_maps = 0;
    int new_progs = 0;
    int missing_progs = 0;
    int changed_progs = 0;

    /* Track which current programs are accounted for */
    int prog_matched[MAX_PROGS];
    memset(prog_matched, 0, sizeof(prog_matched));

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#')
            continue;

        if (strncmp(line, "PROG", 4) == 0) {
            baseline_progs++;
            unsigned int b_id;
            char b_type[64], b_name[64], b_tag[32];
            unsigned int b_uid;

            if (sscanf(line, "PROG %u %63s %63s %31s %u",
                       &b_id, b_type, b_name, b_tag, &b_uid) >= 4) {
                /* Find matching program by tag (not ID, as IDs change) */
                int found = 0;
                for (int i = 0; i < prog_count; i++) {
                    if (strcmp(progs[i].tag, b_tag) == 0) {
                        found = 1;
                        prog_matched[i] = 1;

                        /* Check if type changed */
                        if (strcmp(bpf_prog_type_name(progs[i].type), b_type) != 0) {
                            printf("  CHANGED: Program tag %s type changed: %s -> %s\n",
                                   b_tag, b_type, bpf_prog_type_name(progs[i].type));
                            changed_progs++;
                        }
                        break;
                    }
                }
                if (!found) {
                    printf("  MISSING: Baseline program '%s' (tag: %s) no longer present\n",
                           b_name, b_tag);
                    missing_progs++;
                }
            }
        } else if (strncmp(line, "MAP", 3) == 0) {
            baseline_maps++;
        }
    }
    fclose(fp);

    /* Check for new programs not in baseline */
    for (int i = 0; i < prog_count; i++) {
        if (!prog_matched[i]) {
            printf("  NEW: Program ID %u (%s) type=%s tag=%s not in baseline\n",
                   progs[i].id,
                   progs[i].name[0] ? progs[i].name : "(unnamed)",
                   bpf_prog_type_name(progs[i].type),
                   progs[i].tag);
            new_progs++;
        }
    }

    printf("\n  Baseline: %d programs, %d maps\n", baseline_progs, baseline_maps);
    printf("  Current:  %d programs, %d maps\n", prog_count, map_count);
    printf("  New:      %d programs\n", new_progs);
    printf("  Missing:  %d programs\n", missing_progs);
    printf("  Changed:  %d programs\n", changed_progs);

    if (new_progs == 0 && missing_progs == 0 && changed_progs == 0)
        printf("\n  RESULT: BPF environment matches baseline.\n");
    else
        printf("\n  RESULT: BPF environment has changed from baseline.\n");
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int mode_baseline = 0;
    int mode_verify = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--baseline") == 0)
            mode_baseline = 1;
        else if (strcmp(argv[i], "--verify") == 0)
            mode_verify = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --baseline  Create BPF program/map baseline\n");
            printf("  --verify    Verify current state against baseline\n");
            printf("  --list      (default) List all BPF programs and maps\n");
            printf("  --help      Show this help\n");
            printf("\nMust be run as root.\n");
            return 0;
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root (BPF requires CAP_SYS_ADMIN).\n");
        return 1;
    }

    printf("============================================================\n");
    printf("  BPF Program Auditor v1.0\n");
    printf("============================================================\n");
    time_t now = time(NULL);
    printf("  Date: %s", ctime(&now));
    printf("============================================================\n");

    /* Enumerate everything */
    enumerate_programs();
    enumerate_maps();

    if (mode_baseline) {
        create_baseline();
    } else if (mode_verify) {
        verify_baseline();
    } else {
        /* Default: list everything with analysis */
        check_pinned_objects();
        security_analysis();
    }

    printf("\n============================================================\n");
    printf("  Audit complete: %d programs, %d maps inventoried.\n",
           prog_count, map_count);
    printf("============================================================\n");

    return 0;
}

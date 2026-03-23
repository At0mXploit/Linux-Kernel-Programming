/*
 * ebpf_baseline.c - Create and Verify Baseline of Expected BPF Programs
 * ======================================================================
 *
 * This program creates a baseline snapshot of all loaded BPF programs and
 * maps, then can verify the current state against this baseline to detect
 * unauthorized changes.
 *
 *
 * COMPILATION:
 *   gcc -O2 -o ebpf_baseline ebpf_baseline.c
 *
 * USAGE:
 *   sudo ./ebpf_baseline --save baseline.dat     # Create baseline
 *   sudo ./ebpf_baseline --verify baseline.dat   # Verify against baseline
 *   sudo ./ebpf_baseline --list                  # List current state
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

/* Direct bpf() syscall wrapper */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                           unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

#define MAX_PROGS 4096
#define MAX_MAPS  4096

/* Baseline entry for a BPF program */
struct prog_baseline_entry {
    unsigned int id;
    unsigned int type;
    char         name[16];
    unsigned char tag[8];
    unsigned int  xlated_prog_len;
    unsigned int  nr_map_ids;
    unsigned long long run_cnt;
};

/* Baseline entry for a BPF map */
struct map_baseline_entry {
    unsigned int id;
    unsigned int type;
    char         name[16];
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

/* Baseline file header */
struct baseline_header {
    char     magic[8];        /* "BPFBASE\0" */
    time_t   timestamp;
    int      prog_count;
    int      map_count;
    char     kernel_version[64];
};

/* Current state */
static struct prog_baseline_entry current_progs[MAX_PROGS];
static int current_prog_count = 0;
static struct map_baseline_entry current_maps[MAX_MAPS];
static int current_map_count = 0;

/* Program type name */
static const char *prog_type_str(unsigned int type)
{
    static const char *names[] = {
        "unspec", "socket_filter", "kprobe", "sched_cls", "sched_act",
        "tracepoint", "xdp", "perf_event", "cgroup_skb", "cgroup_sock",
        "lwt_in", "lwt_out", "lwt_xmit", "sock_ops", "sk_skb",
        "cgroup_device", "sk_msg", "raw_tracepoint", "cgroup_sock_addr",
        "lwt_seg6local", "sk_reuseport", "flow_dissector", "cgroup_sysctl",
        "raw_tp_writable", "cgroup_sockopt", "tracing", "struct_ops",
        "ext", "lsm", "sk_lookup", "syscall"
    };
    if (type < sizeof(names)/sizeof(names[0]))
        return names[type];
    return "unknown";
}

/* Map type name */
static const char *map_type_str(unsigned int type)
{
    static const char *names[] = {
        "unspec", "hash", "array", "prog_array", "perf_event_array",
        "percpu_hash", "percpu_array", "stack_trace", "cgroup_array",
        "lru_hash", "lru_percpu_hash", "lpm_trie", "array_of_maps",
        "hash_of_maps", "devmap", "sockmap", "cpumap", "xskmap",
        "sockhash", "cgroup_storage", "reuseport_sockarray",
        "percpu_cgroup_storage", "queue", "stack", "sk_storage",
        "devmap_hash", "struct_ops", "ringbuf", "inode_storage",
        "task_storage", "bloom_filter"
    };
    if (type < sizeof(names)/sizeof(names[0]))
        return names[type];
    return "unknown";
}

/* Enumerate current BPF programs */
static int enumerate_progs(void)
{
    union bpf_attr attr;
    unsigned int id = 0;

    current_prog_count = 0;

    while (current_prog_count < MAX_PROGS) {
        int fd;
        struct bpf_prog_info info;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        if (sys_bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) != 0)
            break;
        id = attr.next_id;

        memset(&attr, 0, sizeof(attr));
        attr.prog_id = id;
        fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0)
            continue;

        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (unsigned long)&info;

        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
            struct prog_baseline_entry *entry =
                &current_progs[current_prog_count];

            entry->id = info.id;
            entry->type = info.type;
            memcpy(entry->name, info.name, sizeof(entry->name));
            memcpy(entry->tag, info.tag, sizeof(entry->tag));
            entry->xlated_prog_len = info.xlated_prog_len;
            entry->nr_map_ids = info.nr_map_ids;
            entry->run_cnt = info.run_cnt;

            current_prog_count++;
        }

        close(fd);
    }

    return current_prog_count;
}

/* Enumerate current BPF maps */
static int enumerate_maps(void)
{
    union bpf_attr attr;
    unsigned int id = 0;

    current_map_count = 0;

    while (current_map_count < MAX_MAPS) {
        int fd;
        struct bpf_map_info info;

        memset(&attr, 0, sizeof(attr));
        attr.start_id = id;
        if (sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) != 0)
            break;
        id = attr.next_id;

        memset(&attr, 0, sizeof(attr));
        attr.map_id = id;
        fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
        if (fd < 0)
            continue;

        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (unsigned long)&info;

        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
            struct map_baseline_entry *entry =
                &current_maps[current_map_count];

            entry->id = info.id;
            entry->type = info.type;
            memcpy(entry->name, info.name, sizeof(entry->name));
            entry->key_size = info.key_size;
            entry->value_size = info.value_size;
            entry->max_entries = info.max_entries;

            current_map_count++;
        }

        close(fd);
    }

    return current_map_count;
}

/* Save baseline to file */
static int save_baseline(const char *path)
{
    FILE *fp;
    struct baseline_header header;
    struct utsname uts;

    enumerate_progs();
    enumerate_maps();

    fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot create baseline file: %s\n",
                strerror(errno));
        return -1;
    }

    /* Write header */
    memset(&header, 0, sizeof(header));
    strcpy(header.magic, "BPFBASE");
    header.timestamp = time(NULL);
    header.prog_count = current_prog_count;
    header.map_count = current_map_count;

    if (uname(&uts) == 0)
        strncpy(header.kernel_version, uts.release,
                sizeof(header.kernel_version) - 1);

    fwrite(&header, sizeof(header), 1, fp);

    /* Write program entries */
    fwrite(current_progs, sizeof(struct prog_baseline_entry),
           current_prog_count, fp);

    /* Write map entries */
    fwrite(current_maps, sizeof(struct map_baseline_entry),
           current_map_count, fp);

    fclose(fp);

    printf("Baseline saved to: %s\n", path);
    printf("  Programs: %d\n", current_prog_count);
    printf("  Maps:     %d\n", current_map_count);
    printf("  Kernel:   %s\n", header.kernel_version);
    printf("  Time:     %s", ctime(&header.timestamp));

    return 0;
}

/* Verify current state against baseline */
static int verify_baseline(const char *path)
{
    FILE *fp;
    struct baseline_header header;
    struct prog_baseline_entry *baseline_progs;
    struct map_baseline_entry *baseline_maps;
    int differences = 0;

    /* Read baseline */
    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot read baseline file: %s\n",
                strerror(errno));
        return -1;
    }

    if (fread(&header, sizeof(header), 1, fp) != 1 ||
        strcmp(header.magic, "BPFBASE") != 0) {
        fprintf(stderr, "ERROR: Invalid baseline file format\n");
        fclose(fp);
        return -1;
    }

    printf("Baseline info:\n");
    printf("  Created: %s", ctime(&header.timestamp));
    printf("  Kernel:  %s\n", header.kernel_version);
    printf("  Programs: %d, Maps: %d\n\n",
           header.prog_count, header.map_count);

    /* Read baseline programs */
    baseline_progs = calloc(header.prog_count,
                            sizeof(struct prog_baseline_entry));
    if (!baseline_progs) {
        fclose(fp);
        return -1;
    }
    fread(baseline_progs, sizeof(struct prog_baseline_entry),
          header.prog_count, fp);

    /* Read baseline maps */
    baseline_maps = calloc(header.map_count,
                           sizeof(struct map_baseline_entry));
    if (!baseline_maps) {
        free(baseline_progs);
        fclose(fp);
        return -1;
    }
    fread(baseline_maps, sizeof(struct map_baseline_entry),
          header.map_count, fp);

    fclose(fp);

    /* Enumerate current state */
    enumerate_progs();
    enumerate_maps();

    printf("Current state:\n");
    printf("  Programs: %d, Maps: %d\n\n",
           current_prog_count, current_map_count);

    /* Compare programs */
    printf("--- Program Comparison ---\n\n");

    /* Check for new programs (in current but not in baseline) */
    for (int i = 0; i < current_prog_count; i++) {
        int found = 0;
        for (int j = 0; j < header.prog_count; j++) {
            /* Match by tag (program content hash) and type */
            if (memcmp(current_progs[i].tag, baseline_progs[j].tag, 8) == 0 &&
                current_progs[i].type == baseline_progs[j].type) {
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("  [NEW] Program ID=%u Type=%-16s Name=%-16s\n",
                   current_progs[i].id,
                   prog_type_str(current_progs[i].type),
                   current_progs[i].name[0] ? current_progs[i].name :
                   "(unnamed)");
            printf("    Tag: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   current_progs[i].tag[0], current_progs[i].tag[1],
                   current_progs[i].tag[2], current_progs[i].tag[3],
                   current_progs[i].tag[4], current_progs[i].tag[5],
                   current_progs[i].tag[6], current_progs[i].tag[7]);
            printf("    INVESTIGATE: This program was not in the baseline.\n\n");
            differences++;
        }
    }

    /* Check for removed programs (in baseline but not in current) */
    for (int j = 0; j < header.prog_count; j++) {
        int found = 0;
        for (int i = 0; i < current_prog_count; i++) {
            if (memcmp(current_progs[i].tag, baseline_progs[j].tag, 8) == 0 &&
                current_progs[i].type == baseline_progs[j].type) {
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("  [REMOVED] Type=%-16s Name=%-16s (was ID=%u)\n",
                   prog_type_str(baseline_progs[j].type),
                   baseline_progs[j].name[0] ? baseline_progs[j].name :
                   "(unnamed)",
                   baseline_progs[j].id);
            printf("    NOTE: Program from baseline is no longer loaded.\n\n");
            differences++;
        }
    }

    /* Compare maps */
    printf("--- Map Comparison ---\n\n");

    for (int i = 0; i < current_map_count; i++) {
        int found = 0;
        for (int j = 0; j < header.map_count; j++) {
            if (current_maps[i].type == baseline_maps[j].type &&
                strcmp(current_maps[i].name, baseline_maps[j].name) == 0 &&
                current_maps[i].key_size == baseline_maps[j].key_size &&
                current_maps[i].value_size == baseline_maps[j].value_size) {
                found = 1;
                break;
            }
        }
        if (!found && current_maps[i].name[0]) {
            printf("  [NEW MAP] ID=%u Type=%-16s Name=%-16s "
                   "Key=%uB Val=%uB\n",
                   current_maps[i].id,
                   map_type_str(current_maps[i].type),
                   current_maps[i].name,
                   current_maps[i].key_size,
                   current_maps[i].value_size);
            differences++;
        }
    }

    /* Summary */
    printf("\n================================================\n");
    printf("  VERIFICATION RESULT\n");
    printf("================================================\n");
    printf("  Differences found: %d\n", differences);

    if (differences == 0) {
        printf("  Status: CLEAN - Current state matches baseline.\n");
    } else {
        printf("  Status: CHANGES DETECTED - Investigate above items.\n");
        printf("\n  RECOMMENDATION:\n");
        printf("  - NEW programs may be legitimate (tool updates) or "
               "suspicious.\n");
        printf("  - REMOVED programs may indicate cleanup or "
               "interference.\n");
        printf("  - Cross-reference with known tools and recent changes.\n");
    }

    printf("================================================\n");

    free(baseline_progs);
    free(baseline_maps);

    return differences;
}

/* List current state */
static void list_current(int verbose)
{
    enumerate_progs();
    enumerate_maps();

    printf("======================================================\n");
    printf("  Current BPF State\n");
    printf("======================================================\n\n");

    printf("--- Programs (%d) ---\n\n", current_prog_count);
    for (int i = 0; i < current_prog_count; i++) {
        printf("  ID=%-6u Type=%-16s Name=%-16s",
               current_progs[i].id,
               prog_type_str(current_progs[i].type),
               current_progs[i].name[0] ? current_progs[i].name : "(unnamed)");

        if (verbose) {
            printf("  Tag=%02x%02x%02x%02x Insns=%u RunCnt=%llu",
                   current_progs[i].tag[0], current_progs[i].tag[1],
                   current_progs[i].tag[2], current_progs[i].tag[3],
                   current_progs[i].xlated_prog_len / 8,
                   (unsigned long long)current_progs[i].run_cnt);
        }
        printf("\n");
    }

    printf("\n--- Maps (%d) ---\n\n", current_map_count);
    for (int i = 0; i < current_map_count; i++) {
        printf("  ID=%-6u Type=%-16s Name=%-16s Key=%uB Val=%uB Max=%u\n",
               current_maps[i].id,
               map_type_str(current_maps[i].type),
               current_maps[i].name[0] ? current_maps[i].name : "(unnamed)",
               current_maps[i].key_size,
               current_maps[i].value_size,
               current_maps[i].max_entries);
    }

    printf("\n======================================================\n");
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [options]\n", prog);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  --save <file>     Save current state as baseline\n");
    fprintf(stderr, "  --verify <file>   Verify current state against baseline\n");
    fprintf(stderr, "  --list            List current BPF programs and maps\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v                Verbose output\n");
    fprintf(stderr, "\nDefensive Tool: BPF program baseline and integrity monitoring.\n");
}

int main(int argc, char **argv)
{
    int verbose = 0;
    static struct option long_opts[] = {
        {"save",   required_argument, 0, 's'},
        {"verify", required_argument, 0, 'c'},
        {"list",   no_argument,       0, 'l'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    char action = 0;
    const char *file_arg = NULL;

    while ((opt = getopt_long(argc, argv, "vs:c:lh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 's': action = 's'; file_arg = optarg; break;
        case 'c': action = 'c'; file_arg = optarg; break;
        case 'l': action = 'l'; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges.\n");
        return 1;
    }

    if (!action) {
        usage(argv[0]);
        return 1;
    }

    switch (action) {
    case 's':
        return save_baseline(file_arg) == 0 ? 0 : 1;
    case 'c':
        return verify_baseline(file_arg);
    case 'l':
        list_current(verbose);
        return 0;
    default:
        usage(argv[0]);
        return 1;
    }
}

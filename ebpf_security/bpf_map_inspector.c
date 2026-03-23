/*
 * bpf_map_inspector.c - Inspect BPF Maps and Their Contents
 * ===========================================================
 *
 * This program enumerates all BPF maps on the system and allows
 * inspection of their contents. Maps are the primary data storage
 * mechanism for BPF programs and can contain sensitive information.
 *
 *
 * COMPILATION:
 *   gcc -O2 -o bpf_map_inspector bpf_map_inspector.c
 *
 * USAGE:
 *   sudo ./bpf_map_inspector [-v] [-d map_id] [-a]
 *
 *   -v          Verbose mode
 *   -d map_id   Dump contents of specific map
 *   -a          Show all maps (including internal)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <getopt.h>

/* Direct bpf() syscall wrapper */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                           unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* BPF map type names */
static const char *map_type_name(enum bpf_map_type type)
{
    static const char *names[] = {
        [BPF_MAP_TYPE_UNSPEC]              = "unspec",
        [BPF_MAP_TYPE_HASH]                = "hash",
        [BPF_MAP_TYPE_ARRAY]               = "array",
        [BPF_MAP_TYPE_PROG_ARRAY]          = "prog_array",
        [BPF_MAP_TYPE_PERF_EVENT_ARRAY]    = "perf_event_array",
        [BPF_MAP_TYPE_PERCPU_HASH]         = "percpu_hash",
        [BPF_MAP_TYPE_PERCPU_ARRAY]        = "percpu_array",
        [BPF_MAP_TYPE_STACK_TRACE]         = "stack_trace",
        [BPF_MAP_TYPE_CGROUP_ARRAY]        = "cgroup_array",
        [BPF_MAP_TYPE_LRU_HASH]            = "lru_hash",
        [BPF_MAP_TYPE_LRU_PERCPU_HASH]     = "lru_percpu_hash",
        [BPF_MAP_TYPE_LPM_TRIE]            = "lpm_trie",
        [BPF_MAP_TYPE_ARRAY_OF_MAPS]       = "array_of_maps",
        [BPF_MAP_TYPE_HASH_OF_MAPS]        = "hash_of_maps",
        [BPF_MAP_TYPE_DEVMAP]              = "devmap",
        [BPF_MAP_TYPE_SOCKMAP]             = "sockmap",
        [BPF_MAP_TYPE_CPUMAP]              = "cpumap",
        [BPF_MAP_TYPE_XSKMAP]              = "xskmap",
        [BPF_MAP_TYPE_SOCKHASH]            = "sockhash",
        [BPF_MAP_TYPE_CGROUP_STORAGE]      = "cgroup_storage",
        [BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "reuseport_sockarray",
        [BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE] = "percpu_cgroup_storage",
        [BPF_MAP_TYPE_QUEUE]               = "queue",
        [BPF_MAP_TYPE_STACK]               = "stack",
        [BPF_MAP_TYPE_SK_STORAGE]          = "sk_storage",
        [BPF_MAP_TYPE_DEVMAP_HASH]         = "devmap_hash",
        [BPF_MAP_TYPE_STRUCT_OPS]          = "struct_ops",
        [BPF_MAP_TYPE_RINGBUF]             = "ringbuf",
        [BPF_MAP_TYPE_INODE_STORAGE]       = "inode_storage",
        [BPF_MAP_TYPE_TASK_STORAGE]        = "task_storage",
        [BPF_MAP_TYPE_BLOOM_FILTER]        = "bloom_filter",
    };

    if (type < sizeof(names)/sizeof(names[0]) && names[type])
        return names[type];
    return "unknown";
}

/* Security classification for map types */
static const char *map_security_note(enum bpf_map_type type)
{
    switch (type) {
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_LRU_HASH:
        return "Key-value storage - check for sensitive data";
    case BPF_MAP_TYPE_RINGBUF:
        return "Event streaming - potential exfiltration channel";
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        return "Perf events - data streaming to userspace";
    case BPF_MAP_TYPE_PROG_ARRAY:
        return "Tail call table - check for unexpected programs";
    case BPF_MAP_TYPE_ARRAY:
        return "Fixed array - check for config or staged data";
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return "Per-CPU storage - high-performance data collection";
    default:
        return "";
    }
}

/* Get map FD by ID */
static int get_map_fd(unsigned int id)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_id = id;

    return sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

/* Get next map ID */
static int get_next_map_id(unsigned int *id)
{
    union bpf_attr attr;
    int err;

    memset(&attr, 0, sizeof(attr));
    attr.start_id = *id;

    err = sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
    if (err == 0)
        *id = attr.next_id;

    return err;
}

/* Get map info by FD */
static int get_map_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    memset(info, 0, sizeof(*info));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (unsigned long)info;

    return sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

/* Print hex dump of a buffer */
static void hex_dump(const unsigned char *data, size_t len, const char *prefix)
{
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        printf("%s%04zx: ", prefix, i);

        /* Hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        /* ASCII */
        printf(" |");
        for (j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

/* Check if data contains printable strings */
static int contains_strings(const unsigned char *data, size_t len)
{
    size_t printable = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        if (isprint(data[i]) || data[i] == '\0')
            printable++;
    }

    /* If more than 60% printable, likely contains strings */
    return (printable * 100 / len) > 60;
}

/* Dump contents of a specific map */
static int dump_map_contents(unsigned int map_id, int max_entries)
{
    int fd;
    struct bpf_map_info info;
    union bpf_attr attr;
    unsigned char *key, *value, *next_key;
    int count = 0;

    fd = get_map_fd(map_id);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot open map ID %u: %s\n",
                map_id, strerror(errno));
        return -1;
    }

    if (get_map_info(fd, &info) != 0) {
        fprintf(stderr, "ERROR: Cannot get info for map ID %u: %s\n",
                map_id, strerror(errno));
        close(fd);
        return -1;
    }

    printf("\nDumping map ID %u (%s, type=%s)\n",
           map_id, info.name[0] ? info.name : "(unnamed)",
           map_type_name(info.type));
    printf("Key size: %u bytes, Value size: %u bytes, Max entries: %u\n",
           info.key_size, info.value_size, info.max_entries);
    printf("---\n");

    /* Cannot iterate all map types */
    if (info.type == BPF_MAP_TYPE_RINGBUF ||
        info.type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
        info.type == BPF_MAP_TYPE_PROG_ARRAY) {
        printf("  (Map type %s does not support key iteration)\n",
               map_type_name(info.type));
        close(fd);
        return 0;
    }

    key = calloc(1, info.key_size);
    next_key = calloc(1, info.key_size);
    value = calloc(1, info.value_size);

    if (!key || !next_key || !value) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        close(fd);
        free(key);
        free(next_key);
        free(value);
        return -1;
    }

    /* Iterate map entries using BPF_MAP_GET_NEXT_KEY */
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;

    /* Get first key */
    memset(key, 0, info.key_size);
    attr.key = (unsigned long)NULL;
    attr.next_key = (unsigned long)next_key;

    if (sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) != 0) {
        printf("  (Map is empty)\n");
        goto done;
    }

    do {
        memcpy(key, next_key, info.key_size);

        /* Lookup value for this key */
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = fd;
        attr.key = (unsigned long)key;
        attr.value = (unsigned long)value;

        if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0) {
            printf("\n  Entry %d:\n", count);
            printf("  Key:\n");
            hex_dump(key, info.key_size, "    ");
            printf("  Value:\n");
            hex_dump(value, info.value_size, "    ");

            /* Check for string-like content */
            if (contains_strings(value, info.value_size)) {
                printf("  [NOTE: Value appears to contain string data]\n");
            }
        }

        count++;
        if (max_entries > 0 && count >= max_entries) {
            printf("\n  (Showing first %d entries, use -n to change)\n",
                   max_entries);
            break;
        }

        /* Get next key */
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = fd;
        attr.key = (unsigned long)key;
        attr.next_key = (unsigned long)next_key;

    } while (sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0);

    printf("\n  Total entries dumped: %d\n", count);

done:
    free(key);
    free(next_key);
    free(value);
    close(fd);
    return 0;
}

/* Print map info */
static void print_map_info(struct bpf_map_info *info, int verbose)
{
    size_t total_size;
    const char *security_note;

    total_size = (size_t)info->key_size + (size_t)info->value_size;
    total_size *= info->max_entries;

    printf("  ID: %-6u  Type: %-20s  Name: %-16s\n",
           info->id, map_type_name(info->type),
           info->name[0] ? info->name : "(unnamed)");

    if (verbose) {
        printf("    Key size: %-4u  Value size: %-6u  Max entries: %-8u  "
               "Est. size: %zu bytes\n",
               info->key_size, info->value_size, info->max_entries,
               total_size);
        printf("    Flags: 0x%x\n", info->map_flags);

        security_note = map_security_note(info->type);
        if (security_note[0])
            printf("    Security note: %s\n", security_note);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-d map_id] [-n max_entries] [-a]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v            Verbose mode\n");
    fprintf(stderr, "  -d map_id     Dump contents of specific map\n");
    fprintf(stderr, "  -n max_entries Max entries to dump (default: 10)\n");
    fprintf(stderr, "  -a            Show all maps including internal\n");
    fprintf(stderr, "\nDefensive Security Tool: Inspects BPF maps for auditing.\n");
}

int main(int argc, char **argv)
{
    int verbose = 0, show_all = 0;
    int dump_id = -1;
    int max_entries = 10;
    int opt;
    unsigned int id = 0;
    int count = 0;
    size_t total_memory = 0;

    while ((opt = getopt(argc, argv, "vd:n:ah")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'd':
            dump_id = atoi(optarg);
            break;
        case 'n':
            max_entries = atoi(optarg);
            break;
        case 'a':
            show_all = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges.\n");
        return 1;
    }

    /* If dump mode, dump specific map and exit */
    if (dump_id >= 0) {
        return dump_map_contents(dump_id, max_entries) == 0 ? 0 : 1;
    }

    /* List all maps */
    printf("======================================"
           "==================================\n");
    printf("  BPF Map Inspector - Defensive Security Audit Tool\n");
    printf("======================================"
           "==================================\n");
    printf("  Scan time: ");
    time_t now = time(NULL);
    printf("%s", ctime(&now));
    printf("======================================"
           "==================================\n\n");

    while (get_next_map_id(&id) == 0) {
        int fd;
        struct bpf_map_info info;

        fd = get_map_fd(id);
        if (fd < 0)
            continue;

        if (get_map_info(fd, &info) != 0) {
            close(fd);
            continue;
        }
        close(fd);

        /* Skip internal maps unless -a is specified */
        if (!show_all && info.name[0] == '.' )
            continue;

        print_map_info(&info, verbose);

        if (verbose)
            printf("\n");

        count++;
        total_memory += (size_t)(info.key_size + info.value_size)
                        * info.max_entries;
    }

    printf("\n======================================"
           "==================================\n");
    printf("  Summary: %d maps found\n", count);
    printf("  Estimated total memory: %zu bytes (%zu KB)\n",
           total_memory, total_memory / 1024);
    printf("======================================"
           "==================================\n");
    printf("\n  Use -d <map_id> to dump specific map contents.\n");

    return 0;
}

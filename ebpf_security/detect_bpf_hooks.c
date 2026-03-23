/*
 * detect_bpf_hooks.c - Detect BPF Programs Attached to Sensitive Functions
 * =========================================================================
 *
 * This program detects BPF programs that are attached to security-sensitive
 * kernel functions. It enumerates all loaded BPF programs and checks their
 * attachment points against a list of high-value targets.
 *
 *
 * COMPILATION:
 *   gcc -O2 -o detect_bpf_hooks detect_bpf_hooks.c
 *
 * USAGE:
 *   sudo ./detect_bpf_hooks [-v]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <ctype.h>

/* Direct bpf() syscall wrapper */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                           unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/*
 * Sensitive kernel functions that should be monitored for BPF attachments.
 * Any BPF program hooking these functions warrants investigation.
 */
struct sensitive_function {
    const char *name;
    const char *category;
    const char *risk_description;
};

static const struct sensitive_function sensitive_funcs[] = {
    /* Credential and authentication */
    {"commit_creds",         "CRED",    "Credential modification (privesc indicator)"},
    {"prepare_creds",        "CRED",    "Credential preparation"},
    {"copy_creds",           "CRED",    "Credential copying"},
    {"override_creds",       "CRED",    "Credential override"},
    {"revert_creds",         "CRED",    "Credential revert"},
    {"set_current_groups",   "CRED",    "Group modification"},

    /* System calls - execution */
    {"do_execveat_common",   "EXEC",    "Process execution (all execve)"},
    {"__x64_sys_execve",     "EXEC",    "execve syscall entry"},
    {"__x64_sys_execveat",   "EXEC",    "execveat syscall entry"},
    {"search_binary_handler","EXEC",    "Binary handler lookup"},
    {"load_elf_binary",      "EXEC",    "ELF binary loading"},

    /* File operations */
    {"do_sys_openat2",       "FILE",    "File open (all open operations)"},
    {"do_filp_open",         "FILE",    "Internal file open"},
    {"vfs_read",             "FILE",    "File read (data access)"},
    {"vfs_write",            "FILE",    "File write (data modification)"},
    {"do_unlinkat",          "FILE",    "File deletion"},
    {"vfs_rename",           "FILE",    "File rename/move"},

    /* Network */
    {"tcp_v4_connect",       "NET",     "Outbound TCP connection"},
    {"tcp_v6_connect",       "NET",     "Outbound TCP6 connection"},
    {"tcp_sendmsg",          "NET",     "TCP data transmission"},
    {"tcp_recvmsg",          "NET",     "TCP data reception"},
    {"udp_sendmsg",          "NET",     "UDP data transmission"},
    {"udp_recvmsg",          "NET",     "UDP data reception"},
    {"ip_local_out",         "NET",     "IP packet output"},
    {"inet_csk_accept",      "NET",     "TCP accept (new connection)"},

    /* Module loading */
    {"do_init_module",       "MODULE",  "Module initialization"},
    {"__x64_sys_init_module","MODULE",  "init_module syscall"},
    {"__x64_sys_finit_module","MODULE", "finit_module syscall"},
    {"load_module",          "MODULE",  "Module loading"},

    /* BPF operations (meta - watching the watchers) */
    {"__x64_sys_bpf",       "BPF",     "bpf() syscall (meta-hook)"},
    {"bpf_prog_load",       "BPF",     "BPF program loading"},
    {"bpf_check",           "BPF",     "BPF verifier entry"},

    /* Security / LSM */
    {"security_file_open",   "SEC",     "LSM file open check"},
    {"security_bprm_check",  "SEC",     "LSM exec check"},
    {"security_socket_connect","SEC",   "LSM socket connect check"},
    {"security_task_kill",   "SEC",     "LSM kill check"},
    {"security_inode_create","SEC",     "LSM inode creation check"},

    /* Process management */
    {"do_exit",              "PROC",    "Process exit"},
    {"__x64_sys_clone",      "PROC",    "Process/thread creation"},
    {"__x64_sys_kill",       "PROC",    "Signal sending"},
    {"__x64_sys_ptrace",     "PROC",    "Process tracing/debugging"},

    {NULL, NULL, NULL}  /* Sentinel */
};

/*
 * Check /sys/kernel/debug/kprobes/list for active kprobes
 * Returns number of suspicious kprobes found
 */
static int check_kprobe_list(int verbose)
{
    FILE *fp;
    char line[1024];
    int suspicious_count = 0;

    fp = fopen("/sys/kernel/debug/kprobes/list", "r");
    if (!fp) {
        fprintf(stderr, "  WARNING: Cannot read /sys/kernel/debug/kprobes/list\n");
        fprintf(stderr, "  (mount debugfs: mount -t debugfs none /sys/kernel/debug)\n\n");
        return -1;
    }

    printf("\n--- Active kprobes on sensitive functions ---\n\n");

    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline */
        line[strcspn(line, "\n")] = 0;

        /* Check each sensitive function */
        for (int i = 0; sensitive_funcs[i].name; i++) {
            if (strstr(line, sensitive_funcs[i].name)) {
                printf("  ALERT [%s] kprobe detected on: %s\n",
                       sensitive_funcs[i].category,
                       sensitive_funcs[i].name);
                printf("    Risk: %s\n", sensitive_funcs[i].risk_description);
                printf("    kprobe details: %s\n\n", line);
                suspicious_count++;
            }
        }

        if (verbose) {
            /* Show all kprobes */
            printf("  Active kprobe: %s\n", line);
        }
    }

    fclose(fp);

    if (suspicious_count == 0)
        printf("  No kprobes on sensitive functions detected.\n");

    return suspicious_count;
}

/*
 * Check /sys/kernel/debug/tracing/uprobe_events for active uprobes
 * Uprobes on PAM, SSL, and auth libraries are especially concerning.
 */
static int check_uprobe_events(int verbose)
{
    FILE *fp;
    char line[1024];
    int suspicious_count = 0;

    /* Sensitive library patterns */
    static const char *sensitive_libs[] = {
        "libpam",
        "libssl",
        "libcrypto",
        "libgnutls",
        "libssh",
        "libnss",
        "libkrb5",
        "libsasl",
        NULL
    };

    fp = fopen("/sys/kernel/debug/tracing/uprobe_events", "r");
    if (!fp) {
        if (verbose)
            fprintf(stderr, "  WARNING: Cannot read uprobe_events\n");
        return -1;
    }

    printf("\n--- Active uprobes on sensitive libraries ---\n\n");

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;

        for (int i = 0; sensitive_libs[i]; i++) {
            if (strstr(line, sensitive_libs[i])) {
                printf("  ALERT: uprobe on sensitive library detected!\n");
                printf("    Library: %s\n", sensitive_libs[i]);
                printf("    Details: %s\n\n", line);
                suspicious_count++;
                break;
            }
        }

        if (verbose) {
            printf("  Active uprobe: %s\n", line);
        }
    }

    fclose(fp);

    if (suspicious_count == 0)
        printf("  No uprobes on sensitive libraries detected.\n");

    return suspicious_count;
}

/*
 * Enumerate BPF programs and check their types for high-risk categories
 */
static int check_bpf_programs(int verbose)
{
    union bpf_attr attr;
    unsigned int id = 0;
    int suspicious_count = 0;
    int total_count = 0;

    printf("\n--- BPF program type analysis ---\n\n");

    while (1) {
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

        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0) {
            close(fd);
            continue;
        }
        close(fd);
        total_count++;

        /* Check for high-risk program types */
        int is_suspicious = 0;
        const char *concern = "";

        switch (info.type) {
        case BPF_PROG_TYPE_KPROBE:
            is_suspicious = 1;
            concern = "Can hook any kernel function";
            break;
        case BPF_PROG_TYPE_TRACING:
            is_suspicious = 1;
            concern = "fentry/fexit - can modify returns";
            break;
        case BPF_PROG_TYPE_LSM:
            is_suspicious = 1;
            concern = "Can override security policy decisions";
            break;
        case BPF_PROG_TYPE_XDP:
            is_suspicious = 1;
            concern = "Can drop/redirect network packets";
            break;
        case BPF_PROG_TYPE_SCHED_CLS:
            is_suspicious = 1;
            concern = "Can manipulate network traffic (TC)";
            break;
        default:
            if (verbose) {
                printf("  [OK] ID=%-6u Type=%-20s Name=%s\n",
                       info.id,
                       info.type <= 31 ? "known" : "unknown",
                       info.name[0] ? info.name : "(unnamed)");
            }
            break;
        }

        if (is_suspicious) {
            printf("  REVIEW [ID=%-6u] Type=%-12u Name=%-16s\n",
                   info.id, info.type,
                   info.name[0] ? info.name : "(unnamed)");
            printf("    Concern: %s\n", concern);
            printf("    Instructions: %u, Run count: %llu\n",
                   info.xlated_prog_len / 8,
                   (unsigned long long)info.run_cnt);

            if (info.run_cnt > 0)
                printf("    NOTE: Program has been actively executing "
                       "(run_count > 0)\n");

            printf("\n");
            suspicious_count++;
        }
    }

    printf("  Total programs: %d, Requiring review: %d\n",
           total_count, suspicious_count);

    return suspicious_count;
}

/*
 * Check for BPF programs pinned to /sys/fs/bpf/
 */
static int check_bpf_pins(int verbose)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    printf("\n--- Pinned BPF objects (/sys/fs/bpf/) ---\n\n");

    dir = opendir("/sys/fs/bpf");
    if (!dir) {
        fprintf(stderr, "  WARNING: Cannot open /sys/fs/bpf/\n");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        printf("  Pinned object: /sys/fs/bpf/%s\n", entry->d_name);

        /* Check for suspicious naming patterns */
        if (entry->d_name[0] == '.' && entry->d_name[1] != '\0') {
            printf("    ALERT: Hidden pin (starts with dot)\n");
        }

        /* Check for unexpected pins */
        int is_known = 0;
        static const char *known_prefixes[] = {
            "tc", "ip", "cilium", "calico", "xdp",
            "bpftools", NULL
        };
        for (int i = 0; known_prefixes[i]; i++) {
            if (strstr(entry->d_name, known_prefixes[i])) {
                is_known = 1;
                break;
            }
        }
        if (!is_known) {
            printf("    NOTE: Pin does not match known tool prefixes\n");
        }

        count++;
    }

    closedir(dir);

    if (count == 0)
        printf("  No pinned BPF objects found.\n");
    else
        printf("\n  Total pinned objects: %d\n", count);

    return count;
}

/*
 * Check for XDP programs attached to network interfaces
 */
static int check_xdp_attachments(int verbose)
{
    FILE *fp;
    char line[4096];
    int xdp_count = 0;

    printf("\n--- XDP program attachments ---\n\n");

    fp = popen("ip -d link show 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "  WARNING: Cannot execute 'ip link show'\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "xdp") || strstr(line, "XDP")) {
            printf("  DETECTED: %s", line);
            xdp_count++;
        }
    }

    pclose(fp);

    if (xdp_count == 0)
        printf("  No XDP programs detected on interfaces.\n");

    return xdp_count;
}

int main(int argc, char **argv)
{
    int verbose = 0;
    int total_alerts = 0;
    int opt;

    while ((opt = getopt(argc, argv, "vh")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'h':
            printf("Usage: %s [-v]\n", argv[0]);
            printf("\nDetect BPF programs attached to sensitive kernel functions.\n");
            printf("  -v  Verbose mode (show all programs, not just suspicious)\n");
            return 0;
        default:
            return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges.\n");
        return 1;
    }

    printf("====================================================\n");
    printf("  BPF Hook Detector - Defensive Security Audit Tool\n");
    printf("====================================================\n");

    int result;

    /* Check 1: kprobe list */
    result = check_kprobe_list(verbose);
    if (result > 0) total_alerts += result;

    /* Check 2: uprobe events */
    result = check_uprobe_events(verbose);
    if (result > 0) total_alerts += result;

    /* Check 3: BPF program analysis */
    result = check_bpf_programs(verbose);
    if (result > 0) total_alerts += result;

    /* Check 4: Pinned objects */
    check_bpf_pins(verbose);

    /* Check 5: XDP attachments */
    result = check_xdp_attachments(verbose);
    if (result > 0) total_alerts += result;

    /* Summary */
    printf("\n====================================================\n");
    printf("  SCAN COMPLETE\n");
    printf("====================================================\n");
    printf("  Total alerts: %d\n", total_alerts);

    if (total_alerts > 0) {
        printf("\n  RECOMMENDATION: Investigate each alert above.\n");
        printf("  Cross-reference with known security tools (Falco,\n");
        printf("  Tetragon, Cilium, etc.) to filter false positives.\n");
    } else {
        printf("  No suspicious BPF hooks detected.\n");
    }

    printf("====================================================\n");

    return total_alerts > 0 ? 1 : 0;
}

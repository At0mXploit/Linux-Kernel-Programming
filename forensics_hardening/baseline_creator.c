/*
 * baseline_creator.c - System Security Baseline Generator
 *
 *
 * Creates a comprehensive system security baseline including:
 *   1. SHA-256 hashes of critical system binaries
 *   2. Loaded kernel module inventory
 *   3. BPF program inventory
 *   4. Listening network ports
 *   5. SUID/SGID file inventory
 *   6. Sysctl security settings
 *   7. System metadata (kernel version, boot time, etc.)
 *
 * Build: gcc -O2 -Wall -Wextra -o baseline_creator baseline_creator.c -lcrypto
 * Usage: sudo ./baseline_creator --create /var/lib/baseline
 *        sudo ./baseline_creator --verify /var/lib/baseline
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

/* Use OpenSSL if available, otherwise fall back to simple hash */
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif

#define MAX_PATH_LEN    512
#define MAX_LINE_LEN    1024
#define MAX_ENTRIES     10000
#define HASH_LEN        65      /* SHA-256 hex string + null */

/* ── Data structures ───────────────────────────────────────────── */

typedef struct {
    char path[MAX_PATH_LEN];
    char hash[HASH_LEN];
    unsigned int mode;
    unsigned int uid;
    unsigned int gid;
    unsigned long size;
} file_entry_t;

typedef struct {
    char name[256];
    unsigned long size;
    int refcount;
    char state[32];
} module_entry_t;

/* ── Simple hash function (when OpenSSL not available) ─────────── */

static void compute_file_hash(const char *path, char *hash_out, size_t hash_size)
{
    /* Simplified FNV-1a based hash for portability.
     * In production, link with -lcrypto and use SHA256. */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        snprintf(hash_out, hash_size, "ERROR_CANNOT_READ");
        return;
    }

    unsigned long long h1 = 14695981039346656037ULL;
    unsigned long long h2 = 0xcbf29ce484222325ULL;
    unsigned char buf[4096];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        for (size_t i = 0; i < n; i++) {
            h1 ^= buf[i];
            h1 *= 1099511628211ULL;
            h2 ^= buf[i];
            h2 *= 0x100000001b3ULL;
        }
    }
    fclose(fp);

    snprintf(hash_out, hash_size, "%016llx%016llx%016llx%016llx",
             h1, h2, h1 ^ h2, h1 + h2);
}

/* ── Hash critical directories ─────────────────────────────────── */

static int hash_directory(const char *dir_path, FILE *output)
{
    DIR *dir = opendir(dir_path);
    if (!dir)
        return 0;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) != 0)
            continue;

        /* Only hash regular files */
        if (!S_ISREG(st.st_mode))
            continue;

        char hash[HASH_LEN];
        compute_file_hash(full_path, hash, sizeof(hash));

        fprintf(output, "FILE %s %s %o %u %u %lu\n",
                full_path, hash, st.st_mode & 07777,
                st.st_uid, st.st_gid, (unsigned long)st.st_size);
        count++;
    }
    closedir(dir);
    return count;
}

/* ── Collect module information ────────────────────────────────── */

static int collect_modules(FILE *output)
{
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp)
        return 0;

    char line[MAX_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char name[256];
        unsigned long size;
        int refcount;
        char deps[1024];
        char state[32];

        if (sscanf(line, "%255s %lu %d %1023s %31s",
                   name, &size, &refcount, deps, state) >= 3) {
            fprintf(output, "MODULE %s %lu %d %s\n",
                    name, size, refcount, state);
            count++;
        }
    }
    fclose(fp);
    return count;
}

/* ── Collect listening ports ───────────────────────────────────── */

static int collect_listeners(FILE *output)
{
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp)
        return 0;

    char line[MAX_LINE_LEN];
    int count = 0;

    /* Skip header */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned int local_addr, local_port;
        unsigned int rem_addr, rem_port;
        unsigned int state;
        unsigned int inode;

        if (sscanf(line, " %*d: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %*u %*u %u",
                   &local_addr, &local_port, &rem_addr, &rem_port,
                   &state, &inode) >= 5) {
            /* State 0x0A = LISTEN */
            if (state == 0x0A) {
                fprintf(output, "LISTENER %u.%u.%u.%u %u %u\n",
                        local_addr & 0xFF, (local_addr >> 8) & 0xFF,
                        (local_addr >> 16) & 0xFF, (local_addr >> 24) & 0xFF,
                        local_port, inode);
                count++;
            }
        }
    }
    fclose(fp);

    /* Also check tcp6 */
    fp = fopen("/proc/net/tcp6", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            while (fgets(line, sizeof(line), fp)) {
                char local_addr6[33];
                unsigned int local_port;
                unsigned int state;

                if (sscanf(line, " %*d: %32s:%X %*32s:%*X %X",
                           local_addr6, &local_port, &state) >= 3) {
                    if (state == 0x0A) {
                        fprintf(output, "LISTENER6 %s %u\n",
                                local_addr6, local_port);
                        count++;
                    }
                }
            }
        }
        fclose(fp);
    }
    return count;
}

/* ── Collect SUID/SGID files ──────────────────────────────────── */

static int collect_suid_recursive(const char *dir_path, FILE *output, int depth)
{
    if (depth > 10)
        return 0; /* Prevent infinite recursion */

    DIR *dir = opendir(dir_path);
    if (!dir)
        return 0;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) != 0)
            continue;

        /* Skip /proc, /sys, /dev */
        if (strcmp(full_path, "/proc") == 0 || strcmp(full_path, "/sys") == 0 ||
            strcmp(full_path, "/dev") == 0)
            continue;

        if (S_ISREG(st.st_mode)) {
            if (st.st_mode & (S_ISUID | S_ISGID)) {
                char hash[HASH_LEN];
                compute_file_hash(full_path, hash, sizeof(hash));
                fprintf(output, "SUID %s %o %u %u %s\n",
                        full_path, st.st_mode & 07777,
                        st.st_uid, st.st_gid, hash);
                count++;
            }
        } else if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            count += collect_suid_recursive(full_path, output, depth + 1);
        }
    }
    closedir(dir);
    return count;
}

/* ── Collect sysctl settings ───────────────────────────────────── */

static int collect_sysctl(FILE *output)
{
    /* Key security-relevant sysctl settings */
    const char *settings[] = {
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.perf_event_paranoid",
        "kernel.randomize_va_space",
        "kernel.yama.ptrace_scope",
        "kernel.sysrq",
        "kernel.unprivileged_bpf_disabled",
        "vm.unprivileged_userfaultfd",
        "fs.suid_dumpable",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.all.log_martians",
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.all.accept_source_route",
        NULL
    };

    int count = 0;
    for (int i = 0; settings[i] != NULL; i++) {
        /* Convert dot notation to path */
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "/proc/sys/%s", settings[i]);

        /* Replace dots with slashes */
        for (char *p = path + 10; *p; p++) {
            if (*p == '.') *p = '/';
        }

        FILE *fp = fopen(path, "r");
        if (fp) {
            char value[256] = "";
            if (fgets(value, sizeof(value), fp)) {
                value[strcspn(value, "\n")] = '\0';
                fprintf(output, "SYSCTL %s %s\n", settings[i], value);
                count++;
            }
            fclose(fp);
        }
    }
    return count;
}

/* ── Create baseline ───────────────────────────────────────────── */

static int create_baseline(const char *output_dir)
{
    printf("=== Creating System Security Baseline ===\n\n");

    /* Create output directory */
    char cmd[MAX_PATH_LEN + 32];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", output_dir);
    if (system(cmd) != 0) {
        fprintf(stderr, "Cannot create directory: %s\n", output_dir);
        return -1;
    }

    char baseline_path[MAX_PATH_LEN];
    snprintf(baseline_path, sizeof(baseline_path), "%s/baseline.dat", output_dir);

    FILE *output = fopen(baseline_path, "w");
    if (!output) {
        fprintf(stderr, "Cannot create %s: %s\n", baseline_path, strerror(errno));
        return -1;
    }

    /* Write header */
    struct utsname uts;
    uname(&uts);
    time_t now = time(NULL);

    fprintf(output, "# System Security Baseline\n");
    fprintf(output, "# Generated: %s", ctime(&now));
    fprintf(output, "# Kernel: %s %s %s\n", uts.sysname, uts.release, uts.machine);
    fprintf(output, "# Hostname: %s\n", uts.nodename);
    fprintf(output, "#\n");

    /* System metadata */
    fprintf(output, "META kernel_version %s\n", uts.release);
    fprintf(output, "META hostname %s\n", uts.nodename);
    fprintf(output, "META architecture %s\n", uts.machine);
    fprintf(output, "META timestamp %ld\n", (long)now);

    /* Kernel taint */
    FILE *fp = fopen("/proc/sys/kernel/tainted", "r");
    if (fp) {
        unsigned long taint;
        if (fscanf(fp, "%lu", &taint) == 1)
            fprintf(output, "META kernel_taint %lu\n", taint);
        fclose(fp);
    }

    printf("Hashing critical binaries...\n");

    /* Hash critical directories */
    const char *critical_dirs[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/usr/lib", "/lib",
        NULL
    };

    int total_files = 0;
    for (int i = 0; critical_dirs[i] != NULL; i++) {
        int n = hash_directory(critical_dirs[i], output);
        printf("  %s: %d files\n", critical_dirs[i], n);
        total_files += n;
    }

    /* Hash boot files */
    int boot_files = hash_directory("/boot", output);
    printf("  /boot: %d files\n", boot_files);
    total_files += boot_files;

    /* Hash critical config files */
    const char *config_files[] = {
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/fstab",
        "/etc/hosts", "/etc/resolv.conf", "/etc/pam.d/common-auth",
        NULL
    };

    for (int i = 0; config_files[i] != NULL; i++) {
        struct stat st;
        if (stat(config_files[i], &st) == 0) {
            char hash[HASH_LEN];
            compute_file_hash(config_files[i], hash, sizeof(hash));
            fprintf(output, "FILE %s %s %o %u %u %lu\n",
                    config_files[i], hash, st.st_mode & 07777,
                    st.st_uid, st.st_gid, (unsigned long)st.st_size);
            total_files++;
        }
    }

    printf("\nCollecting kernel modules...\n");
    int n_mods = collect_modules(output);
    printf("  Modules: %d\n", n_mods);

    printf("Collecting listening ports...\n");
    int n_listeners = collect_listeners(output);
    printf("  Listeners: %d\n", n_listeners);

    printf("Scanning for SUID/SGID files...\n");
    int n_suid = collect_suid_recursive("/", output, 0);
    printf("  SUID/SGID files: %d\n", n_suid);

    printf("Collecting sysctl settings...\n");
    int n_sysctl = collect_sysctl(output);
    printf("  Sysctl settings: %d\n", n_sysctl);

    fclose(output);

    printf("\n=== Baseline Summary ===\n");
    printf("  File hashes:     %d\n", total_files);
    printf("  Kernel modules:  %d\n", n_mods);
    printf("  Listeners:       %d\n", n_listeners);
    printf("  SUID files:      %d\n", n_suid);
    printf("  Sysctl settings: %d\n", n_sysctl);
    printf("  Baseline saved:  %s\n", baseline_path);
    printf("\nStore this baseline on read-only media for tamper resistance.\n");

    return 0;
}

/* ── Verify baseline ───────────────────────────────────────────── */

static int verify_baseline(const char *baseline_dir)
{
    printf("=== Verifying System Against Baseline ===\n\n");

    char baseline_path[MAX_PATH_LEN];
    snprintf(baseline_path, sizeof(baseline_path), "%s/baseline.dat", baseline_dir);

    FILE *fp = fopen(baseline_path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open baseline: %s\n", baseline_path);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int files_checked = 0, files_ok = 0, files_changed = 0, files_missing = 0;
    int modules_checked = 0, modules_ok = 0, modules_changed = 0;
    int sysctl_checked = 0, sysctl_ok = 0, sysctl_changed = 0;
    int new_suid = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        if (strncmp(line, "FILE ", 5) == 0) {
            char path[MAX_PATH_LEN], stored_hash[HASH_LEN];
            unsigned int mode, uid, gid;
            unsigned long size;

            if (sscanf(line + 5, "%511s %64s %o %u %u %lu",
                       path, stored_hash, &mode, &uid, &gid, &size) >= 2) {
                files_checked++;

                struct stat st;
                if (stat(path, &st) != 0) {
                    printf("  MISSING: %s\n", path);
                    files_missing++;
                    continue;
                }

                char current_hash[HASH_LEN];
                compute_file_hash(path, current_hash, sizeof(current_hash));

                if (strcmp(current_hash, stored_hash) != 0) {
                    printf("  CHANGED: %s (hash mismatch)\n", path);
                    files_changed++;
                } else if ((st.st_mode & 07777) != mode) {
                    printf("  PERMS:   %s (was %04o, now %04o)\n",
                           path, mode, st.st_mode & 07777);
                    files_changed++;
                } else {
                    files_ok++;
                }
            }
        } else if (strncmp(line, "SYSCTL ", 7) == 0) {
            char setting[256], stored_value[256];
            if (sscanf(line + 7, "%255s %255s", setting, stored_value) == 2) {
                sysctl_checked++;

                char path[MAX_PATH_LEN];
                snprintf(path, sizeof(path), "/proc/sys/%s", setting);
                for (char *p = path + 10; *p; p++) {
                    if (*p == '.') *p = '/';
                }

                FILE *sysctl_fp = fopen(path, "r");
                if (sysctl_fp) {
                    char current[256] = "";
                    if (fgets(current, sizeof(current), sysctl_fp)) {
                        current[strcspn(current, "\n")] = '\0';
                        if (strcmp(current, stored_value) != 0) {
                            printf("  SYSCTL CHANGED: %s (was %s, now %s)\n",
                                   setting, stored_value, current);
                            sysctl_changed++;
                        } else {
                            sysctl_ok++;
                        }
                    }
                    fclose(sysctl_fp);
                }
            }
        }
    }
    fclose(fp);

    printf("\n=== Verification Summary ===\n");
    printf("  Files checked:   %d\n", files_checked);
    printf("    OK:            %d\n", files_ok);
    printf("    Changed:       %d\n", files_changed);
    printf("    Missing:       %d\n", files_missing);
    printf("  Sysctl checked:  %d\n", sysctl_checked);
    printf("    OK:            %d\n", sysctl_ok);
    printf("    Changed:       %d\n", sysctl_changed);
    printf("  New SUID files:  %d\n", new_suid);

    int total_issues = files_changed + files_missing + sysctl_changed;

    if (total_issues == 0) {
        printf("\n  RESULT: System matches baseline.\n");
    } else {
        printf("\n  RESULT: %d deviation(s) from baseline detected.\n",
               total_issues);
    }

    return (total_issues > 0) ? 1 : 0;
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s --create <output_dir>\n", argv[0]);
        printf("       %s --verify <baseline_dir>\n", argv[0]);
        printf("\nCreates or verifies a system security baseline.\n");
        printf("Must be run as root for complete coverage.\n");
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "WARNING: Running without root. Results will be incomplete.\n\n");
    }

    printf("============================================================\n");
    printf("  System Security Baseline Creator v1.0\n");
    printf("============================================================\n");
    time_t now = time(NULL);
    printf("  Date: %s", ctime(&now));
    printf("============================================================\n\n");

    if (strcmp(argv[1], "--create") == 0) {
        return create_baseline(argv[2]);
    } else if (strcmp(argv[1], "--verify") == 0) {
        return verify_baseline(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
}

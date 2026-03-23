/*
 * detect_preload.c - Detect LD_PRELOAD-based library injection
 *
 *
 * This program checks multiple indicators of LD_PRELOAD-based
 * userland rootkit activity:
 *   1. Checks if /etc/ld.so.preload exists and its contents
 *   2. Scans all running processes for LD_PRELOAD in their environment
 *   3. Checks current process environment for LD_PRELOAD
 *   4. Analyzes loaded libraries in /proc/<pid>/maps for anomalies
 *
 * Compile: gcc -o detect_preload detect_preload.c -static
 * NOTE: Compile STATICALLY to avoid being affected by LD_PRELOAD itself!
 *
 * Usage: sudo ./detect_preload
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define MAX_PATH 4096
#define MAX_BUF  65536
#define PRELOAD_FILE "/etc/ld.so.preload"

/* ANSI color codes for terminal output */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

static int warnings_count = 0;
static int alerts_count = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  LD_PRELOAD Rootkit Detection Tool\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

static void print_ok(const char *msg)
{
    printf(GREEN "[  OK  ]" RESET " %s\n", msg);
}

static void print_warn(const char *msg)
{
    printf(YELLOW "[ WARN ]" RESET " %s\n", msg);
    warnings_count++;
}

static void print_alert(const char *msg)
{
    printf(RED "[ALERT!]" RESET " %s\n", msg);
    alerts_count++;
}

static void print_info(const char *msg)
{
    printf(CYAN "[ INFO ]" RESET " %s\n", msg);
}

/*
 * Check 1: Examine /etc/ld.so.preload
 *
 * This file, if it exists, causes the dynamic linker to preload
 * listed libraries into EVERY dynamically linked process on the system.
 * On most clean systems, this file does not exist.
 */
static void check_ld_so_preload(void)
{
    struct stat st;
    FILE *fp;
    char line[MAX_PATH];

    printf("\n--- Check 1: /etc/ld.so.preload ---\n\n");

    if (stat(PRELOAD_FILE, &st) != 0) {
        if (errno == ENOENT) {
            print_ok("/etc/ld.so.preload does not exist (normal)");
        } else {
            print_warn("Cannot stat /etc/ld.so.preload - access denied or error");
        }
        return;
    }

    /* File exists - this is potentially suspicious */
    print_alert("/etc/ld.so.preload EXISTS!");
    printf("         File size: %ld bytes\n", (long)st.st_size);
    printf("         Permissions: %o\n", st.st_mode & 0777);
    printf("         Owner UID: %d, GID: %d\n", st.st_uid, st.st_gid);

    fp = fopen(PRELOAD_FILE, "r");
    if (fp == NULL) {
        print_warn("Cannot read /etc/ld.so.preload contents");
        return;
    }

    printf("         Contents:\n");
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Remove trailing newline */
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) > 0) {
            printf("           -> Library: %s\n", line);

            /* Check if the referenced library file exists */
            if (access(line, F_OK) == 0) {
                print_alert("  Preloaded library file exists on disk!");

                /* Check if it is a shared object */
                struct stat lib_st;
                if (stat(line, &lib_st) == 0) {
                    printf("           Size: %ld bytes, Perms: %o\n",
                           (long)lib_st.st_size, lib_st.st_mode & 0777);
                }
            } else {
                print_info("  Referenced library does not exist (may have been removed)");
            }
        }
    }

    fclose(fp);
}

/*
 * Check 2: Scan process environments for LD_PRELOAD
 *
 * Reads /proc/<pid>/environ for each running process and searches
 * for LD_PRELOAD entries. Requires root privileges to read other
 * processes' environments.
 */
static void check_process_environments(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    char path[MAX_PATH];
    char buf[MAX_BUF];
    int fd;
    ssize_t bytes_read;
    int processes_checked = 0;
    int preloads_found = 0;

    printf("\n--- Check 2: Process Environment Scan ---\n\n");

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        print_warn("Cannot open /proc directory");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        /* Only process numeric directories (PID directories) */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid)
            continue;

        snprintf(path, sizeof(path), "/proc/%s/environ", entry->d_name);

        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue; /* Cannot read - permission denied (normal for other users) */

        bytes_read = read(fd, buf, sizeof(buf) - 1);
        close(fd);

        if (bytes_read <= 0)
            continue;

        buf[bytes_read] = '\0';
        processes_checked++;

        /*
         * Environment variables in /proc/<pid>/environ are null-separated.
         * Search through the buffer for "LD_PRELOAD" entries.
         */
        char *ptr = buf;
        char *end = buf + bytes_read;

        while (ptr < end) {
            if (strncmp(ptr, "LD_PRELOAD=", 11) == 0) {
                /* Get process name for context */
                char comm_path[MAX_PATH];
                char comm[256] = "unknown";
                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                FILE *cf = fopen(comm_path, "r");
                if (cf) {
                    if (fgets(comm, sizeof(comm), cf))
                        comm[strcspn(comm, "\n")] = '\0';
                    fclose(cf);
                }

                char alert_msg[MAX_PATH];
                snprintf(alert_msg, sizeof(alert_msg),
                         "PID %s (%s) has LD_PRELOAD set: %s",
                         entry->d_name, comm, ptr);
                print_alert(alert_msg);
                preloads_found++;
            }

            /* Move to next null-terminated string */
            ptr += strlen(ptr) + 1;
        }
    }

    closedir(proc_dir);

    char msg[256];
    snprintf(msg, sizeof(msg), "Checked %d processes, found %d with LD_PRELOAD",
             processes_checked, preloads_found);

    if (preloads_found == 0) {
        print_ok(msg);
    } else {
        print_warn(msg);
    }
}

/*
 * Check 3: Verify current process is not being preloaded
 */
static void check_self_preload(void)
{
    printf("\n--- Check 3: Self-Check (Current Process) ---\n\n");

    const char *preload = getenv("LD_PRELOAD");
    if (preload != NULL) {
        char msg[MAX_PATH];
        snprintf(msg, sizeof(msg), "Current process has LD_PRELOAD=%s", preload);
        print_alert(msg);
    } else {
        print_ok("No LD_PRELOAD in current process environment");
    }

    /* Check our own maps for unexpected libraries */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        print_warn("Cannot read /proc/self/maps");
        return;
    }

    char line[MAX_PATH];
    int suspicious_libs = 0;

    while (fgets(line, sizeof(line), maps) != NULL) {
        /* Look for shared objects in unusual locations */
        char *lib = strstr(line, "/");
        if (lib != NULL && strstr(line, ".so") != NULL) {
            /* Check for libraries outside standard paths */
            if (strstr(lib, "/lib/") == NULL &&
                strstr(lib, "/lib64/") == NULL &&
                strstr(lib, "/usr/lib") == NULL &&
                strstr(lib, "/usr/lib64") == NULL &&
                strstr(lib, "/usr/local/lib") == NULL &&
                strstr(lib, "/lib/x86_64") == NULL &&
                strstr(lib, "/usr/libexec") == NULL) {
                lib[strcspn(lib, "\n")] = '\0';
                char msg[MAX_PATH];
                snprintf(msg, sizeof(msg),
                         "Library in non-standard path: %s", lib);
                print_warn(msg);
                suspicious_libs++;
            }
        }
    }

    fclose(maps);

    if (suspicious_libs == 0) {
        print_ok("No suspicious library paths in current process");
    }
}

/*
 * Check 4: Scan for processes with unusual library mappings
 *
 * Examines /proc/<pid>/maps for each process and looks for
 * shared objects loaded from non-standard locations.
 */
static void check_library_maps(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    char path[MAX_PATH];
    char line[MAX_PATH];
    int processes_checked = 0;
    int anomalies_found = 0;

    printf("\n--- Check 4: Library Mapping Analysis ---\n\n");

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        print_warn("Cannot open /proc directory");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        int is_pid = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid)
            continue;

        snprintf(path, sizeof(path), "/proc/%s/maps", entry->d_name);

        FILE *maps = fopen(path, "r");
        if (maps == NULL)
            continue;

        processes_checked++;

        while (fgets(line, sizeof(line), maps) != NULL) {
            /* Look for executable shared objects in /tmp, /dev/shm, /var/tmp */
            if ((strstr(line, "/tmp/") != NULL ||
                 strstr(line, "/dev/shm/") != NULL ||
                 strstr(line, "/var/tmp/") != NULL) &&
                strstr(line, ".so") != NULL) {

                /* Get process name */
                char comm_path[MAX_PATH];
                char comm[256] = "unknown";
                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                FILE *cf = fopen(comm_path, "r");
                if (cf) {
                    if (fgets(comm, sizeof(comm), cf))
                        comm[strcspn(comm, "\n")] = '\0';
                    fclose(cf);
                }

                line[strcspn(line, "\n")] = '\0';

                char msg[MAX_PATH * 2];
                snprintf(msg, sizeof(msg),
                         "PID %s (%s) has library from suspicious path: %s",
                         entry->d_name, comm, line);
                print_alert(msg);
                anomalies_found++;
            }
        }

        fclose(maps);
    }

    closedir(proc_dir);

    char msg[256];
    snprintf(msg, sizeof(msg),
             "Scanned %d process maps, found %d suspicious library mappings",
             processes_checked, anomalies_found);

    if (anomalies_found == 0) {
        print_ok(msg);
    } else {
        print_warn(msg);
    }
}

/*
 * Check 5: Verify dynamic linker integrity
 */
static void check_linker_integrity(void)
{
    printf("\n--- Check 5: Dynamic Linker Checks ---\n\n");

    /* Check if standard ld.so.conf.d has unusual entries */
    DIR *d = opendir("/etc/ld.so.conf.d");
    if (d != NULL) {
        struct dirent *entry;
        int unusual = 0;

        while ((entry = readdir(d)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;

            /* Read each .conf file for unusual paths */
            char conf_path[MAX_PATH];
            snprintf(conf_path, sizeof(conf_path),
                     "/etc/ld.so.conf.d/%s", entry->d_name);

            FILE *cf = fopen(conf_path, "r");
            if (cf != NULL) {
                char line[MAX_PATH];
                while (fgets(line, sizeof(line), cf) != NULL) {
                    line[strcspn(line, "\n")] = '\0';
                    if (strstr(line, "/tmp") != NULL ||
                        strstr(line, "/dev/shm") != NULL ||
                        strstr(line, "/var/tmp") != NULL) {
                        char msg[MAX_PATH * 2];
                        snprintf(msg, sizeof(msg),
                                 "Suspicious library path in %s: %s",
                                 conf_path, line);
                        print_alert(msg);
                        unusual++;
                    }
                }
                fclose(cf);
            }
        }
        closedir(d);

        if (unusual == 0) {
            print_ok("No suspicious paths in /etc/ld.so.conf.d/");
        }
    } else {
        print_info("Cannot read /etc/ld.so.conf.d/");
    }
}

static void print_summary(void)
{
    printf("\n" CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Alerts:   %d\n", alerts_count);
    printf("  Warnings: %d\n", warnings_count);
    printf("\n");

    if (alerts_count > 0) {
        printf(RED "  RESULT: Potential LD_PRELOAD abuse detected!\n" RESET);
        printf("  Recommended actions:\n");
        printf("  1. Investigate flagged libraries\n");
        printf("  2. Compare with statically linked tools\n");
        printf("  3. Check /etc/ld.so.preload with trusted media\n");
        printf("  4. Acquire memory image for forensics\n");
    } else if (warnings_count > 0) {
        printf(YELLOW "  RESULT: Some warnings detected, review recommended.\n" RESET);
    } else {
        printf(GREEN "  RESULT: No LD_PRELOAD indicators detected.\n" RESET);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    print_banner();

    if (geteuid() != 0) {
        print_warn("Running without root privileges - some checks will be limited");
        printf("         For full scan, run: sudo %s\n\n", argv[0]);
    }

    check_ld_so_preload();
    check_process_environments();
    check_self_preload();
    check_library_maps();
    check_linker_integrity();
    print_summary();

    return (alerts_count > 0) ? 1 : 0;
}

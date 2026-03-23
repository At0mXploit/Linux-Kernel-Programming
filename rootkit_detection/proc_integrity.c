/*
 * proc_integrity.c - Verify /proc filesystem integrity
 *
 *
 * Verifies /proc integrity by comparing multiple data sources:
 *   1. /proc/<pid>/stat vs. /proc/<pid>/status consistency
 *   2. Process credential verification (unexpected UID 0)
 *   3. /proc/<pid>/exe existence and validity
 *   4. TracerPid check (unexpected ptrace attachment)
 *   5. Suspicious process name analysis
 *
 * Compile: gcc -o proc_integrity proc_integrity.c -static
 * Usage:   sudo ./proc_integrity
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_PATH 512
#define MAX_LINE 4096

static int anomaly_count = 0;
static int processes_checked = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  /proc Filesystem Integrity Verifier\n");
    printf("  Multi-Source Cross-Reference Analysis\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Extract a value from /proc/<pid>/status by field name
 * Returns the first numeric value after the field name
 */
static int get_status_field(const char *status_buf, const char *field, int *value)
{
    char *pos = strstr(status_buf, field);
    if (pos == NULL)
        return -1;

    pos += strlen(field);
    while (*pos && !isdigit((unsigned char)*pos) && *pos != '\n')
        pos++;

    if (isdigit((unsigned char)*pos)) {
        *value = atoi(pos);
        return 0;
    }

    return -1;
}

/*
 * Check 1: Verify /proc/<pid>/stat and /proc/<pid>/status consistency
 */
static void check_stat_status_consistency(int pid, const char *status_buf)
{
    char path[MAX_PATH];
    char stat_buf[MAX_LINE];
    int fd;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fd = open(path, 0 /* O_RDONLY */);
    if (fd < 0) return;

    n = read(fd, stat_buf, sizeof(stat_buf) - 1);
    close(fd);
    if (n <= 0) return;
    stat_buf[n] = '\0';

    /* Extract PID from /proc/<pid>/stat (first field) */
    int stat_pid = 0;
    sscanf(stat_buf, "%d", &stat_pid);

    /* Extract PID from /proc/<pid>/status */
    int status_pid = -1;
    get_status_field(status_buf, "Pid:", &status_pid);

    if (stat_pid != status_pid && status_pid != -1) {
        printf(RED "  [ANOMALY]" RESET " PID %d: stat reports PID %d, status reports PID %d\n",
               pid, stat_pid, status_pid);
        anomaly_count++;
    }

    /* Extract PPID from both sources */
    int stat_ppid = 0;
    /* PPID is the 4th field in /proc/<pid>/stat */
    char *p = strchr(stat_buf, ')'); /* Skip past comm field */
    if (p != NULL) {
        p++; /* Skip ')' */
        char state;
        sscanf(p, " %c %d", &state, &stat_ppid);
    }

    int status_ppid = -1;
    get_status_field(status_buf, "PPid:", &status_ppid);

    if (stat_ppid != status_ppid && status_ppid != -1 && stat_ppid != 0) {
        printf(YELLOW "  [MISMATCH]" RESET " PID %d: stat PPID=%d, status PPID=%d\n",
               pid, stat_ppid, status_ppid);
        anomaly_count++;
    }
}

/*
 * Check 2: Verify process credentials - look for unexpected root processes
 */
static void check_credentials(int pid, const char *status_buf, const char *comm)
{
    int uid = -1;
    int euid = -1;

    /* Parse Uid line: real, effective, saved, filesystem */
    char *uid_line = strstr(status_buf, "Uid:");
    if (uid_line != NULL) {
        sscanf(uid_line + 4, "%d %d", &uid, &euid);
    }

    /*
     * Flag processes running as root (euid=0) that have unusual names.
     * This is a heuristic - legitimate root processes exist.
     * Focus on processes that look like they might be shells or
     * backdoor processes running with unexpected privileges.
     */
    if (euid == 0 && uid != 0) {
        /* Process has effective UID 0 but real UID is not 0 */
        /* This could be legitimate (SUID) or credential manipulation */
        printf(YELLOW "  [CREDENTIAL]" RESET " PID %d (%s): real_uid=%d, effective_uid=0 (SUID or escalated)\n",
               pid, comm, uid);
        /* Not counted as anomaly since SUID is normal */
    }
}

/*
 * Check 3: Verify /proc/<pid>/exe symlink validity
 */
static void check_exe_link(int pid, const char *comm)
{
    char path[MAX_PATH];
    char exe_target[MAX_PATH];
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    n = readlink(path, exe_target, sizeof(exe_target) - 1);

    if (n < 0) {
        /* Cannot read exe - might be kernel thread (normal) or permission denied */
        if (errno == ENOENT) {
            /* exe not found - could be deleted binary */
            printf(YELLOW "  [DELETED]" RESET " PID %d (%s): executable has been deleted\n",
                   pid, comm);
        }
        return;
    }

    exe_target[n] = '\0';

    /* Check for "(deleted)" suffix - binary was deleted while running */
    if (strstr(exe_target, "(deleted)") != NULL) {
        printf(YELLOW "  [DELETED]" RESET " PID %d (%s): exe -> %s\n",
               pid, comm, exe_target);
        /* Running a deleted binary is suspicious for user processes */
    }

    /* Check for executables in unusual locations */
    if (strncmp(exe_target, "/tmp/", 5) == 0 ||
        strncmp(exe_target, "/dev/shm/", 9) == 0 ||
        strncmp(exe_target, "/var/tmp/", 9) == 0) {
        printf(RED "  [SUSPICIOUS]" RESET " PID %d (%s): running from suspicious path: %s\n",
               pid, comm, exe_target);
        anomaly_count++;
    }
}

/*
 * Check 4: TracerPid verification
 */
static void check_tracer(int pid, const char *status_buf, const char *comm)
{
    int tracer_pid = 0;
    get_status_field(status_buf, "TracerPid:", &tracer_pid);

    if (tracer_pid > 0) {
        /* Process is being traced - check if it's a known debugger */
        char tracer_comm[256] = "unknown";
        char tracer_path[MAX_PATH];

        snprintf(tracer_path, sizeof(tracer_path), "/proc/%d/comm", tracer_pid);
        FILE *fp = fopen(tracer_path, "r");
        if (fp != NULL) {
            if (fgets(tracer_comm, sizeof(tracer_comm), fp))
                tracer_comm[strcspn(tracer_comm, "\n")] = '\0';
            fclose(fp);
        }

        /* Common debuggers: gdb, strace, ltrace, lldb */
        int is_known_debugger = (
            strcmp(tracer_comm, "gdb") == 0 ||
            strcmp(tracer_comm, "strace") == 0 ||
            strcmp(tracer_comm, "ltrace") == 0 ||
            strcmp(tracer_comm, "lldb") == 0 ||
            strcmp(tracer_comm, "valgrind") == 0
        );

        if (!is_known_debugger) {
            printf(RED "  [TRACED]" RESET " PID %d (%s) is being traced by PID %d (%s)\n",
                   pid, comm, tracer_pid, tracer_comm);
            anomaly_count++;
        } else {
            printf(CYAN "  [DEBUG]" RESET " PID %d (%s) traced by %s (PID %d) - legitimate\n",
                   pid, comm, tracer_comm, tracer_pid);
        }
    }
}

/*
 * Check 5: Suspicious process name analysis
 */
static void check_process_name(int pid, const char *comm)
{
    /* Look for kernel thread naming patterns in user processes */
    /* Kernel threads have names like [kworker/0:0] */
    /* A userland process with such a name is suspicious */

    char path[MAX_PATH];
    char mm_buf[64];

    if (comm[0] == '[') {
        /* Looks like a kernel thread name - verify it IS a kernel thread */
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        FILE *fp = fopen(path, "r");
        if (fp != NULL) {
            /* If maps file has content, it's NOT a kernel thread */
            if (fgets(mm_buf, sizeof(mm_buf), fp) != NULL) {
                printf(RED "  [DISGUISED]" RESET " PID %d: process name '%s' looks like kernel thread but has user memory maps!\n",
                       pid, comm);
                anomaly_count++;
            }
            fclose(fp);
        }
    }

    /* Check for very short or unusual process names */
    if (strlen(comm) == 1 && !isalpha((unsigned char)comm[0])) {
        printf(YELLOW "  [UNUSUAL]" RESET " PID %d: single-character process name: '%s'\n",
               pid, comm);
    }
}

/*
 * Check 6: Verify /proc/<pid>/fd consistency
 */
static void check_fd_anomalies(int pid, const char *comm)
{
    char path[MAX_PATH];
    char link_target[MAX_PATH];
    DIR *fd_dir;
    struct dirent *entry;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    fd_dir = opendir(path);
    if (fd_dir == NULL)
        return;

    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char fd_path[MAX_PATH];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%s", pid, entry->d_name);

        n = readlink(fd_path, link_target, sizeof(link_target) - 1);
        if (n < 0) continue;
        link_target[n] = '\0';

        /* Check for file descriptors pointing to deleted files */
        if (strstr(link_target, "(deleted)") != NULL &&
            strstr(link_target, "/tmp") == NULL &&
            strstr(link_target, ".so") != NULL) {
            printf(YELLOW "  [DELETED-LIB]" RESET " PID %d (%s): fd %s -> %s\n",
                   pid, comm, entry->d_name, link_target);
        }

        /* Check for raw network sockets (unusual) */
        if (strncmp(link_target, "socket:", 7) == 0) {
            /* Raw sockets are unusual for non-root processes */
            /* Skipping detailed check here for performance */
        }
    }

    closedir(fd_dir);
}

/*
 * Main process scanning loop
 */
static void scan_all_processes(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    char path[MAX_PATH];
    char status_buf[MAX_LINE];
    char comm[256];
    int fd;
    ssize_t n;

    printf(CYAN "  [Scanning]" RESET " Analyzing all visible processes...\n\n");

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("  Cannot open /proc");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        /* Only process PID directories */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid) continue;

        int pid = atoi(entry->d_name);

        /* Read /proc/<pid>/status */
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        fd = open(path, 0);
        if (fd < 0) continue;
        n = read(fd, status_buf, sizeof(status_buf) - 1);
        close(fd);
        if (n <= 0) continue;
        status_buf[n] = '\0';

        /* Read /proc/<pid>/comm */
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *fp = fopen(path, "r");
        comm[0] = '\0';
        if (fp != NULL) {
            if (fgets(comm, sizeof(comm), fp))
                comm[strcspn(comm, "\n")] = '\0';
            fclose(fp);
        }

        processes_checked++;

        /* Run all checks */
        check_stat_status_consistency(pid, status_buf);
        check_credentials(pid, status_buf, comm);
        check_exe_link(pid, comm);
        check_tracer(pid, status_buf, comm);
        check_process_name(pid, comm);
        check_fd_anomalies(pid, comm);
    }

    closedir(proc_dir);
}

/*
 * Additional /proc filesystem checks
 */
static void check_proc_mount(void)
{
    FILE *fp;
    char line[MAX_LINE];
    int proc_found = 0;

    printf(CYAN "  [Mount Check]" RESET " Verifying /proc mount:\n");

    fp = fopen("/proc/mounts", "r");
    if (fp == NULL) {
        printf(RED "  Cannot read /proc/mounts!\n" RESET);
        anomaly_count++;
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, " /proc ") != NULL) {
            /* Check mount type */
            if (strstr(line, "proc") != NULL && strstr(line, "fuse") == NULL) {
                printf(GREEN "  /proc is mounted as type proc (normal)\n" RESET);
                proc_found = 1;
            } else if (strstr(line, "fuse") != NULL) {
                printf(RED "  [ALERT] /proc appears to be a FUSE mount!\n" RESET);
                printf("  This could be an overlay intercepting /proc data.\n");
                anomaly_count++;
                proc_found = 1;
            }
        }
    }

    fclose(fp);

    if (!proc_found) {
        printf(RED "  [ALERT] /proc mount not found in /proc/mounts!\n" RESET);
        anomaly_count++;
    }

    printf("\n");
}

static void print_summary(void)
{
    printf(CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Processes analyzed: %d\n", processes_checked);
    printf("  Anomalies found: %d\n", anomaly_count);
    printf("\n");

    if (anomaly_count > 0) {
        printf(YELLOW "  RESULT: Anomalies detected in /proc data.\n" RESET);
        printf("  Review each finding above for context.\n");
        printf("  Some findings may be benign (SUID, debuggers).\n");
        printf("  Red items warrant investigation.\n");
    } else {
        printf(GREEN "  RESULT: No anomalies detected in /proc data.\n" RESET);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Some process details may be inaccessible.\n\n" RESET);
    }

    check_proc_mount();
    scan_all_processes();
    print_summary();

    return (anomaly_count > 0) ? 1 : 0;
}

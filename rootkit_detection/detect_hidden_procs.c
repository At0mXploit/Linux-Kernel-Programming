/*
 * detect_hidden_procs.c - Detect hidden processes via cross-view analysis
 *
 *
 * Detection methodology:
 *   View 1: Enumerate /proc/<pid> directories (standard approach)
 *   View 2: Probe entire PID space using kill(pid, 0)
 *   View 3: Attempt to open /proc/<pid>/stat directly
 *
 *   If a PID responds to kill(pid, 0) but does not appear in /proc
 *   directory listing, it may be hidden by a rootkit.
 *
 * Compile: gcc -o detect_hidden_procs detect_hidden_procs.c -static
 * Usage:   sudo ./detect_hidden_procs [--full]
 *          --full: Scan entire PID range (slow but thorough)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define DEFAULT_PID_MAX 32768
#define ABSOLUTE_PID_MAX 4194304

static int hidden_count = 0;
static int ghost_count = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Hidden Process Detection Tool\n");
    printf("  Cross-View Analysis Method\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Read pid_max from /proc/sys/kernel/pid_max
 */
static int get_pid_max(void)
{
    FILE *fp = fopen("/proc/sys/kernel/pid_max", "r");
    int pid_max = DEFAULT_PID_MAX;

    if (fp != NULL) {
        if (fscanf(fp, "%d", &pid_max) != 1)
            pid_max = DEFAULT_PID_MAX;
        fclose(fp);
    }

    return pid_max;
}

/*
 * View 1: Enumerate visible PIDs from /proc directory listing
 *
 * This is what ps, top, and other tools do.
 * If a rootkit hooks getdents64 or /proc readdir,
 * hidden PIDs will NOT appear here.
 */
static int *enumerate_proc_pids(int *count)
{
    DIR *proc_dir;
    struct dirent *entry;
    int *pids = NULL;
    int capacity = 1024;
    int n = 0;

    pids = malloc(capacity * sizeof(int));
    if (pids == NULL) {
        perror("malloc");
        *count = 0;
        return NULL;
    }

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("opendir /proc");
        free(pids);
        *count = 0;
        return NULL;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        /* Check if directory name is purely numeric (a PID) */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit((unsigned char)entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }

        if (is_pid) {
            if (n >= capacity) {
                capacity *= 2;
                int *tmp = realloc(pids, capacity * sizeof(int));
                if (tmp == NULL) {
                    perror("realloc");
                    break;
                }
                pids = tmp;
            }
            pids[n++] = atoi(entry->d_name);
        }
    }

    closedir(proc_dir);
    *count = n;
    return pids;
}

/*
 * View 2: Probe PID existence using kill(pid, 0)
 *
 * kill(pid, 0) does not send a signal but checks if the process exists.
 * Returns 0 if process exists and we can signal it.
 * Returns -1 with errno=EPERM if process exists but we cannot signal it.
 * Returns -1 with errno=ESRCH if process does not exist.
 *
 * This uses a different kernel code path than /proc enumeration,
 * so it may find processes hidden from /proc.
 */
static int *probe_kill_pids(int pid_max, int *count)
{
    int *pids = NULL;
    int capacity = 1024;
    int n = 0;
    int progress_interval;

    pids = malloc(capacity * sizeof(int));
    if (pids == NULL) {
        perror("malloc");
        *count = 0;
        return NULL;
    }

    progress_interval = pid_max / 20; /* Show progress every 5% */
    if (progress_interval < 1)
        progress_interval = 1;

    printf("  Probing PID range 1-%d", pid_max);
    fflush(stdout);

    for (int pid = 1; pid <= pid_max; pid++) {
        if (pid % progress_interval == 0) {
            printf(".");
            fflush(stdout);
        }

        int ret = kill(pid, 0);
        if (ret == 0 || (ret == -1 && errno == EPERM)) {
            /* Process exists */
            if (n >= capacity) {
                capacity *= 2;
                int *tmp = realloc(pids, capacity * sizeof(int));
                if (tmp == NULL) {
                    perror("realloc");
                    break;
                }
                pids = tmp;
            }
            pids[n++] = pid;
        }
    }

    printf(" done\n");
    *count = n;
    return pids;
}

/*
 * View 3: Direct /proc/<pid>/stat access
 *
 * Try to open /proc/<pid>/stat for a specific PID.
 * This uses the lookup code path rather than readdir.
 */
static int check_proc_stat_direct(int pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1; /* Exists */
    }
    return 0; /* Does not exist */
}

/*
 * Check if a PID is in the given array
 */
static int pid_in_array(int pid, int *array, int count)
{
    for (int i = 0; i < count; i++) {
        if (array[i] == pid)
            return 1;
    }
    return 0;
}

/*
 * Gather information about a suspicious PID
 */
static void investigate_pid(int pid)
{
    char path[256];
    char buf[4096];
    ssize_t n;
    int fd;

    printf("    --- Investigating PID %d ---\n", pid);

    /* Try to read /proc/<pid>/comm */
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            buf[strcspn(buf, "\n")] = '\0';
            printf("    Process name:  %s\n", buf);
        }
        close(fd);
    } else {
        printf("    Process name:  [cannot read]\n");
    }

    /* Try to read /proc/<pid>/cmdline */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            /* Replace null separators with spaces for display */
            for (ssize_t i = 0; i < n - 1; i++) {
                if (buf[i] == '\0')
                    buf[i] = ' ';
            }
            printf("    Command line:  %s\n", buf);
        }
        close(fd);
    }

    /* Try to read /proc/<pid>/status for UID info */
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            /* Extract Uid line */
            char *uid_line = strstr(buf, "Uid:");
            if (uid_line) {
                char *eol = strchr(uid_line, '\n');
                if (eol) *eol = '\0';
                printf("    %s\n", uid_line);
                if (eol) *eol = '\n';
            }
            /* Extract State line */
            char *state_line = strstr(buf, "State:");
            if (state_line) {
                char *eol = strchr(state_line, '\n');
                if (eol) *eol = '\0';
                printf("    %s\n", state_line);
            }
        }
        close(fd);
    }

    /* Check exe symlink */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    n = readlink(path, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("    Executable:    %s\n", buf);
    } else {
        printf("    Executable:    [cannot read - %s]\n", strerror(errno));
    }

    printf("\n");
}

/*
 * Main cross-view comparison
 */
static void cross_view_analysis(int full_scan)
{
    int proc_count, kill_count;
    int *proc_pids, *kill_pids;
    int pid_max;
    time_t start, end;

    if (full_scan) {
        pid_max = get_pid_max();
        printf(YELLOW "  Full scan mode: Probing %d PIDs (this may take a while)\n" RESET,
               pid_max);
    } else {
        /* Quick scan: Only probe a reasonable range */
        pid_max = DEFAULT_PID_MAX;
        printf("  Quick scan mode: Probing PIDs 1-%d\n", pid_max);
        printf("  Use --full to scan entire PID range (up to %d)\n", get_pid_max());
    }
    printf("\n");

    /* View 1: /proc enumeration */
    printf(CYAN "  [View 1]" RESET " Enumerating /proc directory...\n");
    proc_pids = enumerate_proc_pids(&proc_count);
    printf("  Found %d visible processes in /proc\n\n", proc_count);

    /* View 2: kill() probing */
    printf(CYAN "  [View 2]" RESET " Probing PIDs via kill(pid, 0)...\n");
    time(&start);
    kill_pids = probe_kill_pids(pid_max, &kill_count);
    time(&end);
    printf("  Found %d responding PIDs (%.0f seconds)\n\n",
           kill_count, difftime(end, start));

    if (proc_pids == NULL || kill_pids == NULL) {
        fprintf(stderr, "Error: Failed to collect PID data\n");
        free(proc_pids);
        free(kill_pids);
        return;
    }

    /* Cross-view comparison */
    printf(CYAN "  [Analysis]" RESET " Comparing views...\n\n");

    /* Check for PIDs in kill() but NOT in /proc (potentially hidden) */
    printf("  Checking for hidden processes (in kill but not in /proc):\n");
    for (int i = 0; i < kill_count; i++) {
        if (!pid_in_array(kill_pids[i], proc_pids, proc_count)) {
            /* Additional verification via View 3 */
            int direct_access = check_proc_stat_direct(kill_pids[i]);

            printf(RED "  [HIDDEN]" RESET " PID %d: responds to kill(0)",
                   kill_pids[i]);

            if (direct_access) {
                printf(", /proc/<pid>/stat accessible");
            } else {
                printf(", /proc/<pid>/stat NOT accessible");
            }
            printf(", NOT in /proc listing\n");

            investigate_pid(kill_pids[i]);
            hidden_count++;
        }
    }

    if (hidden_count == 0) {
        printf(GREEN "  No hidden processes detected.\n" RESET);
    }

    /* Check for PIDs in /proc but NOT in kill() (ghost entries) */
    printf("\n  Checking for ghost entries (in /proc but not responding to kill):\n");
    for (int i = 0; i < proc_count; i++) {
        if (!pid_in_array(proc_pids[i], kill_pids, kill_count)) {
            printf(YELLOW "  [GHOST]" RESET " PID %d: in /proc but does not respond to kill(0)\n",
                   proc_pids[i]);
            printf("    This may indicate a race condition or a phantom /proc entry\n\n");
            ghost_count++;
        }
    }

    if (ghost_count == 0) {
        printf(GREEN "  No ghost entries detected.\n" RESET);
    }

    free(proc_pids);
    free(kill_pids);
}

static void print_summary(void)
{
    printf("\n" CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Hidden processes: %d\n", hidden_count);
    printf("  Ghost entries:    %d\n", ghost_count);
    printf("\n");

    if (hidden_count > 0) {
        printf(RED "  RESULT: Hidden process(es) detected!\n" RESET);
        printf("  This strongly suggests rootkit activity.\n");
        printf("  Recommended actions:\n");
        printf("  1. Acquire memory image (LiME or AVML)\n");
        printf("  2. Analyze with Volatility framework\n");
        printf("  3. Investigate hidden PID(s)\n");
        printf("  4. Check for kernel module rootkit (detect_hidden_modules)\n");
        printf("  5. Activate incident response procedures\n");
    } else if (ghost_count > 0) {
        printf(YELLOW "  RESULT: Ghost entries detected (likely race conditions).\n" RESET);
        printf("  Run the scan again to verify.\n");
    } else {
        printf(GREEN "  RESULT: No hidden processes detected.\n" RESET);
    }

    printf("\n");
    printf("  NOTE: This tool may miss processes hidden via DKOM if the\n");
    printf("  rootkit also hooks kill() or removes the process from the\n");
    printf("  PID hash table. For comprehensive detection, use memory\n");
    printf("  forensics (Volatility linux_psxview).\n\n");
}

int main(int argc, char *argv[])
{
    int full_scan = 0;

    print_banner();

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0) {
            full_scan = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--full]\n", argv[0]);
            printf("  --full  Scan entire PID range (slow but thorough)\n");
            printf("  Default: Scan PIDs 1-%d\n", DEFAULT_PID_MAX);
            return 0;
        }
    }

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Some processes may appear hidden simply due to\n");
        printf("  permission restrictions. Run as root for accurate results.\n" RESET);
        printf("\n");
    }

    cross_view_analysis(full_scan);
    print_summary();

    return (hidden_count > 0) ? 1 : 0;
}

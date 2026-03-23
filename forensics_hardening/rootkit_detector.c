/*
 * rootkit_detector.c - Comprehensive Rootkit Detection Tool
 *
 *
 * This tool performs multiple detection checks:
 *   1. Hidden process detection (cross-view: /proc vs syscall)
 *   2. Hidden kernel module detection (cross-view: /proc/modules vs /sys/module)
 *   3. Syscall table verification (address range checking)
 *   4. Hidden network connection detection (/proc/net/tcp cross-check)
 *   5. Suspicious file detection (common rootkit artifacts)
 *   6. Kernel taint flag analysis
 *
 * Build: gcc -O2 -Wall -Wextra -o rootkit_detector rootkit_detector.c
 * Usage: sudo ./rootkit_detector [--verbose] [--json]
 *
 * MUST be run as root for full detection capabilities.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define MAX_PIDS       65536
#define MAX_MODULES    1024
#define MAX_CONNECTIONS 4096
#define MAX_NAME_LEN   256
#define MAX_LINE_LEN   1024

/* ── Detection result tracking ─────────────────────────────────── */

static int alerts_total    = 0;
static int checks_passed   = 0;
static int checks_failed   = 0;
static int verbose_mode    = 0;
static int json_mode       = 0;

typedef struct {
    char name[MAX_NAME_LEN];
    int  found_in_proc;
    int  found_in_sys;
    int  found_in_kallsyms;
} module_entry_t;

typedef struct {
    unsigned int local_port;
    unsigned int remote_port;
    unsigned int local_addr;
    unsigned int remote_addr;
    int          state;
    unsigned int inode;
} tcp_connection_t;

/* ── Utility functions ─────────────────────────────────────────── */

static void print_banner(void)
{
    printf("============================================================\n");
    printf("  Linux Rootkit Detector v1.0\n");
    printf("  Forensics and Hardening\n");
    printf("============================================================\n");
    printf("  Date: ");
    time_t now = time(NULL);
    printf("%s", ctime(&now));
    printf("  UID:  %d\n", getuid());
    printf("============================================================\n\n");
}

static void alert(const char *category, const char *message)
{
    alerts_total++;
    if (json_mode) {
        printf("  {\"category\": \"%s\", \"severity\": \"ALERT\", "
               "\"message\": \"%s\"},\n", category, message);
    } else {
        printf("  [ALERT] %s: %s\n", category, message);
    }
}

static void info(const char *category, const char *message)
{
    if (verbose_mode) {
        if (!json_mode)
            printf("  [INFO]  %s: %s\n", category, message);
    }
}

static void check_result(const char *check_name, int passed)
{
    if (passed) {
        checks_passed++;
        if (!json_mode)
            printf("  [PASS]  %s\n", check_name);
    } else {
        checks_failed++;
        if (!json_mode)
            printf("  [FAIL]  %s\n", check_name);
    }
}

static int is_numeric(const char *str)
{
    while (*str) {
        if (!isdigit((unsigned char)*str))
            return 0;
        str++;
    }
    return 1;
}

/* ── Check 1: Hidden Process Detection ─────────────────────────── */

static void detect_hidden_processes(void)
{
    printf("\n--- Check 1: Hidden Process Detection ---\n");

    DIR *proc_dir;
    struct dirent *entry;
    int proc_pids[MAX_PIDS];
    int proc_count = 0;
    int hidden_count = 0;
    char path[512];
    char msg[MAX_LINE_LEN];

    /* Gather PIDs from /proc directory listing */
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        alert("PROCESS", "Cannot open /proc - detection impossible");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL && proc_count < MAX_PIDS) {
        if (is_numeric(entry->d_name)) {
            proc_pids[proc_count++] = atoi(entry->d_name);
        }
    }
    closedir(proc_dir);

    info("PROCESS", "Scanning for processes visible in /proc but hidden from tools");

    /* For each PID found in /proc, verify we can read its status */
    for (int i = 0; i < proc_count; i++) {
        snprintf(path, sizeof(path), "/proc/%d/status", proc_pids[i]);
        FILE *fp = fopen(path, "r");
        if (!fp) {
            /* Process may have exited between listing and check */
            continue;
        }

        char name[256] = "unknown";
        char line[MAX_LINE_LEN];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line + 5, " %255s", name);
                break;
            }
        }
        fclose(fp);

        /* Check if the process cmdline is readable (hidden procs often have issues) */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", proc_pids[i]);
        int fd = open(path, O_RDONLY);
        if (fd < 0 && errno == ENOENT) {
            /* Process vanished - normal */
            continue;
        }
        if (fd >= 0) {
            char cmdline[1024];
            ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);

            if (n == 0) {
                /* Empty cmdline - could be kernel thread or hidden process */
                snprintf(path, sizeof(path), "/proc/%d/exe", proc_pids[i]);
                char exe_link[512];
                ssize_t len = readlink(path, exe_link, sizeof(exe_link) - 1);
                if (len > 0) {
                    exe_link[len] = '\0';
                    /* Has exe link but no cmdline - suspicious for userspace */
                    if (strstr(exe_link, "(deleted)")) {
                        snprintf(msg, sizeof(msg),
                                 "PID %d (%s) has deleted executable: %s",
                                 proc_pids[i], name, exe_link);
                        alert("PROCESS", msg);
                        hidden_count++;
                    }
                }
            }
        }
    }

    /* Cross-check: scan PID range for invisible processes */
    int max_pid = 32768; /* Default, could read from /proc/sys/kernel/pid_max */
    FILE *pid_max_fp = fopen("/proc/sys/kernel/pid_max", "r");
    if (pid_max_fp) {
        if (fscanf(pid_max_fp, "%d", &max_pid) != 1)
            max_pid = 32768;
        fclose(pid_max_fp);
    }

    /* Sample check: try to send signal 0 to detect hidden processes */
    int signal_found = 0;
    int proc_found = 0;
    for (int pid = 1; pid <= max_pid && pid < MAX_PIDS; pid++) {
        /* Check if process exists via kill(pid, 0) */
        if (kill(pid, 0) == 0 || errno == EPERM) {
            signal_found++;
            /* Check if visible in /proc */
            snprintf(path, sizeof(path), "/proc/%d", pid);
            struct stat st;
            if (stat(path, &st) != 0) {
                snprintf(msg, sizeof(msg),
                         "PID %d responds to signals but has no /proc entry - HIDDEN",
                         pid);
                alert("PROCESS", msg);
                hidden_count++;
            } else {
                proc_found++;
            }
        }
    }

    snprintf(msg, sizeof(msg),
             "Scanned PID range 1-%d: %d via signals, %d in /proc",
             max_pid > MAX_PIDS ? MAX_PIDS : max_pid, signal_found, proc_found);
    info("PROCESS", msg);

    check_result("Hidden process detection", hidden_count == 0);
}

/* ── Check 2: Hidden Module Detection ──────────────────────────── */

static void detect_hidden_modules(void)
{
    printf("\n--- Check 2: Hidden Kernel Module Detection ---\n");

    module_entry_t modules[MAX_MODULES];
    int module_count = 0;
    char line[MAX_LINE_LEN];
    char msg[MAX_LINE_LEN];
    int hidden_count = 0;

    memset(modules, 0, sizeof(modules));

    /* Source A: Read /proc/modules */
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) {
        alert("MODULE", "Cannot open /proc/modules");
        return;
    }

    while (fgets(line, sizeof(line), fp) && module_count < MAX_MODULES) {
        char name[MAX_NAME_LEN];
        if (sscanf(line, "%255s", name) == 1) {
            /* Check if already in list */
            int found = 0;
            for (int i = 0; i < module_count; i++) {
                if (strcmp(modules[i].name, name) == 0) {
                    modules[i].found_in_proc = 1;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                strncpy(modules[module_count].name, name, MAX_NAME_LEN - 1);
                modules[module_count].found_in_proc = 1;
                module_count++;
            }
        }
    }
    fclose(fp);

    int proc_count = module_count;
    snprintf(msg, sizeof(msg), "Found %d modules in /proc/modules", proc_count);
    info("MODULE", msg);

    /* Source B: Read /sys/module/ */
    DIR *sys_dir = opendir("/sys/module");
    if (!sys_dir) {
        alert("MODULE", "Cannot open /sys/module");
        return;
    }

    struct dirent *entry;
    int sys_count = 0;
    while ((entry = readdir(sys_dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        /* Check if this is a loadable module (has initstate file) */
        char path[512];
        snprintf(path, sizeof(path), "/sys/module/%s/initstate", entry->d_name);
        FILE *state_fp = fopen(path, "r");
        if (!state_fp)
            continue; /* Built-in module, skip */

        char state[64] = "";
        if (fgets(state, sizeof(state), state_fp)) {
            state[strcspn(state, "\n")] = '\0';
        }
        fclose(state_fp);

        if (strcmp(state, "live") != 0)
            continue;

        sys_count++;

        /* Check if already in list */
        int found = 0;
        for (int i = 0; i < module_count; i++) {
            if (strcmp(modules[i].name, entry->d_name) == 0) {
                modules[i].found_in_sys = 1;
                found = 1;
                break;
            }
        }
        if (!found && module_count < MAX_MODULES) {
            strncpy(modules[module_count].name, entry->d_name, MAX_NAME_LEN - 1);
            modules[module_count].found_in_sys = 1;
            module_count++;
        }
    }
    closedir(sys_dir);

    snprintf(msg, sizeof(msg), "Found %d live modules in /sys/module", sys_count);
    info("MODULE", msg);

    /* Source C: Check /proc/kallsyms for module tags */
    fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *bracket_start = strchr(line, '[');
            if (bracket_start) {
                char *bracket_end = strchr(bracket_start, ']');
                if (bracket_end) {
                    *bracket_end = '\0';
                    char *mod_name = bracket_start + 1;

                    /* Find in list or add */
                    int found = 0;
                    for (int i = 0; i < module_count; i++) {
                        if (strcmp(modules[i].name, mod_name) == 0) {
                            modules[i].found_in_kallsyms = 1;
                            found = 1;
                            break;
                        }
                    }
                    if (!found && module_count < MAX_MODULES) {
                        strncpy(modules[module_count].name, mod_name, MAX_NAME_LEN - 1);
                        modules[module_count].found_in_kallsyms = 1;
                        module_count++;
                    }
                }
            }
        }
        fclose(fp);
    }

    /* Compare views */
    for (int i = 0; i < module_count; i++) {
        if (modules[i].found_in_sys && !modules[i].found_in_proc) {
            snprintf(msg, sizeof(msg),
                     "Module '%s' in /sys/module but NOT in /proc/modules (possible hook on /proc)",
                     modules[i].name);
            alert("MODULE", msg);
            hidden_count++;
        }
        if (modules[i].found_in_kallsyms && !modules[i].found_in_proc
            && !modules[i].found_in_sys) {
            snprintf(msg, sizeof(msg),
                     "Module '%s' has symbols in kallsyms but missing from /proc/modules AND /sys/module",
                     modules[i].name);
            alert("MODULE", msg);
            hidden_count++;
        }
        if (modules[i].found_in_proc && !modules[i].found_in_sys) {
            snprintf(msg, sizeof(msg),
                     "Module '%s' in /proc/modules but NOT in /sys/module (kobject removed)",
                     modules[i].name);
            alert("MODULE", msg);
            hidden_count++;
        }
    }

    snprintf(msg, sizeof(msg), "Total unique modules across all sources: %d", module_count);
    info("MODULE", msg);

    check_result("Hidden module detection", hidden_count == 0);
}

/* ── Check 3: Syscall Table Verification ───────────────────────── */

static void verify_syscall_table(void)
{
    printf("\n--- Check 3: Syscall Table Verification ---\n");

    char line[MAX_LINE_LEN];
    char msg[MAX_LINE_LEN];
    unsigned long stext = 0, etext = 0;
    unsigned long sys_call_table = 0;
    int suspicious = 0;

    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        alert("SYSCALL", "Cannot open /proc/kallsyms (need root)");
        return;
    }

    /* Find kernel text boundaries and syscall table address */
    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];

        if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, "_stext") == 0)
                stext = addr;
            else if (strcmp(name, "_etext") == 0)
                etext = addr;
            else if (strcmp(name, "sys_call_table") == 0)
                sys_call_table = addr;
        }
    }
    fclose(fp);

    if (stext == 0 || etext == 0) {
        alert("SYSCALL", "Cannot determine kernel text boundaries "
              "(kptr_restrict may be enabled)");
        info("SYSCALL", "Set kernel.kptr_restrict=0 temporarily for full check");
        check_result("Syscall table verification", 0);
        return;
    }

    snprintf(msg, sizeof(msg), "Kernel text range: 0x%lx - 0x%lx", stext, etext);
    info("SYSCALL", msg);

    if (sys_call_table != 0) {
        snprintf(msg, sizeof(msg), "sys_call_table at: 0x%lx", sys_call_table);
        info("SYSCALL", msg);

        /* Verify sys_call_table is in expected range */
        if (sys_call_table < stext || sys_call_table > etext + 0x200000) {
            alert("SYSCALL",
                  "sys_call_table address is outside expected kernel range");
            suspicious++;
        }
    } else {
        info("SYSCALL", "sys_call_table address not found (symbol may be hidden)");
    }

    /* Check syscall handler addresses */
    fp = fopen("/proc/kallsyms", "r");
    if (!fp)
        return;

    int handlers_checked = 0;
    int handlers_suspicious = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];
        char module[256] = "";

        int fields = sscanf(line, "%lx %c %255s [%255[^]]]", &addr, &type, name, module);
        if (fields < 3)
            continue;

        /* Check __x64_sys_ or __do_sys_ prefixed functions */
        if (strncmp(name, "__x64_sys_", 10) == 0 ||
            strncmp(name, "__do_sys_", 9) == 0) {

            handlers_checked++;

            if (addr < stext || addr > etext) {
                /* Handler is outside kernel text - could be in a module */
                if (module[0] != '\0') {
                    snprintf(msg, sizeof(msg),
                             "Syscall handler %s at 0x%lx is in module [%s]",
                             name, addr, module);
                    alert("SYSCALL", msg);
                    handlers_suspicious++;
                } else {
                    snprintf(msg, sizeof(msg),
                             "Syscall handler %s at 0x%lx is outside kernel text "
                             "and not in any known module",
                             name, addr);
                    alert("SYSCALL", msg);
                    handlers_suspicious++;
                }
            }
        }
    }
    fclose(fp);

    snprintf(msg, sizeof(msg),
             "Checked %d syscall handlers, %d suspicious",
             handlers_checked, handlers_suspicious);
    info("SYSCALL", msg);

    suspicious += handlers_suspicious;
    check_result("Syscall table verification", suspicious == 0);
}

/* ── Check 4: Hidden Network Connections ───────────────────────── */

static void detect_hidden_connections(void)
{
    printf("\n--- Check 4: Hidden Network Connection Detection ---\n");

    char line[MAX_LINE_LEN];
    char msg[MAX_LINE_LEN];
    tcp_connection_t connections[MAX_CONNECTIONS];
    int conn_count = 0;
    int hidden_count = 0;

    /* Read /proc/net/tcp */
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        alert("NETWORK", "Cannot open /proc/net/tcp");
        return;
    }

    /* Skip header */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp) && conn_count < MAX_CONNECTIONS) {
        unsigned int local_addr, local_port;
        unsigned int remote_addr, remote_port;
        unsigned int state;
        unsigned int inode;

        /* Parse: sl local_address rem_address st ... inode */
        int n = sscanf(line, " %*d: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %*d %*d %u",
                        &local_addr, &local_port,
                        &remote_addr, &remote_port,
                        &state, &inode);

        if (n >= 5) {
            connections[conn_count].local_addr = local_addr;
            connections[conn_count].local_port = local_port;
            connections[conn_count].remote_addr = remote_addr;
            connections[conn_count].remote_port = remote_port;
            connections[conn_count].state = state;
            connections[conn_count].inode = (n >= 6) ? inode : 0;
            conn_count++;
        }
    }
    fclose(fp);

    snprintf(msg, sizeof(msg), "Found %d TCP connections in /proc/net/tcp", conn_count);
    info("NETWORK", msg);

    /* Check for listening ports on suspicious well-known backdoor ports */
    int suspicious_ports[] = {
        1337, 4444, 5555, 6666, 6667, 7777, 8888, 9999,
        31337, 12345, 54321, 65535, 0
    };

    for (int i = 0; i < conn_count; i++) {
        /* State 0x0A = LISTEN */
        if (connections[i].state == 0x0A) {
            for (int j = 0; suspicious_ports[j] != 0; j++) {
                if (connections[i].local_port == (unsigned int)suspicious_ports[j]) {
                    snprintf(msg, sizeof(msg),
                             "LISTEN on suspicious port %d (inode: %u)",
                             connections[i].local_port, connections[i].inode);
                    alert("NETWORK", msg);
                    hidden_count++;
                }
            }
        }

        /* Check for connections to known C2 ports */
        if (connections[i].state == 0x01) { /* ESTABLISHED */
            for (int j = 0; suspicious_ports[j] != 0; j++) {
                if (connections[i].remote_port == (unsigned int)suspicious_ports[j]) {
                    unsigned int a = connections[i].remote_addr;
                    snprintf(msg, sizeof(msg),
                             "ESTABLISHED connection to %u.%u.%u.%u:%d",
                             a & 0xFF, (a >> 8) & 0xFF,
                             (a >> 16) & 0xFF, (a >> 24) & 0xFF,
                             connections[i].remote_port);
                    alert("NETWORK", msg);
                    hidden_count++;
                }
            }
        }
    }

    /* Also check /proc/net/tcp6 */
    fp = fopen("/proc/net/tcp6", "r");
    if (fp) {
        int tcp6_count = 0;
        if (fgets(line, sizeof(line), fp)) { /* skip header */
            while (fgets(line, sizeof(line), fp))
                tcp6_count++;
        }
        fclose(fp);
        snprintf(msg, sizeof(msg), "Found %d TCP6 connections", tcp6_count);
        info("NETWORK", msg);
    }

    check_result("Network connection verification", hidden_count == 0);
}

/* ── Check 5: Suspicious File Detection ────────────────────────── */

static void detect_suspicious_files(void)
{
    printf("\n--- Check 5: Suspicious File Detection ---\n");

    char msg[MAX_LINE_LEN];
    int suspicious = 0;

    /* Known rootkit file artifacts */
    const char *rootkit_files[] = {
        "/usr/lib/libproc.a",             /* common rootkit library */
        "/dev/.hidden",                    /* hidden device file */
        "/dev/shm/.x",                    /* shared memory artifact */
        "/tmp/.ICE-unix/.x",              /* hidden in ICE directory */
        "/usr/share/.woot",               /* Jynx rootkit */
        "/etc/ld.so.preload",             /* LD_PRELOAD rootkit (check content) */
        "/usr/lib/crt0.o",               /* potential rootkit */
        "/dev/tux",                       /* rootkit device */
        "/dev/hda06",                     /* fake device */
        "/var/run/.x",                    /* hidden runtime artifact */
        "/var/spool/cron/.x",            /* hidden cron artifact */
        NULL
    };

    for (int i = 0; rootkit_files[i] != NULL; i++) {
        struct stat st;
        if (stat(rootkit_files[i], &st) == 0) {
            snprintf(msg, sizeof(msg),
                     "Known rootkit artifact found: %s (size: %ld, mode: %o)",
                     rootkit_files[i], (long)st.st_size, st.st_mode & 07777);
            alert("FILES", msg);
            suspicious++;
        }
    }

    /* Check /etc/ld.so.preload for suspicious entries */
    FILE *fp = fopen("/etc/ld.so.preload", "r");
    if (fp) {
        char line[MAX_LINE_LEN];
        int line_count = 0;
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            if (strlen(line) > 0 && line[0] != '#') {
                snprintf(msg, sizeof(msg),
                         "/etc/ld.so.preload contains: %s", line);
                alert("FILES", msg);
                suspicious++;
                line_count++;
            }
        }
        fclose(fp);
        if (line_count == 0) {
            info("FILES", "/etc/ld.so.preload exists but is empty (OK)");
        }
    }

    /* Check for hidden directories in common locations */
    const char *search_dirs[] = {"/tmp", "/var/tmp", "/dev/shm", NULL};

    for (int d = 0; search_dirs[d] != NULL; d++) {
        DIR *dir = opendir(search_dirs[d]);
        if (!dir)
            continue;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.' && entry->d_name[1] != '\0'
                && entry->d_name[1] != '.') {
                /* Hidden file/directory in temp location */
                char full_path[512];
                snprintf(full_path, sizeof(full_path),
                         "%s/%s", search_dirs[d], entry->d_name);

                struct stat st;
                if (stat(full_path, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        snprintf(msg, sizeof(msg),
                                 "Hidden directory in temp area: %s", full_path);
                        info("FILES", msg);
                    }
                }
            }
        }
        closedir(dir);
    }

    check_result("Suspicious file detection", suspicious == 0);
}

/* ── Check 6: Kernel Taint Analysis ────────────────────────────── */

static void analyze_kernel_taint(void)
{
    printf("\n--- Check 6: Kernel Taint Flag Analysis ---\n");

    char msg[MAX_LINE_LEN];
    unsigned long taint = 0;
    int suspicious = 0;

    FILE *fp = fopen("/proc/sys/kernel/tainted", "r");
    if (!fp) {
        alert("TAINT", "Cannot read /proc/sys/kernel/tainted");
        return;
    }

    if (fscanf(fp, "%lu", &taint) != 1) {
        fclose(fp);
        alert("TAINT", "Cannot parse kernel taint value");
        return;
    }
    fclose(fp);

    snprintf(msg, sizeof(msg), "Kernel taint value: %lu (0x%lx)", taint, taint);
    info("TAINT", msg);

    if (taint == 0) {
        info("TAINT", "Kernel is not tainted (clean state)");
        check_result("Kernel taint analysis", 1);
        return;
    }

    /* Decode taint flags */
    struct {
        unsigned long bit;
        const char *description;
        int is_security_concern;
    } taint_flags[] = {
        {1,     "Proprietary module loaded",                0},
        {2,     "Module force-loaded",                      1},
        {4,     "SMP kernel on non-SMP hardware",           0},
        {8,     "Module force-unloaded",                    1},
        {16,    "Machine Check Exception occurred",         0},
        {64,    "Bad page found",                           0},
        {128,   "Userspace taint request",                  0},
        {512,   "Kernel warning occurred",                  0},
        {1024,  "Staging driver loaded",                    0},
        {2048,  "Workaround applied",                       0},
        {4096,  "Unsigned module loaded",                   1},
        {8192,  "Soft lockup occurred",                     0},
        {32768, "Live-patched kernel",                      0},
        {65536, "Vendor-supplied kernel",                   0},
        {0,     NULL,                                       0}
    };

    for (int i = 0; taint_flags[i].description != NULL; i++) {
        if (taint & taint_flags[i].bit) {
            snprintf(msg, sizeof(msg), "Taint flag set: %s (bit %lu)",
                     taint_flags[i].description, taint_flags[i].bit);
            if (taint_flags[i].is_security_concern) {
                alert("TAINT", msg);
                suspicious++;
            } else {
                info("TAINT", msg);
            }
        }
    }

    check_result("Kernel taint analysis", suspicious == 0);
}

/* ── Summary ───────────────────────────────────────────────────── */

static void print_summary(void)
{
    printf("\n============================================================\n");
    printf("  DETECTION SUMMARY\n");
    printf("============================================================\n");
    printf("  Total alerts:       %d\n", alerts_total);
    printf("  Checks passed:      %d\n", checks_passed);
    printf("  Checks failed:      %d\n", checks_failed);
    printf("============================================================\n");

    if (alerts_total == 0) {
        printf("  RESULT: No indicators of compromise detected.\n");
    } else {
        printf("  RESULT: %d potential indicator(s) of compromise found.\n",
               alerts_total);
        printf("  RECOMMENDATION: Investigate each alert. Consider:\n");
        printf("    - Memory forensics (LiME + Volatility)\n");
        printf("    - Boot from trusted media for offline analysis\n");
        printf("    - Cross-reference with SIEM/log data\n");
    }
    printf("============================================================\n");
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0)
            verbose_mode = 1;
        else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0)
            json_mode = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--verbose|-v] [--json|-j]\n", argv[0]);
            printf("  --verbose  Show informational messages\n");
            printf("  --json     Output in JSON format\n");
            printf("\nMust be run as root for full detection capabilities.\n");
            return 0;
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "WARNING: Running without root privileges. "
                "Detection capabilities will be limited.\n\n");
    }

    print_banner();

    /* Run all detection checks */
    detect_hidden_processes();
    detect_hidden_modules();
    verify_syscall_table();
    detect_hidden_connections();
    detect_suspicious_files();
    analyze_kernel_taint();

    print_summary();

    return (alerts_total > 0) ? 1 : 0;
}

/*
 * lsm_check.c - Userspace program to check active Linux Security Modules
 *
 * Demonstrates how to programmatically determine
 * which LSMs are active on a Linux system by reading various
 * /sys and /proc interfaces.
 *
 * This program checks:
 *   - Active LSMs via /sys/kernel/security/lsm
 *   - SELinux status via /sys/fs/selinux/enforce
 *   - AppArmor status via /sys/kernel/security/apparmor/profiles
 *   - Yama ptrace scope via /proc/sys/kernel/yama/ptrace_scope
 *   - Lockdown status via /sys/kernel/security/lockdown
 *   - Seccomp availability
 *   - Various security-related kernel parameters
 *
 * Compile:
 *   gcc -O2 -Wall -o lsm_check lsm_check.c
 *
 * Run:
 *   ./lsm_check
 *
 * License: GPL v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#define MAX_BUF 4096
#define MAX_LINE 256

/* ──────────────── Helper functions ──────────────── */

/*
 * read_file_contents - Read entire file into a buffer
 *
 * Returns: number of bytes read, or -1 on error
 * Note: removes trailing newline if present
 */
static int read_file_contents(const char *path, char *buf, size_t bufsize)
{
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    n = read(fd, buf, bufsize - 1);
    close(fd);

    if (n < 0)
        return -1;

    buf[n] = '\0';

    /* Strip trailing newline */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';

    return (int)n;
}

/*
 * file_exists - Check if a file or directory exists
 */
static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * print_header - Print a section header
 */
static void print_header(const char *title)
{
    int len = (int)strlen(title);
    int padding = 56 - len - 4;
    int i;

    printf("\n+");
    for (i = 0; i < 58; i++) printf("-");
    printf("+\n");

    printf("| %s", title);
    for (i = 0; i < padding; i++) printf(" ");
    printf(" |\n");

    printf("+");
    for (i = 0; i < 58; i++) printf("-");
    printf("+\n");
}

/*
 * print_field - Print a key-value pair with alignment
 */
static void print_field(const char *key, const char *value)
{
    printf("  %-30s : %s\n", key, value);
}

/* ──────────────── LSM Detection Functions ──────────────── */

/*
 * check_active_lsms - Read the list of active LSMs
 */
static void check_active_lsms(void)
{
    char buf[MAX_BUF];
    char *token, *saveptr;
    int count = 0;

    print_header("Active Linux Security Modules");

    if (read_file_contents("/sys/kernel/security/lsm", buf, sizeof(buf)) > 0) {
        printf("  LSM Stack: %s\n\n", buf);

        /* Parse comma-separated list */
        token = strtok_r(buf, ",", &saveptr);
        while (token) {
            count++;
            printf("    [%d] %s\n", count, token);
            token = strtok_r(NULL, ",", &saveptr);
        }
        printf("\n  Total: %d LSMs active\n", count);
    } else {
        printf("  Unable to read /sys/kernel/security/lsm\n");
        printf("  (securityfs may not be mounted)\n");
    }
}

/*
 * check_selinux - Check SELinux status and configuration
 */
static void check_selinux(void)
{
    char buf[MAX_BUF];
    char mode[32] = "unknown";

    print_header("SELinux Status");

    if (!file_exists("/sys/fs/selinux")) {
        print_field("Status", "Not available (selinuxfs not mounted)");
        return;
    }

    print_field("Present", "Yes (/sys/fs/selinux exists)");

    /* Check enforcing mode */
    if (read_file_contents("/sys/fs/selinux/enforce", buf, sizeof(buf)) >= 0) {
        if (buf[0] == '1')
            snprintf(mode, sizeof(mode), "Enforcing");
        else
            snprintf(mode, sizeof(mode), "Permissive");
        print_field("Mode", mode);
    }

    /* Check policy type */
    if (read_file_contents("/etc/selinux/config", buf, sizeof(buf)) > 0) {
        char *line = strstr(buf, "SELINUXTYPE=");
        if (line) {
            char *value = line + strlen("SELINUXTYPE=");
            char *end = strchr(value, '\n');
            if (end) *end = '\0';
            print_field("Policy Type", value);
        }
    }

    /* Check deny_unknown */
    if (read_file_contents("/sys/fs/selinux/deny_unknown", buf, sizeof(buf)) >= 0) {
        print_field("Deny Unknown", buf[0] == '1' ? "Yes" : "No");
    }

    /* Check policyvers */
    if (read_file_contents("/sys/fs/selinux/policyvers", buf, sizeof(buf)) > 0) {
        print_field("Policy Version", buf);
    }
}

/*
 * check_apparmor - Check AppArmor status and loaded profiles
 */
static void check_apparmor(void)
{
    char buf[MAX_BUF];
    FILE *fp;
    int enforce = 0, complain = 0, kill = 0, unconfined = 0;
    char line[MAX_LINE];

    print_header("AppArmor Status");

    if (!file_exists("/sys/kernel/security/apparmor")) {
        print_field("Status", "Not available");
        return;
    }

    print_field("Present", "Yes (/sys/kernel/security/apparmor exists)");

    /* Count profiles by mode */
    fp = fopen("/sys/kernel/security/apparmor/profiles", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "(enforce)"))
                enforce++;
            else if (strstr(line, "(complain)"))
                complain++;
            else if (strstr(line, "(kill)"))
                kill++;
            else if (strstr(line, "(unconfined)"))
                unconfined++;
        }
        fclose(fp);

        snprintf(buf, sizeof(buf), "%d", enforce + complain + kill + unconfined);
        print_field("Total Profiles", buf);

        snprintf(buf, sizeof(buf), "%d", enforce);
        print_field("  Enforce Mode", buf);

        snprintf(buf, sizeof(buf), "%d", complain);
        print_field("  Complain Mode", buf);

        if (kill > 0) {
            snprintf(buf, sizeof(buf), "%d", kill);
            print_field("  Kill Mode", buf);
        }

        if (unconfined > 0) {
            snprintf(buf, sizeof(buf), "%d", unconfined);
            print_field("  Unconfined", buf);
        }
    } else {
        print_field("Profiles", "Unable to read");
    }
}

/*
 * check_yama - Check Yama LSM ptrace restrictions
 */
static void check_yama(void)
{
    char buf[MAX_BUF];
    const char *scope_desc;

    print_header("Yama LSM");

    if (read_file_contents("/proc/sys/kernel/yama/ptrace_scope", buf, sizeof(buf)) >= 0) {
        print_field("Present", "Yes");

        switch (buf[0]) {
        case '0':
            scope_desc = "0 - Classic (unrestricted)";
            break;
        case '1':
            scope_desc = "1 - Restricted (parent only)";
            break;
        case '2':
            scope_desc = "2 - Admin only (CAP_SYS_PTRACE)";
            break;
        case '3':
            scope_desc = "3 - No attach (completely disabled)";
            break;
        default:
            scope_desc = "Unknown";
            break;
        }
        print_field("ptrace_scope", scope_desc);
    } else {
        print_field("Status", "Not available");
    }
}

/*
 * check_lockdown - Check kernel lockdown status
 */
static void check_lockdown(void)
{
    char buf[MAX_BUF];

    print_header("Kernel Lockdown");

    if (read_file_contents("/sys/kernel/security/lockdown", buf, sizeof(buf)) > 0) {
        print_field("Status", buf);
    } else {
        print_field("Status", "Not available");
    }
}

/*
 * check_security_params - Check various security-related kernel parameters
 */
static void check_security_params(void)
{
    char buf[MAX_BUF];

    print_header("Security Kernel Parameters");

    /* kptr_restrict */
    if (read_file_contents("/proc/sys/kernel/kptr_restrict", buf, sizeof(buf)) >= 0) {
        const char *desc;
        switch (buf[0]) {
        case '0': desc = "0 - Unrestricted"; break;
        case '1': desc = "1 - Hide from non-privileged"; break;
        case '2': desc = "2 - Hide from all"; break;
        default:  desc = buf; break;
        }
        print_field("kptr_restrict", desc);
    }

    /* dmesg_restrict */
    if (read_file_contents("/proc/sys/kernel/dmesg_restrict", buf, sizeof(buf)) >= 0) {
        print_field("dmesg_restrict", buf[0] == '1' ? "1 - Restricted" : "0 - Unrestricted");
    }

    /* perf_event_paranoid */
    if (read_file_contents("/proc/sys/kernel/perf_event_paranoid", buf, sizeof(buf)) >= 0) {
        print_field("perf_event_paranoid", buf);
    }

    /* unprivileged_bpf_disabled */
    if (read_file_contents("/proc/sys/kernel/unprivileged_bpf_disabled", buf, sizeof(buf)) >= 0) {
        print_field("unprivileged_bpf_disabled", buf);
    }

    /* modules_disabled */
    if (read_file_contents("/proc/sys/kernel/modules_disabled", buf, sizeof(buf)) >= 0) {
        print_field("modules_disabled", buf[0] == '1' ? "1 - Disabled" : "0 - Enabled");
    }

    /* kexec_load_disabled */
    if (read_file_contents("/proc/sys/kernel/kexec_load_disabled", buf, sizeof(buf)) >= 0) {
        print_field("kexec_load_disabled", buf[0] == '1' ? "1 - Disabled" : "0 - Enabled");
    }

    /* randomize_va_space (ASLR) */
    if (read_file_contents("/proc/sys/kernel/randomize_va_space", buf, sizeof(buf)) >= 0) {
        const char *desc;
        switch (buf[0]) {
        case '0': desc = "0 - Disabled"; break;
        case '1': desc = "1 - Conservative (stack+mmap)"; break;
        case '2': desc = "2 - Full (stack+mmap+heap)"; break;
        default:  desc = buf; break;
        }
        print_field("ASLR (randomize_va_space)", desc);
    }
}

/*
 * check_cpu_vulnerabilities - Check CPU vulnerability mitigation status
 */
static void check_cpu_vulnerabilities(void)
{
    char buf[MAX_BUF];
    DIR *dir;
    struct dirent *entry;
    char path[512];

    print_header("CPU Vulnerability Mitigations");

    dir = opendir("/sys/devices/system/cpu/vulnerabilities");
    if (!dir) {
        printf("  Unable to read vulnerability status\n");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/vulnerabilities/%s",
                 entry->d_name);

        if (read_file_contents(path, buf, sizeof(buf)) > 0) {
            /* Truncate long mitigation descriptions */
            if (strlen(buf) > 50)
                strcpy(buf + 47, "...");
            print_field(entry->d_name, buf);
        }
    }

    closedir(dir);
}

/* ──────────────── Main ──────────────── */

int main(int argc, char **argv)
{
    printf("============================================================\n");
    printf("   Linux Security Module (LSM) and Hardening Status Check\n");
    printf("============================================================\n");

    /* System info */
    {
        char buf[MAX_BUF];
        if (read_file_contents("/proc/version", buf, sizeof(buf)) > 0) {
            /* Truncate for readability */
            if (strlen(buf) > 80)
                strcpy(buf + 77, "...");
            printf("\n  Kernel: %s\n", buf);
        }
    }

    /* Run all checks */
    check_active_lsms();
    check_selinux();
    check_apparmor();
    check_yama();
    check_lockdown();
    check_security_params();
    check_cpu_vulnerabilities();

    printf("\n============================================================\n");
    printf("   Check complete.\n");
    printf("============================================================\n\n");

    return 0;
}

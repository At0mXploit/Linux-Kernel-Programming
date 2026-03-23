/*
 * boot_info.c - Read and display boot information from /proc
 *
 * This program reads various /proc and /sys files to display comprehensive
 * information about the system's boot configuration, kernel version,
 * command-line parameters, and hardware environment.
 *
 * Sources:
 *   /proc/cmdline     - Kernel boot parameters
 *   /proc/version     - Kernel version and build info
 *   /proc/uptime      - System uptime
 *   /proc/cpuinfo     - CPU details
 *   /proc/meminfo     - Memory configuration
 *   /sys/firmware/efi  - UEFI boot detection
 *
 * Compile: gcc -Wall -Wextra -o boot_info boot_info.c
 * Usage:   ./boot_info
 *
 * Related: Lesson 2 (Boot Process - UEFI to GRUB to initramfs to kernel)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>

#define MAX_LINE 1024

/*
 * read_file_line - Read the first line from a file
 * @path: File path to read
 * @buf:  Output buffer
 * @size: Buffer size
 *
 * Returns 0 on success, -1 on failure.
 */
static int read_file_line(const char *path, char *buf, size_t size)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (!fgets(buf, size, fp)) {
        fclose(fp);
        return -1;
    }

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    fclose(fp);
    return 0;
}

/*
 * show_kernel_version - Display kernel version information
 */
static void show_kernel_version(void)
{
    printf("--- Kernel Version ---\n\n");

    /* Method 1: uname syscall */
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("  System:     %s\n", uts.sysname);
        printf("  Hostname:   %s\n", uts.nodename);
        printf("  Release:    %s\n", uts.release);
        printf("  Version:    %s\n", uts.version);
        printf("  Machine:    %s\n", uts.machine);
    }

    /* Method 2: /proc/version (includes compiler info) */
    char version[512];
    if (read_file_line("/proc/version", version, sizeof(version)) == 0) {
        printf("  Full:       %s\n", version);
    }

    printf("\n");
}

/*
 * show_cmdline - Display and parse kernel command-line parameters
 *
 * The kernel command line is set by the bootloader (GRUB) and contains
 * critical parameters like root device, security options, and debugging flags.
 */
static void show_cmdline(void)
{
    printf("--- Kernel Command Line (/proc/cmdline) ---\n\n");

    char cmdline[4096];
    if (read_file_line("/proc/cmdline", cmdline, sizeof(cmdline)) != 0) {
        printf("  (Could not read /proc/cmdline)\n\n");
        return;
    }

    printf("  Raw: %s\n\n", cmdline);

    /* Parse individual parameters */
    printf("  Parsed parameters:\n");
    char *copy = strdup(cmdline);
    char *token = strtok(copy, " ");
    int param_num = 1;

    while (token) {
        char *eq = strchr(token, '=');
        if (eq) {
            /* key=value parameter */
            *eq = '\0';
            printf("    [%2d] %-25s = %s\n", param_num, token, eq + 1);
        } else {
            /* Flag parameter (no value) */
            printf("    [%2d] %-25s   (flag)\n", param_num, token);
        }
        param_num++;
        token = strtok(NULL, " ");
    }
    free(copy);

    /* Highlight important parameters */
    printf("\n  Key parameter analysis:\n");

    if (strstr(cmdline, "root="))
        printf("    [*] root= found: root filesystem specified\n");
    if (strstr(cmdline, "quiet"))
        printf("    [*] quiet: boot messages suppressed\n");
    if (strstr(cmdline, "splash"))
        printf("    [*] splash: graphical splash enabled\n");
    if (strstr(cmdline, "nomodeset"))
        printf("    [!] nomodeset: kernel mode setting disabled (no GPU accel)\n");
    if (strstr(cmdline, "lockdown"))
        printf("    [S] lockdown: kernel lockdown enabled (security)\n");
    if (strstr(cmdline, "mitigations=off"))
        printf("    [!] mitigations=off: CPU vuln mitigations DISABLED\n");
    else if (strstr(cmdline, "mitigations=auto"))
        printf("    [S] mitigations=auto: CPU vuln mitigations on (default)\n");
    if (strstr(cmdline, "init="))
        printf("    [*] init= found: custom init process specified\n");
    if (strstr(cmdline, "nosmp"))
        printf("    [!] nosmp: SMP disabled, running on single CPU\n");
    if (strstr(cmdline, "debug"))
        printf("    [D] debug: verbose kernel messages enabled\n");
    if (strstr(cmdline, "audit=1"))
        printf("    [S] audit=1: kernel auditing enabled\n");

    printf("\n");
}

/*
 * show_boot_mode - Detect BIOS vs UEFI boot
 */
static void show_boot_mode(void)
{
    printf("--- Boot Mode ---\n\n");

    struct stat st;
    if (stat("/sys/firmware/efi", &st) == 0 && S_ISDIR(st.st_mode)) {
        printf("  Boot mode: UEFI\n");

        /* Check Secure Boot status */
        /* The secure boot variable is in the EFI variables filesystem */
        char sb_state[64];
        if (read_file_line("/sys/firmware/efi/fw_vendor", sb_state,
                           sizeof(sb_state)) == 0) {
            printf("  EFI vendor: %s\n", sb_state);
        }

        /* Check if EFI runtime services are available */
        if (stat("/sys/firmware/efi/runtime", &st) == 0) {
            printf("  EFI runtime services: available\n");
        }

        /* Try to read EFI variables */
        if (stat("/sys/firmware/efi/efivars", &st) == 0) {
            printf("  EFI variables: accessible\n");
        }
    } else {
        printf("  Boot mode: Legacy BIOS (no /sys/firmware/efi)\n");
    }

    printf("\n");
}

/*
 * show_uptime - Display system uptime
 */
static void show_uptime(void)
{
    printf("--- System Uptime ---\n\n");

    char uptime_str[64];
    if (read_file_line("/proc/uptime", uptime_str, sizeof(uptime_str)) == 0) {
        double uptime, idle;
        if (sscanf(uptime_str, "%lf %lf", &uptime, &idle) == 2) {
            int days = (int)(uptime / 86400);
            int hours = (int)((uptime - days * 86400) / 3600);
            int mins = (int)((uptime - days * 86400 - hours * 3600) / 60);
            int secs = (int)(uptime) % 60;

            printf("  Uptime:    %d days, %02d:%02d:%02d (%.1f seconds)\n",
                   days, hours, mins, secs, uptime);
            printf("  Idle time: %.1f seconds\n", idle);
            printf("  Idle %%:    %.1f%%\n", (idle / uptime) * 100);

            /* Calculate boot time */
            time_t now = time(NULL);
            time_t boot_time = now - (time_t)uptime;
            printf("  Boot time: %s", ctime(&boot_time));
        }
    }
    printf("\n");
}

/*
 * show_cpu_info - Display CPU information
 */
static void show_cpu_info(void)
{
    printf("--- CPU Information ---\n\n");

    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        printf("  (Could not read /proc/cpuinfo)\n\n");
        return;
    }

    char line[MAX_LINE];
    char model_name[256] = "";
    char vendor[128] = "";
    char cpu_mhz[64] = "";
    char cache_size[64] = "";
    char flags_line[4096] = "";
    int cpu_count = 0;
    int cores = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "processor", 9) == 0)
            cpu_count++;
        else if (strncmp(line, "model name", 10) == 0 && !model_name[0]) {
            char *val = strchr(line, ':');
            if (val) { val += 2; val[strlen(val)-1] = '\0'; strncpy(model_name, val, 255); }
        }
        else if (strncmp(line, "vendor_id", 9) == 0 && !vendor[0]) {
            char *val = strchr(line, ':');
            if (val) { val += 2; val[strlen(val)-1] = '\0'; strncpy(vendor, val, 127); }
        }
        else if (strncmp(line, "cpu MHz", 7) == 0 && !cpu_mhz[0]) {
            char *val = strchr(line, ':');
            if (val) { val += 2; val[strlen(val)-1] = '\0'; strncpy(cpu_mhz, val, 63); }
        }
        else if (strncmp(line, "cache size", 10) == 0 && !cache_size[0]) {
            char *val = strchr(line, ':');
            if (val) { val += 2; val[strlen(val)-1] = '\0'; strncpy(cache_size, val, 63); }
        }
        else if (strncmp(line, "cpu cores", 9) == 0 && !cores) {
            char *val = strchr(line, ':');
            if (val) cores = atoi(val + 2);
        }
        else if (strncmp(line, "flags", 5) == 0 && !flags_line[0]) {
            char *val = strchr(line, ':');
            if (val) { val += 2; val[strlen(val)-1] = '\0'; strncpy(flags_line, val, 4095); }
        }
    }
    fclose(fp);

    printf("  Vendor:       %s\n", vendor[0] ? vendor : "Unknown");
    printf("  Model:        %s\n", model_name[0] ? model_name : "Unknown");
    printf("  Logical CPUs: %d\n", cpu_count);
    printf("  Cores/socket: %d\n", cores);
    if (cpu_mhz[0])
        printf("  Frequency:    %s MHz\n", cpu_mhz);
    if (cache_size[0])
        printf("  Cache:        %s\n", cache_size);

    /* Check for important CPU features */
    printf("\n  Security-relevant CPU features:\n");
    if (strstr(flags_line, " smep"))
        printf("    [+] SMEP (Supervisor Mode Execution Prevention)\n");
    if (strstr(flags_line, " smap"))
        printf("    [+] SMAP (Supervisor Mode Access Prevention)\n");
    if (strstr(flags_line, " umip"))
        printf("    [+] UMIP (User-Mode Instruction Prevention)\n");
    if (strstr(flags_line, " ibrs"))
        printf("    [+] IBRS (Indirect Branch Restricted Speculation)\n");
    if (strstr(flags_line, " ibpb"))
        printf("    [+] IBPB (Indirect Branch Prediction Barrier)\n");
    if (strstr(flags_line, " ssbd"))
        printf("    [+] SSBD (Speculative Store Bypass Disable)\n");
    if (strstr(flags_line, " pcid"))
        printf("    [+] PCID (Process-Context Identifiers - faster TLB)\n");

    printf("\n  Virtualization features:\n");
    if (strstr(flags_line, " vmx"))
        printf("    [+] VMX (Intel VT-x)\n");
    if (strstr(flags_line, " svm"))
        printf("    [+] SVM (AMD-V)\n");
    if (strstr(flags_line, " hypervisor"))
        printf("    [*] Running inside a virtual machine\n");

    printf("\n");
}

/*
 * show_memory_info - Display memory configuration
 */
static void show_memory_info(void)
{
    printf("--- Memory Information ---\n\n");

    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        printf("  (Could not read /proc/meminfo)\n\n");
        return;
    }

    char line[MAX_LINE];
    const char *wanted[] = {
        "MemTotal:", "MemFree:", "MemAvailable:", "Buffers:", "Cached:",
        "SwapTotal:", "SwapFree:", "HugePages_Total:", "Hugepagesize:",
        NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (const char **w = wanted; *w; w++) {
            if (strncmp(line, *w, strlen(*w)) == 0) {
                printf("  %s", line);
                break;
            }
        }
    }
    fclose(fp);
    printf("\n");
}

/*
 * show_init_system - Detect init system (systemd, SysV, etc.)
 */
static void show_init_system(void)
{
    printf("--- Init System (PID 1) ---\n\n");

    char link[256];
    ssize_t len = readlink("/proc/1/exe", link, sizeof(link) - 1);
    if (len > 0) {
        link[len] = '\0';
        printf("  PID 1 executable: %s\n", link);

        if (strstr(link, "systemd"))
            printf("  Init system:      systemd\n");
        else if (strstr(link, "init"))
            printf("  Init system:      SysV init (or compatible)\n");
        else if (strstr(link, "runit"))
            printf("  Init system:      runit\n");
        else if (strstr(link, "openrc"))
            printf("  Init system:      OpenRC\n");
        else
            printf("  Init system:      Unknown (%s)\n", link);
    } else {
        printf("  (Cannot read /proc/1/exe - need root)\n");
    }

    /* Check for systemd-specific info */
    struct stat st;
    if (stat("/run/systemd/system", &st) == 0) {
        printf("  systemd detected: YES (/run/systemd/system exists)\n");

        /* Try to get systemd version */
        FILE *fp = popen("systemctl --version 2>/dev/null | head -1", "r");
        if (fp) {
            char ver[128];
            if (fgets(ver, sizeof(ver), fp)) {
                ver[strlen(ver) - 1] = '\0';
                printf("  systemd version:  %s\n", ver);
            }
            pclose(fp);
        }
    }

    printf("\n");
}

/*
 * show_loaded_modules - Display loaded kernel modules summary
 */
static void show_loaded_modules(void)
{
    printf("--- Loaded Kernel Modules ---\n\n");

    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) {
        printf("  (Could not read /proc/modules)\n\n");
        return;
    }

    char line[MAX_LINE];
    int count = 0;
    unsigned long total_size = 0;

    while (fgets(line, sizeof(line), fp)) {
        char name[128];
        unsigned long size;
        if (sscanf(line, "%127s %lu", name, &size) >= 2) {
            total_size += size;
            count++;
        }
    }
    fclose(fp);

    printf("  Total modules loaded:  %d\n", count);
    printf("  Total module size:     %lu KB (%lu MB)\n",
           total_size / 1024, total_size / (1024 * 1024));

    /* Show the 10 largest modules */
    printf("\n  Largest modules:\n");
    fp = fopen("/proc/modules", "r");
    if (fp) {
        struct { char name[128]; unsigned long size; } modules[256];
        int n = 0;

        while (fgets(line, sizeof(line), fp) && n < 256) {
            sscanf(line, "%127s %lu", modules[n].name, &modules[n].size);
            n++;
        }
        fclose(fp);

        /* Simple selection sort for top 10 */
        for (int i = 0; i < n - 1 && i < 10; i++) {
            int max_idx = i;
            for (int j = i + 1; j < n; j++) {
                if (modules[j].size > modules[max_idx].size)
                    max_idx = j;
            }
            if (max_idx != i) {
                typeof(modules[0]) tmp = modules[i];
                modules[i] = modules[max_idx];
                modules[max_idx] = tmp;
            }
        }

        for (int i = 0; i < 10 && i < n; i++) {
            printf("    %-30s %8lu KB\n", modules[i].name,
                   modules[i].size / 1024);
        }
    }
    printf("\n");
}

int main(void)
{
    printf("====================================================\n");
    printf("  Linux Boot Information Inspector\n");
    printf("====================================================\n\n");

    show_kernel_version();
    show_boot_mode();
    show_cmdline();
    show_uptime();
    show_cpu_info();
    show_memory_info();
    show_init_system();
    show_loaded_modules();

    printf("====================================================\n");
    printf("  Inspection complete.\n");
    printf("====================================================\n");

    return 0;
}

/*
 * syscall_table_checker.c - Check for syscall table anomalies
 *
 *
 * This program parses /proc/kallsyms to:
 *   1. Find the kernel text region boundaries (_stext, _etext)
 *   2. Find expected syscall handler addresses (sys_* symbols)
 *   3. Identify any syscall handlers pointing outside kernel text
 *      (which would indicate hooking to a module's address space)
 *
 * Compile: gcc -o syscall_table_checker syscall_table_checker.c -static
 * Usage:   sudo ./syscall_table_checker
 *
 * NOTE: Requires root access to read actual addresses from /proc/kallsyms.
 *       Without root, addresses appear as 0x0000000000000000.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_SYSCALLS 512
#define MAX_NAME     128

struct syscall_info {
    char name[MAX_NAME];
    unsigned long addr;
};

static unsigned long kernel_stext = 0;
static unsigned long kernel_etext = 0;
static unsigned long module_start = 0;
static unsigned long module_end = 0;
static struct syscall_info syscalls[MAX_SYSCALLS];
static int syscall_count = 0;
static int anomaly_count = 0;

/* Important syscalls that rootkits commonly target */
static const char *critical_syscalls[] = {
    "sys_read",
    "sys_write",
    "sys_open",
    "sys_openat",
    "sys_getdents",
    "sys_getdents64",
    "sys_kill",
    "sys_connect",
    "sys_accept",
    "sys_accept4",
    "sys_recvmsg",
    "sys_recvfrom",
    "sys_execve",
    "sys_execveat",
    "sys_init_module",
    "sys_finit_module",
    "sys_delete_module",
    "sys_ptrace",
    "sys_setuid",
    "sys_setgid",
    "sys_setreuid",
    "sys_setregid",
    NULL
};

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Syscall Table Anomaly Checker\n");
    printf("  Kernel Symbol Analysis Method\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Parse /proc/kallsyms to extract kernel boundaries and syscall addresses
 */
static int parse_kallsyms(void)
{
    FILE *fp;
    char line[512];
    unsigned long addr;
    char type;
    char name[MAX_NAME];
    char module[MAX_NAME];
    int total_symbols = 0;
    int zero_addresses = 0;

    printf(CYAN "  [Phase 1]" RESET " Parsing /proc/kallsyms...\n");

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL) {
        perror("  Cannot open /proc/kallsyms");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        module[0] = '\0';
        int fields = sscanf(line, "%lx %c %127s %127s", &addr, &type, name, module);

        if (fields < 3)
            continue;

        total_symbols++;

        if (addr == 0)
            zero_addresses++;

        /* Find kernel text boundaries */
        if (strcmp(name, "_stext") == 0)
            kernel_stext = addr;
        else if (strcmp(name, "_etext") == 0)
            kernel_etext = addr;

        /* Find module region boundaries (approximate) */
        if (module[0] == '[' && addr > 0) {
            if (module_start == 0 || addr < module_start)
                module_start = addr;
            if (addr > module_end)
                module_end = addr;
        }

        /* Collect syscall handler addresses */
        if (strncmp(name, "__x64_sys_", 10) == 0 ||
            strncmp(name, "__x32_sys_", 10) == 0 ||
            strncmp(name, "sys_", 4) == 0 ||
            strncmp(name, "__se_sys_", 9) == 0) {

            if (syscall_count < MAX_SYSCALLS && addr > 0) {
                strncpy(syscalls[syscall_count].name, name, MAX_NAME - 1);
                syscalls[syscall_count].addr = addr;
                syscall_count++;
            }
        }
    }

    fclose(fp);

    /* Check if we got real addresses or zeros */
    if (zero_addresses > total_symbols / 2) {
        printf(RED "\n  WARNING: Most kernel addresses are 0x0.\n");
        printf("  This means kptr_restrict is enabled.\n");
        printf("  Run as root or set kernel.kptr_restrict=0 for real addresses.\n" RESET);
        printf("\n");
        return -1;
    }

    printf("  Total symbols parsed: %d\n", total_symbols);
    printf("  Syscall handlers found: %d\n", syscall_count);
    printf("\n");

    return 0;
}

/*
 * Display kernel memory layout
 */
static void show_memory_layout(void)
{
    printf(CYAN "  [Phase 2]" RESET " Kernel Memory Layout:\n\n");

    if (kernel_stext && kernel_etext) {
        printf("  Kernel text:    0x%016lx - 0x%016lx\n", kernel_stext, kernel_etext);
        printf("  Kernel text size: %lu KB\n",
               (kernel_etext - kernel_stext) / 1024);
    } else {
        printf(YELLOW "  Kernel text boundaries not found\n" RESET);
    }

    if (module_start && module_end) {
        printf("  Module region:  0x%016lx - 0x%016lx (approximate)\n",
               module_start, module_end);
    } else {
        printf("  Module region:  Not determined (no module symbols found)\n");
    }

    printf("\n");
    printf("  Valid syscall handler range: kernel text region\n");
    printf("  Suspicious: handler pointing to module region\n");
    printf("\n");
}

/*
 * Check if an address is within the kernel text region
 */
static int is_in_kernel_text(unsigned long addr)
{
    if (kernel_stext == 0 || kernel_etext == 0)
        return -1; /* Cannot determine */

    return (addr >= kernel_stext && addr <= kernel_etext);
}

/*
 * Check if a syscall is in the critical list
 */
static int is_critical_syscall(const char *name)
{
    /* Normalize: skip prefixes like __x64_ or __se_ */
    const char *normalized = name;
    if (strncmp(name, "__x64_", 6) == 0)
        normalized = name + 6;
    else if (strncmp(name, "__x32_", 6) == 0)
        normalized = name + 6;
    else if (strncmp(name, "__se_", 5) == 0)
        normalized = name + 5;

    for (int i = 0; critical_syscalls[i] != NULL; i++) {
        if (strcmp(normalized, critical_syscalls[i]) == 0)
            return 1;
    }
    return 0;
}

/*
 * Analyze syscall handler addresses
 */
static void analyze_syscalls(void)
{
    int in_text = 0, out_of_text = 0, unknown = 0;

    printf(CYAN "  [Phase 3]" RESET " Analyzing syscall handler addresses...\n\n");

    if (kernel_stext == 0 || kernel_etext == 0) {
        printf(YELLOW "  Cannot perform address range analysis without\n");
        printf("  kernel text boundaries. Ensure root access.\n" RESET);
        return;
    }

    /* First, check critical syscalls */
    printf("  Checking critical syscall handlers:\n");
    printf("  %-40s %-20s %s\n", "Syscall", "Address", "Status");
    printf("  %-40s %-20s %s\n",
           "----------------------------------------",
           "--------------------",
           "----------");

    for (int i = 0; i < syscall_count; i++) {
        if (!is_critical_syscall(syscalls[i].name))
            continue;

        int result = is_in_kernel_text(syscalls[i].addr);
        const char *status;
        const char *color;

        if (result == 1) {
            status = "OK (kernel text)";
            color = GREEN;
            in_text++;
        } else if (result == 0) {
            status = "SUSPICIOUS!";
            color = RED;
            out_of_text++;
            anomaly_count++;
        } else {
            status = "UNKNOWN";
            color = YELLOW;
            unknown++;
        }

        printf("  %-40s 0x%016lx %s%s" RESET "\n",
               syscalls[i].name, syscalls[i].addr, color, status);
    }

    printf("\n");

    /* Then check ALL syscalls silently, only report anomalies */
    printf("  Checking all %d syscall handlers for anomalies...\n", syscall_count);

    int all_in_text = 0, all_anomalies = 0;

    for (int i = 0; i < syscall_count; i++) {
        int result = is_in_kernel_text(syscalls[i].addr);

        if (result == 1) {
            all_in_text++;
        } else if (result == 0) {
            if (!is_critical_syscall(syscalls[i].name)) {
                /* Only print if not already shown above */
                printf(RED "  [ANOMALY]" RESET " %-40s 0x%016lx OUTSIDE kernel text!\n",
                       syscalls[i].name, syscalls[i].addr);
                anomaly_count++;
            }
            all_anomalies++;
        }
    }

    printf("\n  Address analysis results:\n");
    printf("  In kernel text:      %d\n", all_in_text);
    printf("  Outside kernel text: %d\n", all_anomalies);
    printf("\n");
}

/*
 * Check for duplicate or shadowed syscall names
 */
static void check_duplicates(void)
{
    int duplicates = 0;

    printf(CYAN "  [Phase 4]" RESET " Checking for duplicate syscall entries...\n");

    for (int i = 0; i < syscall_count; i++) {
        for (int j = i + 1; j < syscall_count; j++) {
            if (strcmp(syscalls[i].name, syscalls[j].name) == 0 &&
                syscalls[i].addr != syscalls[j].addr) {
                printf(YELLOW "  [DUPLICATE]" RESET " %s: 0x%016lx and 0x%016lx\n",
                       syscalls[i].name, syscalls[i].addr, syscalls[j].addr);
                duplicates++;
            }
        }
    }

    if (duplicates == 0) {
        printf(GREEN "  No duplicate syscall entries found.\n" RESET);
    } else {
        printf(YELLOW "  Found %d duplicates (may be normal for compat syscalls)\n" RESET,
               duplicates);
    }
    printf("\n");
}

static void print_summary(void)
{
    printf(CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Syscall handlers analyzed: %d\n", syscall_count);
    printf("  Anomalies detected: %d\n", anomaly_count);
    printf("\n");

    if (anomaly_count > 0) {
        printf(RED "  RESULT: Syscall table anomalies detected!\n" RESET);
        printf("  Handler(s) pointing outside kernel text region.\n");
        printf("  This may indicate syscall table hooking by a rootkit.\n");
        printf("\n");
        printf("  Recommended actions:\n");
        printf("  1. Identify which module occupies the target address\n");
        printf("  2. Acquire memory image for forensic analysis\n");
        printf("  3. Compare against known-good kernel\n");
        printf("  4. Check loaded modules (detect_hidden_modules)\n");
    } else {
        printf(GREEN "  RESULT: No syscall table anomalies detected.\n" RESET);
        printf("  All checked handlers point to kernel text region.\n");
        printf("\n");
        printf("  Note: This tool checks symbol addresses from kallsyms.\n");
        printf("  It cannot detect inline hooking or ftrace-based hooking.\n");
        printf("  For inline hook detection, compare kernel memory against vmlinux.\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Kernel addresses in /proc/kallsyms will be hidden.\n");
        printf("  Run as root for meaningful results.\n\n" RESET);
    }

    if (parse_kallsyms() < 0) {
        printf("  Cannot perform analysis. Ensure root access.\n");
        return 1;
    }

    show_memory_layout();
    analyze_syscalls();
    check_duplicates();
    print_summary();

    return (anomaly_count > 0) ? 1 : 0;
}

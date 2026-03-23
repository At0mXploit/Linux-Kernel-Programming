/*
 * detect_hidden_modules.c - Detect hidden kernel modules
 *
 *
 * Detection methodology:
 *   Source 1: /proc/modules (kernel module list)
 *   Source 2: /sys/module/  (sysfs module directory)
 *   Source 3: /proc/kallsyms (kernel symbol table - module attribution)
 *
 *   A rootkit that hides from /proc/modules but forgets to clean
 *   /sys/module or /proc/kallsyms creates a detectable discrepancy.
 *
 * Compile: gcc -o detect_hidden_modules detect_hidden_modules.c -static
 * Usage:   sudo ./detect_hidden_modules
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_MODULES  2048
#define MAX_NAME_LEN 256

struct module_entry {
    char name[MAX_NAME_LEN];
    int in_proc_modules;    /* Found in /proc/modules */
    int in_sys_module;      /* Found in /sys/module/ */
    int in_kallsyms;        /* Has symbols in /proc/kallsyms */
};

static struct module_entry modules[MAX_MODULES];
static int module_count = 0;
static int discrepancies = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Hidden Kernel Module Detection Tool\n");
    printf("  Cross-Reference Analysis Method\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Find or create a module entry by name
 */
static struct module_entry *get_module(const char *name)
{
    for (int i = 0; i < module_count; i++) {
        if (strcmp(modules[i].name, name) == 0)
            return &modules[i];
    }

    if (module_count >= MAX_MODULES) {
        fprintf(stderr, "Warning: Module table full\n");
        return NULL;
    }

    struct module_entry *m = &modules[module_count++];
    strncpy(m->name, name, MAX_NAME_LEN - 1);
    m->name[MAX_NAME_LEN - 1] = '\0';
    m->in_proc_modules = 0;
    m->in_sys_module = 0;
    m->in_kallsyms = 0;

    return m;
}

/*
 * Source 1: Parse /proc/modules
 *
 * Format: module_name size ref_count dependencies state address
 * Example: ext4 815104 1 mbcache,jbd2, Live 0xffffffffc0800000
 */
static int scan_proc_modules(void)
{
    FILE *fp;
    char line[1024];
    char name[MAX_NAME_LEN];
    int count = 0;

    printf(CYAN "  [Source 1]" RESET " Scanning /proc/modules...\n");

    fp = fopen("/proc/modules", "r");
    if (fp == NULL) {
        perror("  Cannot open /proc/modules");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%255s", name) == 1) {
            struct module_entry *m = get_module(name);
            if (m != NULL) {
                m->in_proc_modules = 1;
                count++;
            }
        }
    }

    fclose(fp);
    printf("  Found %d modules in /proc/modules\n\n", count);
    return count;
}

/*
 * Source 2: Enumerate /sys/module/ directory
 *
 * Each loaded module has a directory under /sys/module/.
 * Note: Built-in kernel modules (compiled into vmlinux) also
 * appear here, so not all /sys/module entries are loadable modules.
 * We distinguish them by checking for a "coresize" or "initstate" file.
 */
static int scan_sys_module(void)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    int builtin_count = 0;
    char path[512];

    printf(CYAN "  [Source 2]" RESET " Scanning /sys/module/...\n");

    dir = opendir("/sys/module");
    if (dir == NULL) {
        perror("  Cannot open /sys/module");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        /* Check if this is a loadable module (has initstate file) */
        snprintf(path, sizeof(path), "/sys/module/%s/initstate", entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0) {
            /* This is a loadable module (has initstate) */
            struct module_entry *m = get_module(entry->d_name);
            if (m != NULL) {
                m->in_sys_module = 1;
                count++;
            }
        } else {
            /* Check for coresize as alternative indicator */
            snprintf(path, sizeof(path), "/sys/module/%s/coresize", entry->d_name);
            if (stat(path, &st) == 0) {
                struct module_entry *m = get_module(entry->d_name);
                if (m != NULL) {
                    m->in_sys_module = 1;
                    count++;
                }
            } else {
                /* Built-in module (parameter-only sysfs entry) */
                builtin_count++;
            }
        }
    }

    closedir(dir);
    printf("  Found %d loadable modules in /sys/module/\n", count);
    printf("  (Plus %d built-in module parameter entries)\n\n", builtin_count);
    return count;
}

/*
 * Source 3: Scan /proc/kallsyms for module-attributed symbols
 *
 * Format: address type name [module_name]
 * Example: ffffffffc0800000 t ext4_init [ext4]
 *
 * Symbols with [module_name] belong to loadable modules.
 */
static int scan_kallsyms(void)
{
    FILE *fp;
    char line[1024];
    int count = 0;
    char prev_module[MAX_NAME_LEN] = "";

    printf(CYAN "  [Source 3]" RESET " Scanning /proc/kallsyms for module symbols...\n");

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL) {
        perror("  Cannot open /proc/kallsyms");
        printf("  Note: May need root access or kernel.kptr_restrict=0\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Look for lines with [module_name] at the end */
        char *bracket_open = strchr(line, '[');
        char *bracket_close = strchr(line, ']');

        if (bracket_open != NULL && bracket_close != NULL &&
            bracket_close > bracket_open) {
            char module_name[MAX_NAME_LEN];
            int len = (int)(bracket_close - bracket_open - 1);
            if (len > 0 && len < MAX_NAME_LEN) {
                strncpy(module_name, bracket_open + 1, len);
                module_name[len] = '\0';

                /* Only count each module once */
                if (strcmp(module_name, prev_module) != 0) {
                    struct module_entry *m = get_module(module_name);
                    if (m != NULL) {
                        m->in_kallsyms = 1;
                        count++;
                    }
                    strncpy(prev_module, module_name, MAX_NAME_LEN - 1);
                }
            }
        }
    }

    fclose(fp);
    printf("  Found %d modules with symbols in /proc/kallsyms\n\n", count);
    return count;
}

/*
 * Perform cross-reference analysis
 */
static void cross_reference_analysis(void)
{
    printf(CYAN "============================================\n");
    printf("  Cross-Reference Analysis Results\n");
    printf("============================================\n" RESET);
    printf("\n");

    /* Check for discrepancies */
    printf("  Checking for modules present in one source but not others:\n\n");

    for (int i = 0; i < module_count; i++) {
        struct module_entry *m = &modules[i];
        int anomaly = 0;

        /*
         * Case 1: In /sys/module but NOT in /proc/modules
         * This could indicate a module that hid from /proc/modules
         * (DKOM: module list unlinking) but forgot /sys/module
         */
        if (m->in_sys_module && !m->in_proc_modules) {
            printf(RED "  [DISCREPANCY]" RESET " Module '%s':\n", m->name);
            printf("    Present in /sys/module: YES\n");
            printf("    Present in /proc/modules: NO\n");
            printf("    Symbols in /proc/kallsyms: %s\n",
                   m->in_kallsyms ? "YES" : "NO");
            printf("    -> Module may be hiding from /proc/modules!\n\n");
            anomaly = 1;
        }

        /*
         * Case 2: In /proc/modules but NOT in /sys/module
         * This is unusual - could indicate a rootkit that cleaned
         * sysfs but not /proc/modules, or a timing issue.
         */
        if (m->in_proc_modules && !m->in_sys_module) {
            printf(YELLOW "  [UNUSUAL]" RESET " Module '%s':\n", m->name);
            printf("    Present in /proc/modules: YES\n");
            printf("    Present in /sys/module: NO\n");
            printf("    Symbols in /proc/kallsyms: %s\n",
                   m->in_kallsyms ? "YES" : "NO");
            printf("    -> Unusual: module in /proc but not /sys\n\n");
            anomaly = 1;
        }

        /*
         * Case 3: Has symbols in kallsyms but not in either list
         * This could indicate a module that hid from both lists
         * but left symbols in the symbol table.
         */
        if (m->in_kallsyms && !m->in_proc_modules && !m->in_sys_module) {
            printf(RED "  [SUSPICIOUS]" RESET " Module '%s':\n", m->name);
            printf("    Present in /proc/modules: NO\n");
            printf("    Present in /sys/module: NO\n");
            printf("    Symbols in /proc/kallsyms: YES\n");
            printf("    -> Symbols exist for invisible module!\n\n");
            anomaly = 1;
        }

        if (anomaly)
            discrepancies++;
    }

    if (discrepancies == 0) {
        printf(GREEN "  No discrepancies found. All sources are consistent.\n" RESET);
    }

    /* Print summary table */
    printf("\n  Module count by source:\n");
    int proc_count = 0, sys_count = 0, ksym_count = 0;
    for (int i = 0; i < module_count; i++) {
        if (modules[i].in_proc_modules) proc_count++;
        if (modules[i].in_sys_module) sys_count++;
        if (modules[i].in_kallsyms) ksym_count++;
    }

    printf("  /proc/modules:   %d modules\n", proc_count);
    printf("  /sys/module:     %d modules (loadable only)\n", sys_count);
    printf("  /proc/kallsyms:  %d modules (with symbols)\n", ksym_count);
    printf("  Total unique:    %d modules\n", module_count);
}

/*
 * Check kernel taint flags
 */
static void check_taint_flags(void)
{
    FILE *fp;
    unsigned long taint = 0;

    printf("\n" CYAN "  [Extra Check]" RESET " Kernel Taint Flags:\n");

    fp = fopen("/proc/sys/kernel/tainted", "r");
    if (fp == NULL) {
        printf("  Cannot read /proc/sys/kernel/tainted\n");
        return;
    }

    if (fscanf(fp, "%lu", &taint) != 1)
        taint = 0;
    fclose(fp);

    printf("  Raw taint value: %lu\n", taint);

    if (taint == 0) {
        printf(GREEN "  Kernel is not tainted.\n" RESET);
        return;
    }

    /* Decode relevant taint bits */
    if (taint & (1 << 0))
        printf(YELLOW "  Bit 0: Proprietary module loaded\n" RESET);
    if (taint & (1 << 12))
        printf(RED "  Bit 12: Unsigned module loaded!\n" RESET);
    if (taint & (1 << 13))
        printf(RED "  Bit 13: Module with bad signature loaded!\n" RESET);
    if (taint & (1 << 15))
        printf(RED "  Bit 15: Livepatch applied\n" RESET);
    if (taint & (1 << 16))
        printf(YELLOW "  Bit 16: Out-of-tree module loaded\n" RESET);

    printf("\n");
}

/*
 * Check module signing configuration
 */
static void check_module_signing(void)
{
    printf(CYAN "  [Extra Check]" RESET " Module Signing Status:\n");

    /* Check if modules_disabled is set */
    FILE *fp = fopen("/proc/sys/kernel/modules_disabled", "r");
    if (fp != NULL) {
        int disabled = 0;
        if (fscanf(fp, "%d", &disabled) == 1) {
            if (disabled)
                printf(GREEN "  Module loading is DISABLED (modules_disabled=1)\n" RESET);
            else
                printf(YELLOW "  Module loading is ENABLED (modules_disabled=0)\n" RESET);
        }
        fclose(fp);
    }

    /* Check lockdown status */
    fp = fopen("/sys/kernel/security/lockdown", "r");
    if (fp != NULL) {
        char line[256];
        if (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\n")] = '\0';
            printf("  Kernel lockdown: %s\n", line);
        }
        fclose(fp);
    } else {
        printf("  Kernel lockdown: not available / not enabled\n");
    }

    printf("\n");
}

static void print_summary(void)
{
    printf(CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Discrepancies found: %d\n", discrepancies);
    printf("\n");

    if (discrepancies > 0) {
        printf(RED "  RESULT: Module discrepancies detected!\n" RESET);
        printf("  This may indicate a hidden kernel module.\n");
        printf("  Recommended actions:\n");
        printf("  1. Acquire memory image for forensic analysis\n");
        printf("  2. Use Volatility linux_hidden_modules\n");
        printf("  3. Check kernel taint flags\n");
        printf("  4. Investigate suspicious module names\n");
        printf("  5. Consider booting from trusted media for analysis\n");
    } else {
        printf(GREEN "  RESULT: All module sources are consistent.\n" RESET);
        printf("  Note: A sophisticated rootkit that cleans all three\n");
        printf("  sources will not be detected by this method.\n");
        printf("  For deeper analysis, use memory forensics.\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Some information sources may be restricted.\n");
        printf("  Run as root for complete analysis.\n\n" RESET);
    }

    scan_proc_modules();
    scan_sys_module();
    scan_kallsyms();

    cross_reference_analysis();
    check_taint_flags();
    check_module_signing();
    print_summary();

    return (discrepancies > 0) ? 1 : 0;
}

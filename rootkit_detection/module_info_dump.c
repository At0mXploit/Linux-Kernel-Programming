/*
 * module_info_dump.c - Dump detailed info about loaded kernel modules
 *
 *
 * Gathers module information from multiple sources:
 *   1. /proc/modules - Module list with sizes, refcounts, dependencies
 *   2. /sys/module/<name>/ - Detailed per-module sysfs attributes
 *   3. Module parameters and their values
 *   4. Module section addresses (for address validation)
 *
 * Compile: gcc -o module_info_dump module_info_dump.c -static
 * Usage:   sudo ./module_info_dump [module_name]
 *          Without arguments: dumps all modules
 *          With module_name: detailed info for that module
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

#define MAX_PATH 512
#define MAX_LINE 1024
#define MAX_MODULES 2048

struct module_info {
    char name[256];
    unsigned long size;
    int refcount;
    char dependencies[512];
    char state[32];
    unsigned long address;
    int is_signed;
    char version[128];
    char srcversion[128];
    char initstate[32];
    int tainted;
};

static struct module_info mods[MAX_MODULES];
static int mod_count = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Kernel Module Information Dump\n");
    printf("  Comprehensive Module Analyzer\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Read a single-line sysfs attribute
 */
static int read_sysfs_attr(const char *path, char *buf, size_t buflen)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);

    if (n <= 0) return -1;

    buf[n] = '\0';
    /* Remove trailing newline */
    buf[strcspn(buf, "\n")] = '\0';

    return 0;
}

/*
 * Parse /proc/modules for basic module information
 */
static int parse_proc_modules(void)
{
    FILE *fp;
    char line[MAX_LINE];

    fp = fopen("/proc/modules", "r");
    if (fp == NULL) {
        perror("Cannot open /proc/modules");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL && mod_count < MAX_MODULES) {
        struct module_info *m = &mods[mod_count];
        memset(m, 0, sizeof(*m));

        int fields = sscanf(line, "%255s %lu %d %511s %31s 0x%lx",
                            m->name, &m->size, &m->refcount,
                            m->dependencies, m->state, &m->address);

        if (fields >= 2) {
            mod_count++;
        }
    }

    fclose(fp);
    return mod_count;
}

/*
 * Enrich module info from /sys/module/
 */
static void enrich_from_sysfs(struct module_info *m)
{
    char path[MAX_PATH];
    char buf[256];

    /* Read version */
    snprintf(path, sizeof(path), "/sys/module/%s/version", m->name);
    if (read_sysfs_attr(path, m->version, sizeof(m->version)) != 0)
        strcpy(m->version, "(none)");

    /* Read srcversion */
    snprintf(path, sizeof(path), "/sys/module/%s/srcversion", m->name);
    if (read_sysfs_attr(path, m->srcversion, sizeof(m->srcversion)) != 0)
        strcpy(m->srcversion, "(none)");

    /* Read initstate */
    snprintf(path, sizeof(path), "/sys/module/%s/initstate", m->name);
    if (read_sysfs_attr(path, m->initstate, sizeof(m->initstate)) != 0)
        strcpy(m->initstate, "unknown");

    /* Check taint */
    snprintf(path, sizeof(path), "/sys/module/%s/taint", m->name);
    if (read_sysfs_attr(path, buf, sizeof(buf)) == 0) {
        m->tainted = (strlen(buf) > 0) ? 1 : 0;
    }
}

/*
 * List module parameters
 */
static void list_module_params(const char *modname)
{
    char path[MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    int param_count = 0;

    snprintf(path, sizeof(path), "/sys/module/%s/parameters", modname);
    dir = opendir(path);
    if (dir == NULL) return;

    printf("    Parameters:\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char param_path[MAX_PATH];
        char value[256];

        snprintf(param_path, sizeof(param_path), "%s/%s", path, entry->d_name);

        if (read_sysfs_attr(param_path, value, sizeof(value)) == 0) {
            printf("      %-30s = %s\n", entry->d_name, value);
            param_count++;
        } else {
            printf("      %-30s = (unreadable)\n", entry->d_name);
            param_count++;
        }
    }

    closedir(dir);

    if (param_count == 0)
        printf("      (none)\n");
}

/*
 * List module sections (addresses for validation)
 */
static void list_module_sections(const char *modname)
{
    char path[MAX_PATH];
    DIR *dir;
    struct dirent *entry;

    snprintf(path, sizeof(path), "/sys/module/%s/sections", modname);
    dir = opendir(path);
    if (dir == NULL) return;

    printf("    Section addresses:\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            /* Section names often start with '.' */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
        }

        char section_path[MAX_PATH];
        char value[64];

        snprintf(section_path, sizeof(section_path), "%s/%s", path, entry->d_name);

        if (read_sysfs_attr(section_path, value, sizeof(value)) == 0) {
            printf("      %-30s %s\n", entry->d_name, value);
        }
    }

    closedir(dir);
}

/*
 * Print detailed info for a single module
 */
static void print_module_detail(struct module_info *m)
{
    printf(BOLD "  Module: %s\n" RESET, m->name);
    printf("    Size:          %lu bytes (%lu KB)\n", m->size, m->size / 1024);
    printf("    Reference cnt: %d\n", m->refcount);
    printf("    Dependencies:  %s\n",
           strlen(m->dependencies) > 1 ? m->dependencies : "(none)");
    printf("    State:         %s\n", m->state);
    printf("    Init state:    %s\n", m->initstate);

    if (m->address != 0)
        printf("    Load address:  0x%016lx\n", m->address);
    else
        printf("    Load address:  (not available - run as root)\n");

    printf("    Version:       %s\n", m->version);
    printf("    Source ver:    %s\n", m->srcversion);

    if (m->tainted) {
        printf(YELLOW "    Tainted:       YES\n" RESET);
    } else {
        printf(GREEN "    Tainted:       No\n" RESET);
    }

    list_module_params(m->name);
    list_module_sections(m->name);

    printf("\n");
}

/*
 * Print summary table of all modules
 */
static void print_module_table(void)
{
    printf(CYAN "  %-24s %10s %4s %-12s %-8s %s\n" RESET,
           "Module", "Size(KB)", "Ref", "State", "Taint", "Address");
    printf("  %-24s %10s %4s %-12s %-8s %s\n",
           "------------------------", "----------", "----",
           "------------", "--------", "----------------");

    for (int i = 0; i < mod_count; i++) {
        struct module_info *m = &mods[i];

        const char *color = "";
        const char *endcolor = "";

        if (m->tainted) {
            color = YELLOW;
            endcolor = RESET;
        }

        printf("  %s%-24s %10lu %4d %-12s %-8s",
               color, m->name, m->size / 1024, m->refcount,
               m->state, m->tainted ? "YES" : "-");

        if (m->address != 0)
            printf(" 0x%016lx", m->address);

        printf("%s\n", endcolor);
    }

    printf("\n  Total modules: %d\n\n", mod_count);
}

/*
 * Security analysis of loaded modules
 */
static void security_analysis(void)
{
    int tainted_count = 0;
    int unknown_state = 0;

    printf(CYAN "  [Security Analysis]\n" RESET);

    for (int i = 0; i < mod_count; i++) {
        if (mods[i].tainted) tainted_count++;
        if (strcmp(mods[i].initstate, "unknown") == 0) unknown_state++;
    }

    /* Check kernel taint */
    char taint_buf[32];
    if (read_sysfs_attr("/proc/sys/kernel/tainted", taint_buf, sizeof(taint_buf)) == 0) {
        unsigned long taint = strtoul(taint_buf, NULL, 10);
        printf("  Kernel taint value: %lu\n", taint);

        if (taint & (1 << 0))  printf(YELLOW "    - Proprietary module loaded\n" RESET);
        if (taint & (1 << 12)) printf(RED    "    - Unsigned module loaded\n" RESET);
        if (taint & (1 << 13)) printf(RED    "    - Module with bad signature\n" RESET);
        if (taint & (1 << 16)) printf(YELLOW "    - Out-of-tree module loaded\n" RESET);
        if (taint == 0)        printf(GREEN  "    - Clean (not tainted)\n" RESET);
    }

    printf("\n  Tainted modules: %d\n", tainted_count);
    printf("  Modules with unknown state: %d\n", unknown_state);

    /* Check modules_disabled */
    char disabled_buf[8];
    if (read_sysfs_attr("/proc/sys/kernel/modules_disabled", disabled_buf, sizeof(disabled_buf)) == 0) {
        if (atoi(disabled_buf) == 1) {
            printf(GREEN "  Module loading: DISABLED (good)\n" RESET);
        } else {
            printf(YELLOW "  Module loading: ENABLED\n" RESET);
        }
    }

    /* Check lockdown */
    char lockdown_buf[64];
    if (read_sysfs_attr("/sys/kernel/security/lockdown", lockdown_buf, sizeof(lockdown_buf)) == 0) {
        printf("  Kernel lockdown: %s\n", lockdown_buf);
    } else {
        printf("  Kernel lockdown: not available\n");
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root. Some info may be limited.\n\n" RESET);
    }

    /* Parse /proc/modules */
    printf(CYAN "  [Phase 1]" RESET " Parsing /proc/modules...\n");
    int count = parse_proc_modules();
    printf("  Found %d loaded modules.\n\n", count);

    /* Enrich from sysfs */
    printf(CYAN "  [Phase 2]" RESET " Enriching from /sys/module/...\n\n");
    for (int i = 0; i < mod_count; i++) {
        enrich_from_sysfs(&mods[i]);
    }

    if (argc > 1 && argv[1][0] != '-') {
        /* Specific module requested */
        int found = 0;
        for (int i = 0; i < mod_count; i++) {
            if (strcmp(mods[i].name, argv[1]) == 0) {
                print_module_detail(&mods[i]);
                found = 1;
                break;
            }
        }
        if (!found) {
            printf(YELLOW "  Module '%s' not found in /proc/modules.\n" RESET, argv[1]);
            printf("  Checking /sys/module/...\n");

            char path[MAX_PATH];
            snprintf(path, sizeof(path), "/sys/module/%s", argv[1]);
            struct stat st;
            if (stat(path, &st) == 0) {
                printf(RED "  Module '%s' exists in /sys/module but NOT in /proc/modules!\n" RESET,
                       argv[1]);
                printf("  This may indicate a hidden module.\n");
            } else {
                printf("  Module not found in /sys/module either.\n");
            }
        }
    } else {
        /* Dump all modules */
        print_module_table();
        security_analysis();
    }

    return 0;
}

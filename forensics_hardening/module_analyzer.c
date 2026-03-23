/*
 * module_analyzer.c - Detailed Kernel Module Analysis Tool
 *
 *
 * Performs comprehensive analysis of loaded kernel modules:
 *   1. Reads /proc/modules for module list
 *   2. Inspects /sys/module/ for detailed attributes
 *   3. Cross-view comparison for hidden module detection
 *   4. Module signature and taint analysis
 *   5. Dependency graph construction
 *   6. Detects anomalous modules (high refcount, missing info)
 *
 * Build: gcc -O2 -Wall -Wextra -o module_analyzer module_analyzer.c
 * Usage: sudo ./module_analyzer [--json] [--check-hidden] [--show-deps]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_MODULES     512
#define MAX_NAME_LEN    256
#define MAX_LINE_LEN    1024
#define MAX_DEPS        64

/* ── Data structures ───────────────────────────────────────────── */

typedef struct {
    char          name[MAX_NAME_LEN];
    unsigned long size;
    int           refcount;
    char          deps[MAX_DEPS][MAX_NAME_LEN];
    int           dep_count;
    char          state[32];           /* Live, Loading, Unloading */
    unsigned long address;

    /* From /sys/module */
    int           has_sysfs;
    char          initstate[32];
    unsigned long coresize;
    char          srcversion[64];
    char          version[64];
    char          taint[32];
    int           sys_refcnt;

    /* Cross-view flags */
    int           in_proc_modules;
    int           in_sys_module;
    int           in_kallsyms;

    /* Analysis flags */
    int           is_suspicious;
    char          suspicious_reason[MAX_LINE_LEN];
} module_info_t;

static module_info_t modules[MAX_MODULES];
static int module_count = 0;
static int json_output = 0;

/* ── Helper to read sysfs attribute ────────────────────────────── */

static int read_sysfs_attr(const char *module_name, const char *attr,
                           char *buf, size_t bufsz)
{
    char path[512];
    snprintf(path, sizeof(path), "/sys/module/%s/%s", module_name, attr);

    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    buf[0] = '\0';
    if (fgets(buf, bufsz, fp))
        buf[strcspn(buf, "\n")] = '\0';

    fclose(fp);
    return 0;
}

/* ── Find or create module entry ───────────────────────────────── */

static module_info_t *find_or_create_module(const char *name)
{
    for (int i = 0; i < module_count; i++) {
        if (strcmp(modules[i].name, name) == 0)
            return &modules[i];
    }

    if (module_count >= MAX_MODULES)
        return NULL;

    module_info_t *m = &modules[module_count++];
    memset(m, 0, sizeof(*m));
    strncpy(m->name, name, MAX_NAME_LEN - 1);
    return m;
}

/* ── Parse /proc/modules ──────────────────────────────────────── */

static void parse_proc_modules(void)
{
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open /proc/modules\n");
        return;
    }

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char name[MAX_NAME_LEN];
        unsigned long size;
        int refcount;
        char deps_str[MAX_LINE_LEN];
        char state[32];
        unsigned long address;

        int fields = sscanf(line, "%255s %lu %d %1023s %31s 0x%lx",
                            name, &size, &refcount, deps_str, state, &address);
        if (fields < 5)
            continue;

        module_info_t *m = find_or_create_module(name);
        if (!m) continue;

        m->size = size;
        m->refcount = refcount;
        strncpy(m->state, state, sizeof(m->state) - 1);
        m->address = (fields >= 6) ? address : 0;
        m->in_proc_modules = 1;

        /* Parse dependencies */
        if (strcmp(deps_str, "-") != 0) {
            char *tok = strtok(deps_str, ",");
            while (tok && m->dep_count < MAX_DEPS) {
                if (strlen(tok) > 0 && strcmp(tok, "-") != 0) {
                    strncpy(m->deps[m->dep_count], tok, MAX_NAME_LEN - 1);
                    m->dep_count++;
                }
                tok = strtok(NULL, ",");
            }
        }
    }
    fclose(fp);
}

/* ── Parse /sys/module ─────────────────────────────────────────── */

static void parse_sys_module(void)
{
    DIR *dir = opendir("/sys/module");
    if (!dir) {
        fprintf(stderr, "ERROR: Cannot open /sys/module\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        /* Check if it is a loadable module (has initstate) */
        char buf[256];
        if (read_sysfs_attr(entry->d_name, "initstate", buf, sizeof(buf)) != 0)
            continue; /* Built-in, skip */

        if (strcmp(buf, "live") != 0 && strcmp(buf, "coming") != 0
            && strcmp(buf, "going") != 0)
            continue;

        module_info_t *m = find_or_create_module(entry->d_name);
        if (!m) continue;

        m->has_sysfs = 1;
        m->in_sys_module = 1;
        strncpy(m->initstate, buf, sizeof(m->initstate) - 1);

        /* Read coresize */
        if (read_sysfs_attr(entry->d_name, "coresize", buf, sizeof(buf)) == 0)
            m->coresize = strtoul(buf, NULL, 10);

        /* Read srcversion */
        read_sysfs_attr(entry->d_name, "srcversion", m->srcversion,
                        sizeof(m->srcversion));

        /* Read version */
        read_sysfs_attr(entry->d_name, "version", m->version,
                        sizeof(m->version));

        /* Read taint */
        read_sysfs_attr(entry->d_name, "taint", m->taint, sizeof(m->taint));

        /* Read refcnt */
        if (read_sysfs_attr(entry->d_name, "refcnt", buf, sizeof(buf)) == 0)
            m->sys_refcnt = atoi(buf);
    }
    closedir(dir);
}

/* ── Check kallsyms for module references ──────────────────────── */

static void check_kallsyms(void)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp)
        return;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char *bracket = strchr(line, '[');
        if (!bracket)
            continue;

        char *end = strchr(bracket, ']');
        if (!end)
            continue;

        *end = '\0';
        char *mod_name = bracket + 1;

        module_info_t *m = find_or_create_module(mod_name);
        if (m)
            m->in_kallsyms = 1;
    }
    fclose(fp);
}

/* ── Analysis: detect anomalies ────────────────────────────────── */

static void analyze_modules(void)
{
    for (int i = 0; i < module_count; i++) {
        module_info_t *m = &modules[i];
        m->is_suspicious = 0;
        m->suspicious_reason[0] = '\0';

        /* Check 1: Hidden from /proc/modules but present in /sys/module */
        if (m->in_sys_module && !m->in_proc_modules) {
            m->is_suspicious = 1;
            strncat(m->suspicious_reason,
                    "In /sys/module but NOT in /proc/modules; ",
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
        }

        /* Check 2: In /proc/modules but not in /sys/module (kobject removed) */
        if (m->in_proc_modules && !m->in_sys_module) {
            m->is_suspicious = 1;
            strncat(m->suspicious_reason,
                    "In /proc/modules but NOT in /sys/module (kobject removed); ",
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
        }

        /* Check 3: Only in kallsyms */
        if (m->in_kallsyms && !m->in_proc_modules && !m->in_sys_module) {
            m->is_suspicious = 1;
            strncat(m->suspicious_reason,
                    "Symbols in kallsyms but not in module lists; ",
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
        }

        /* Check 4: Tainted module */
        if (m->taint[0] != '\0') {
            char tbuf[128];
            snprintf(tbuf, sizeof(tbuf), "Taint flags: %s; ", m->taint);
            strncat(m->suspicious_reason, tbuf,
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
            /* O=out-of-tree, E=unsigned, P=proprietary */
            if (strchr(m->taint, 'E'))
                m->is_suspicious = 1; /* Unsigned module */
        }

        /* Check 5: High refcount with no dependents */
        if (m->refcount > 10 && m->dep_count == 0) {
            m->is_suspicious = 1;
            strncat(m->suspicious_reason,
                    "High refcount with no dependents; ",
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
        }

        /* Check 6: Refcount mismatch between /proc and /sys */
        if (m->in_proc_modules && m->in_sys_module &&
            m->refcount != m->sys_refcnt) {
            char rbuf[128];
            snprintf(rbuf, sizeof(rbuf),
                     "Refcount mismatch (/proc=%d, /sys=%d); ",
                     m->refcount, m->sys_refcnt);
            strncat(m->suspicious_reason, rbuf,
                    sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
        }

        /* Check 7: Size mismatch */
        if (m->size > 0 && m->coresize > 0 && m->size != m->coresize) {
            /* Sizes may differ slightly, flag only large discrepancies */
            long diff = (long)m->size - (long)m->coresize;
            if (diff < 0) diff = -diff;
            if (diff > (long)(m->size / 2)) {
                m->is_suspicious = 1;
                strncat(m->suspicious_reason,
                        "Large size discrepancy between /proc and /sys; ",
                        sizeof(m->suspicious_reason) - strlen(m->suspicious_reason) - 1);
            }
        }
    }
}

/* ── Output: text format ───────────────────────────────────────── */

static void print_text_report(int show_deps)
{
    printf("\n=== Kernel Module Analysis Report ===\n");
    printf("Total modules found: %d\n", module_count);

    time_t now = time(NULL);
    printf("Report generated: %s\n", ctime(&now));

    /* Summary of views */
    int in_proc = 0, in_sys = 0, in_ksym = 0, suspicious_count = 0;
    for (int i = 0; i < module_count; i++) {
        if (modules[i].in_proc_modules) in_proc++;
        if (modules[i].in_sys_module) in_sys++;
        if (modules[i].in_kallsyms) in_ksym++;
        if (modules[i].is_suspicious) suspicious_count++;
    }

    printf("In /proc/modules:  %d\n", in_proc);
    printf("In /sys/module:    %d\n", in_sys);
    printf("In kallsyms:       %d\n", in_ksym);
    printf("Suspicious:        %d\n\n", suspicious_count);

    /* Print each module */
    printf("%-24s %10s %5s %-8s %-6s %-12s %s\n",
           "MODULE", "SIZE", "REF", "STATE", "TAINT", "SRCVER", "VIEWS");
    printf("%-24s %10s %5s %-8s %-6s %-12s %s\n",
           "------------------------", "----------", "-----",
           "--------", "------", "------------", "------");

    for (int i = 0; i < module_count; i++) {
        module_info_t *m = &modules[i];

        char views[16] = "";
        if (m->in_proc_modules) strcat(views, "P");
        if (m->in_sys_module)   strcat(views, "S");
        if (m->in_kallsyms)     strcat(views, "K");

        printf("%-24s %10lu %5d %-8s %-6s %-12s %s",
               m->name,
               m->size > 0 ? m->size : m->coresize,
               m->refcount > 0 ? m->refcount : m->sys_refcnt,
               m->state[0] ? m->state : m->initstate,
               m->taint[0] ? m->taint : "-",
               m->srcversion[0] ? m->srcversion : "-",
               views);

        if (m->is_suspicious)
            printf(" <<< SUSPICIOUS");

        printf("\n");

        if (show_deps && m->dep_count > 0) {
            printf("  Dependencies: ");
            for (int j = 0; j < m->dep_count; j++) {
                printf("%s%s", m->deps[j],
                       j < m->dep_count - 1 ? ", " : "");
            }
            printf("\n");
        }
    }

    /* Print suspicious modules detail */
    if (suspicious_count > 0) {
        printf("\n=== SUSPICIOUS MODULES ===\n");
        for (int i = 0; i < module_count; i++) {
            if (!modules[i].is_suspicious)
                continue;

            printf("\n  Module: %s\n", modules[i].name);
            printf("  Address: 0x%lx\n", modules[i].address);
            printf("  Size: %lu bytes\n",
                   modules[i].size > 0 ? modules[i].size : modules[i].coresize);
            printf("  Reason: %s\n", modules[i].suspicious_reason);
            printf("  Views: /proc=%s /sys=%s kallsyms=%s\n",
                   modules[i].in_proc_modules ? "YES" : "NO",
                   modules[i].in_sys_module ? "YES" : "NO",
                   modules[i].in_kallsyms ? "YES" : "NO");
        }
    }
}

/* ── Output: JSON format ───────────────────────────────────────── */

static void print_json_report(void)
{
    printf("{\n");
    printf("  \"timestamp\": %ld,\n", (long)time(NULL));
    printf("  \"module_count\": %d,\n", module_count);
    printf("  \"modules\": [\n");

    for (int i = 0; i < module_count; i++) {
        module_info_t *m = &modules[i];
        printf("    {\n");
        printf("      \"name\": \"%s\",\n", m->name);
        printf("      \"size\": %lu,\n", m->size > 0 ? m->size : m->coresize);
        printf("      \"refcount\": %d,\n",
               m->refcount > 0 ? m->refcount : m->sys_refcnt);
        printf("      \"state\": \"%s\",\n",
               m->state[0] ? m->state : m->initstate);
        printf("      \"address\": \"0x%lx\",\n", m->address);
        printf("      \"taint\": \"%s\",\n", m->taint);
        printf("      \"srcversion\": \"%s\",\n", m->srcversion);
        printf("      \"version\": \"%s\",\n", m->version);
        printf("      \"in_proc_modules\": %s,\n",
               m->in_proc_modules ? "true" : "false");
        printf("      \"in_sys_module\": %s,\n",
               m->in_sys_module ? "true" : "false");
        printf("      \"in_kallsyms\": %s,\n",
               m->in_kallsyms ? "true" : "false");
        printf("      \"suspicious\": %s,\n",
               m->is_suspicious ? "true" : "false");
        if (m->is_suspicious)
            printf("      \"suspicious_reason\": \"%s\",\n",
                   m->suspicious_reason);

        printf("      \"dependencies\": [");
        for (int j = 0; j < m->dep_count; j++) {
            printf("\"%s\"%s", m->deps[j],
                   j < m->dep_count - 1 ? ", " : "");
        }
        printf("]\n");

        printf("    }%s\n", i < module_count - 1 ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
}

/* ── Hidden module check with report ───────────────────────────── */

static void check_hidden_modules(void)
{
    printf("\n=== Hidden Module Detection ===\n");

    int hidden = 0;
    for (int i = 0; i < module_count; i++) {
        module_info_t *m = &modules[i];

        /* Strictly hidden: has symbols but not in either list */
        if (m->in_kallsyms && !m->in_proc_modules && !m->in_sys_module) {
            printf("  HIDDEN: %s (only in kallsyms)\n", m->name);
            hidden++;
        }

        /* Partially hidden: in one list but not the other */
        if (m->in_sys_module && !m->in_proc_modules) {
            printf("  PARTIAL: %s (in /sys/module but not /proc/modules)\n",
                   m->name);
            hidden++;
        }

        if (m->in_proc_modules && !m->in_sys_module) {
            printf("  PARTIAL: %s (in /proc/modules but not /sys/module)\n",
                   m->name);
            hidden++;
        }
    }

    if (hidden == 0)
        printf("  No hidden modules detected.\n");
    else
        printf("  Total hidden/partially hidden: %d\n", hidden);
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int show_deps = 0;
    int check_hidden = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0)
            json_output = 1;
        else if (strcmp(argv[i], "--show-deps") == 0 || strcmp(argv[i], "-d") == 0)
            show_deps = 1;
        else if (strcmp(argv[i], "--check-hidden") == 0 || strcmp(argv[i], "-c") == 0)
            check_hidden = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --json, -j          Output in JSON format\n");
            printf("  --show-deps, -d     Show module dependencies\n");
            printf("  --check-hidden, -c  Perform hidden module detection\n");
            printf("  --help, -h          Show this help\n");
            printf("\nRun as root for complete information.\n");
            return 0;
        }
    }

    if (!json_output) {
        printf("============================================================\n");
        printf("  Kernel Module Analyzer v1.0\n");
        printf("============================================================\n");
    }

    /* Gather data from all sources */
    parse_proc_modules();
    parse_sys_module();
    check_kallsyms();

    /* Analyze for anomalies */
    analyze_modules();

    /* Output */
    if (json_output) {
        print_json_report();
    } else {
        print_text_report(show_deps);
        if (check_hidden)
            check_hidden_modules();
    }

    /* Exit code: 0 if clean, 1 if suspicious modules found */
    int suspicious = 0;
    for (int i = 0; i < module_count; i++) {
        if (modules[i].is_suspicious)
            suspicious++;
    }

    if (!json_output) {
        printf("\n============================================================\n");
        if (suspicious == 0)
            printf("  RESULT: All modules appear normal.\n");
        else
            printf("  RESULT: %d suspicious module(s) detected.\n", suspicious);
        printf("============================================================\n");
    }

    return (suspicious > 0) ? 1 : 0;
}

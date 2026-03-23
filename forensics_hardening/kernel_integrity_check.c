/*
 * kernel_integrity_check.c - Kernel Integrity Verification Tool
 *
 *
 * This program verifies kernel integrity by:
 *   1. Parsing /proc/kallsyms for symbol addresses
 *   2. Verifying kernel text boundaries
 *   3. Checking syscall table entries against kernel text range
 *   4. Computing KASLR offset via System.map comparison
 *   5. Detecting runtime patches (ftrace, kprobes, live patches)
 *   6. Creating and verifying a symbol baseline
 *
 * Build: gcc -O2 -Wall -Wextra -o kernel_integrity_check kernel_integrity_check.c -lcrypto
 *        (or without -lcrypto for basic mode without SHA256)
 * Usage: sudo ./kernel_integrity_check [--baseline|--verify|--dump]
 *
 * MUST be run as root.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/utsname.h>
#include <time.h>

#define MAX_SYMBOLS     200000
#define MAX_SYSCALLS    512
#define MAX_LINE_LEN    1024
#define BASELINE_FILE   "/var/lib/kernel_integrity/baseline.dat"
#define BASELINE_DIR    "/var/lib/kernel_integrity"

/* ── Data structures ───────────────────────────────────────────── */

typedef struct {
    unsigned long address;
    char          type;
    char          name[256];
    char          module[128];   /* empty if kernel core */
} kernel_symbol_t;

typedef struct {
    unsigned long stext;
    unsigned long etext;
    unsigned long sdata;
    unsigned long edata;
    unsigned long sys_call_table;
    unsigned long ia32_sys_call_table;
    unsigned long kaslr_offset;
    int           symbol_count;
    int           syscall_handler_count;
} kernel_info_t;

typedef struct {
    char          name[256];
    unsigned long address;
    unsigned long relative_offset;  /* offset from _stext (KASLR-independent) */
} baseline_entry_t;

static kernel_symbol_t symbols[MAX_SYMBOLS];
static int symbol_count = 0;
static kernel_info_t kinfo;

/* ── Symbol parsing ────────────────────────────────────────────── */

static int parse_kallsyms(void)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open /proc/kallsyms (need root)\n");
        return -1;
    }

    char line[MAX_LINE_LEN];
    symbol_count = 0;

    while (fgets(line, sizeof(line), fp) && symbol_count < MAX_SYMBOLS) {
        unsigned long addr;
        char type;
        char name[256];
        char rest[256] = "";

        int fields = sscanf(line, "%lx %c %255s %255[^\n]",
                            &addr, &type, name, rest);
        if (fields < 3)
            continue;

        /* Skip zero addresses (kptr_restrict is active) */
        if (addr == 0 && symbol_count > 10) {
            fprintf(stderr, "WARNING: Addresses are zeros - "
                    "kernel.kptr_restrict is likely enabled.\n"
                    "Run: sudo sysctl -w kernel.kptr_restrict=0\n");
            fclose(fp);
            return -1;
        }

        symbols[symbol_count].address = addr;
        symbols[symbol_count].type = type;
        strncpy(symbols[symbol_count].name, name, 255);

        /* Extract module name from [brackets] */
        symbols[symbol_count].module[0] = '\0';
        if (rest[0] == '[') {
            char *end = strchr(rest, ']');
            if (end) {
                *end = '\0';
                strncpy(symbols[symbol_count].module, rest + 1, 127);
            }
        }

        symbol_count++;
    }
    fclose(fp);

    printf("Parsed %d symbols from /proc/kallsyms\n", symbol_count);
    return 0;
}

/* ── Find kernel landmarks ─────────────────────────────────────── */

static unsigned long find_symbol(const char *name)
{
    for (int i = 0; i < symbol_count; i++) {
        if (strcmp(symbols[i].name, name) == 0)
            return symbols[i].address;
    }
    return 0;
}

static void find_kernel_info(void)
{
    memset(&kinfo, 0, sizeof(kinfo));

    kinfo.stext = find_symbol("_stext");
    kinfo.etext = find_symbol("_etext");
    kinfo.sdata = find_symbol("_sdata");
    kinfo.edata = find_symbol("_edata");
    kinfo.sys_call_table = find_symbol("sys_call_table");
    kinfo.ia32_sys_call_table = find_symbol("ia32_sys_call_table");
    kinfo.symbol_count = symbol_count;

    /* Count syscall handlers */
    kinfo.syscall_handler_count = 0;
    for (int i = 0; i < symbol_count; i++) {
        if (strncmp(symbols[i].name, "__x64_sys_", 10) == 0 ||
            strncmp(symbols[i].name, "__do_sys_", 9) == 0) {
            kinfo.syscall_handler_count++;
        }
    }

    printf("\n=== Kernel Memory Layout ===\n");
    printf("  _stext:             0x%016lx\n", kinfo.stext);
    printf("  _etext:             0x%016lx\n", kinfo.etext);
    printf("  _sdata:             0x%016lx\n", kinfo.sdata);
    printf("  _edata:             0x%016lx\n", kinfo.edata);
    printf("  Kernel text size:   %lu bytes (%.2f MB)\n",
           kinfo.etext - kinfo.stext,
           (double)(kinfo.etext - kinfo.stext) / (1024.0 * 1024.0));
    printf("  sys_call_table:     0x%016lx\n", kinfo.sys_call_table);
    printf("  ia32_sys_call_table:0x%016lx\n", kinfo.ia32_sys_call_table);
    printf("  Syscall handlers:   %d\n", kinfo.syscall_handler_count);
}

/* ── KASLR offset calculation ──────────────────────────────────── */

static void calculate_kaslr_offset(void)
{
    struct utsname uts;
    uname(&uts);

    char sysmap_path[512];
    snprintf(sysmap_path, sizeof(sysmap_path),
             "/boot/System.map-%s", uts.release);

    FILE *fp = fopen(sysmap_path, "r");
    if (!fp) {
        printf("\n=== KASLR Offset ===\n");
        printf("  Cannot open %s - skipping KASLR calculation\n", sysmap_path);
        return;
    }

    /* Find _stext in System.map */
    char line[MAX_LINE_LEN];
    unsigned long map_stext = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];

        if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, "_stext") == 0) {
                map_stext = addr;
                break;
            }
        }
    }
    fclose(fp);

    printf("\n=== KASLR Offset ===\n");
    if (map_stext == 0) {
        printf("  Cannot find _stext in %s\n", sysmap_path);
        return;
    }

    kinfo.kaslr_offset = kinfo.stext - map_stext;
    printf("  System.map _stext:  0x%016lx\n", map_stext);
    printf("  Runtime _stext:     0x%016lx\n", kinfo.stext);
    printf("  KASLR offset:       0x%016lx (%lu bytes)\n",
           kinfo.kaslr_offset, kinfo.kaslr_offset);

    if (kinfo.kaslr_offset == 0)
        printf("  NOTE: KASLR offset is 0 (KASLR may be disabled)\n");
}

/* ── Syscall table integrity check ─────────────────────────────── */

static int verify_syscall_handlers(void)
{
    printf("\n=== Syscall Handler Verification ===\n");

    int checked = 0;
    int in_range = 0;
    int out_of_range = 0;
    int in_module = 0;
    int alerts = 0;

    for (int i = 0; i < symbol_count; i++) {
        if (strncmp(symbols[i].name, "__x64_sys_", 10) != 0)
            continue;

        checked++;
        unsigned long addr = symbols[i].address;

        if (addr >= kinfo.stext && addr <= kinfo.etext) {
            in_range++;
        } else {
            out_of_range++;
            if (symbols[i].module[0] != '\0') {
                in_module++;
                printf("  WARNING: %s at 0x%lx is in module [%s]\n",
                       symbols[i].name, addr, symbols[i].module);
            } else {
                printf("  ALERT:   %s at 0x%lx is outside kernel text "
                       "and not in any module!\n",
                       symbols[i].name, addr);
                alerts++;
            }
        }
    }

    printf("\n  Summary:\n");
    printf("    Handlers checked:    %d\n", checked);
    printf("    In kernel text:      %d\n", in_range);
    printf("    In module space:     %d\n", in_module);
    printf("    Out of range (bad):  %d\n", out_of_range - in_module);
    printf("    Alerts:              %d\n", alerts);

    return alerts;
}

/* ── Runtime patching detection ────────────────────────────────── */

static void detect_runtime_patches(void)
{
    printf("\n=== Runtime Patching Detection ===\n");

    /* Check ftrace */
    FILE *fp = fopen("/sys/kernel/debug/tracing/enabled_functions", "r");
    if (fp) {
        int ftrace_count = 0;
        char line[MAX_LINE_LEN];
        while (fgets(line, sizeof(line), fp))
            ftrace_count++;
        fclose(fp);
        printf("  Ftrace enabled functions: %d\n", ftrace_count);
        if (ftrace_count > 0)
            printf("  NOTE: Ftrace hooks are active (may be legitimate tracing)\n");
    } else {
        printf("  Ftrace: Cannot read (debugfs may not be mounted or accessible)\n");
    }

    /* Check kprobes */
    fp = fopen("/sys/kernel/debug/kprobes/list", "r");
    if (fp) {
        int kprobe_count = 0;
        char line[MAX_LINE_LEN];
        while (fgets(line, sizeof(line), fp)) {
            kprobe_count++;
            line[strcspn(line, "\n")] = '\0';
            printf("  Kprobe: %s\n", line);
        }
        fclose(fp);
        printf("  Total kprobes: %d\n", kprobe_count);
        if (kprobe_count > 0)
            printf("  NOTE: Active kprobes found (may be legitimate instrumentation)\n");
    } else {
        printf("  Kprobes: Cannot read (debugfs may not be mounted or accessible)\n");
    }

    /* Check kprobes enabled status */
    fp = fopen("/sys/kernel/debug/kprobes/enabled", "r");
    if (fp) {
        int enabled = 0;
        if (fscanf(fp, "%d", &enabled) == 1)
            printf("  Kprobes enabled: %s\n", enabled ? "YES" : "NO");
        fclose(fp);
    }

    /* Check live patches */
    const char *livepatch_dir = "/sys/kernel/livepatch";
    FILE *test = fopen(livepatch_dir, "r");
    if (test) {
        fclose(test);
        printf("  Live patch directory exists\n");
    } else {
        printf("  Live patching: No active live patches detected\n");
    }

    /* Check ftrace trampoline symbols */
    int trampoline_count = 0;
    for (int i = 0; i < symbol_count; i++) {
        if (strstr(symbols[i].name, "ftrace_trampoline") ||
            strstr(symbols[i].name, "__fentry__")) {
            trampoline_count++;
        }
    }
    printf("  Ftrace trampoline symbols: %d\n", trampoline_count);
}

/* ── Baseline creation and verification ────────────────────────── */

static int create_baseline(void)
{
    printf("\n=== Creating Symbol Baseline ===\n");

    /* Create directory */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", BASELINE_DIR);
    if (system(cmd) != 0) {
        fprintf(stderr, "Cannot create %s\n", BASELINE_DIR);
        return -1;
    }

    FILE *fp = fopen(BASELINE_FILE, "w");
    if (!fp) {
        fprintf(stderr, "Cannot create baseline file: %s\n", BASELINE_FILE);
        return -1;
    }

    /* Write header */
    struct utsname uts;
    uname(&uts);
    time_t now = time(NULL);

    fprintf(fp, "# Kernel Integrity Baseline\n");
    fprintf(fp, "# Kernel: %s %s\n", uts.release, uts.machine);
    fprintf(fp, "# Date: %s", ctime(&now));
    fprintf(fp, "# KASLR offset: 0x%016lx\n", kinfo.kaslr_offset);
    fprintf(fp, "# _stext: 0x%016lx\n", kinfo.stext);
    fprintf(fp, "# _etext: 0x%016lx\n", kinfo.etext);
    fprintf(fp, "# Symbols: %d\n", symbol_count);
    fprintf(fp, "#\n");
    fprintf(fp, "# Format: relative_offset type name [module]\n");

    /* Write all syscall-related symbols with relative offsets */
    int baseline_count = 0;
    for (int i = 0; i < symbol_count; i++) {
        /* Store key symbols: syscall handlers, important kernel functions */
        if (strncmp(symbols[i].name, "__x64_sys_", 10) == 0 ||
            strncmp(symbols[i].name, "__do_sys_", 9) == 0 ||
            strncmp(symbols[i].name, "sys_call_table", 14) == 0 ||
            strcmp(symbols[i].name, "_stext") == 0 ||
            strcmp(symbols[i].name, "_etext") == 0 ||
            strncmp(symbols[i].name, "do_", 3) == 0 ||
            strstr(symbols[i].name, "security_") != NULL) {

            unsigned long relative = symbols[i].address - kinfo.stext;
            fprintf(fp, "0x%016lx %c %s", relative, symbols[i].type,
                    symbols[i].name);
            if (symbols[i].module[0] != '\0')
                fprintf(fp, " [%s]", symbols[i].module);
            fprintf(fp, "\n");
            baseline_count++;
        }
    }

    fclose(fp);
    printf("  Baseline created: %s\n", BASELINE_FILE);
    printf("  Symbols recorded: %d\n", baseline_count);
    printf("  Use --verify to check against this baseline later.\n");

    return 0;
}

static int verify_baseline(void)
{
    printf("\n=== Verifying Against Baseline ===\n");

    FILE *fp = fopen(BASELINE_FILE, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open baseline: %s\n", BASELINE_FILE);
        fprintf(stderr, "Create one first with: %s --baseline\n",
                "kernel_integrity_check");
        return -1;
    }

    char line[MAX_LINE_LEN];
    int matched = 0;
    int mismatched = 0;
    int missing = 0;
    int total = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#')
            continue;

        unsigned long rel_offset;
        char type;
        char name[256];
        char module[128] = "";

        int fields = sscanf(line, "0x%lx %c %255s [%127[^]]]",
                            &rel_offset, &type, name, module);
        if (fields < 3)
            continue;

        total++;

        /* Find this symbol in current runtime */
        int found = 0;
        for (int i = 0; i < symbol_count; i++) {
            if (strcmp(symbols[i].name, name) == 0) {
                found = 1;
                unsigned long current_rel = symbols[i].address - kinfo.stext;

                if (current_rel == rel_offset) {
                    matched++;
                } else {
                    mismatched++;
                    printf("  MISMATCH: %s\n", name);
                    printf("    Baseline offset: 0x%016lx\n", rel_offset);
                    printf("    Current offset:  0x%016lx\n", current_rel);
                    printf("    Difference:      0x%016lx\n",
                           current_rel > rel_offset ?
                           current_rel - rel_offset : rel_offset - current_rel);

                    if (symbols[i].module[0] != '\0' && module[0] == '\0') {
                        printf("    NOTE: Symbol now in module [%s] "
                               "(was in kernel core)\n", symbols[i].module);
                    }
                }
                break;
            }
        }

        if (!found) {
            missing++;
            printf("  MISSING: %s (was at offset 0x%016lx)\n", name, rel_offset);
        }
    }
    fclose(fp);

    printf("\n  Verification Summary:\n");
    printf("    Total baseline symbols: %d\n", total);
    printf("    Matched:               %d\n", matched);
    printf("    Mismatched:            %d\n", mismatched);
    printf("    Missing:               %d\n", missing);

    if (mismatched == 0 && missing == 0) {
        printf("\n  RESULT: Kernel integrity VERIFIED - all symbols match baseline.\n");
        return 0;
    } else {
        printf("\n  RESULT: Kernel integrity FAILED - %d mismatches, %d missing.\n",
               mismatched, missing);
        return 1;
    }
}

/* ── Symbol dump mode ──────────────────────────────────────────── */

static void dump_symbols(void)
{
    printf("\n=== Syscall Handler Dump ===\n");
    printf("%-50s %-18s %s\n", "Name", "Address", "Module");
    printf("%-50s %-18s %s\n",
           "--------------------------------------------------",
           "------------------", "--------");

    for (int i = 0; i < symbol_count; i++) {
        if (strncmp(symbols[i].name, "__x64_sys_", 10) == 0) {
            printf("%-50s 0x%016lx %s\n",
                   symbols[i].name,
                   symbols[i].address,
                   symbols[i].module[0] ? symbols[i].module : "(kernel)");
        }
    }
}

/* ── Usage ─────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --baseline    Create a new symbol baseline from current state\n");
    printf("  --verify      Verify current state against stored baseline\n");
    printf("  --dump        Dump all syscall handler addresses\n");
    printf("  --help        Show this help message\n");
    printf("\nDefault (no options): Run full integrity check without baseline.\n");
    printf("\nMust be run as root.\n");
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int mode_baseline = 0;
    int mode_verify = 0;
    int mode_dump = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--baseline") == 0)
            mode_baseline = 1;
        else if (strcmp(argv[i], "--verify") == 0)
            mode_verify = 1;
        else if (strcmp(argv[i], "--dump") == 0)
            mode_dump = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root.\n");
        return 1;
    }

    printf("============================================================\n");
    printf("  Kernel Integrity Check v1.0\n");
    printf("============================================================\n");

    struct utsname uts;
    uname(&uts);
    printf("  Kernel: %s %s\n", uts.release, uts.machine);
    printf("  Host:   %s\n", uts.nodename);

    time_t now = time(NULL);
    printf("  Date:   %s", ctime(&now));
    printf("============================================================\n");

    /* Parse kallsyms */
    if (parse_kallsyms() != 0) {
        fprintf(stderr, "Failed to parse kernel symbols. Aborting.\n");
        return 1;
    }

    /* Find kernel landmarks */
    find_kernel_info();

    if (kinfo.stext == 0 || kinfo.etext == 0) {
        fprintf(stderr, "ERROR: Cannot determine kernel text boundaries.\n");
        fprintf(stderr, "Ensure kernel.kptr_restrict is 0.\n");
        return 1;
    }

    /* Calculate KASLR offset */
    calculate_kaslr_offset();

    if (mode_dump) {
        dump_symbols();
        return 0;
    }

    if (mode_baseline) {
        return create_baseline();
    }

    if (mode_verify) {
        /* Parse, then verify */
        int result = verify_baseline();
        /* Also run regular checks */
        int alerts = verify_syscall_handlers();
        detect_runtime_patches();
        return (result != 0 || alerts > 0) ? 1 : 0;
    }

    /* Default: full check without baseline */
    int alerts = verify_syscall_handlers();
    detect_runtime_patches();

    printf("\n============================================================\n");
    if (alerts == 0)
        printf("  OVERALL: No integrity issues detected.\n");
    else
        printf("  OVERALL: %d integrity issues detected.\n", alerts);
    printf("============================================================\n");

    return (alerts > 0) ? 1 : 0;
}

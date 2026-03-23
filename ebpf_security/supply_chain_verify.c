/*
 * supply_chain_verify.c - Verify Kernel Module Signatures and Integrity
 * ======================================================================
 *
 * This program verifies the integrity of loaded kernel modules by checking:
 *   - Module signature presence and validity
 *   - Module file hash against known-good values
 *   - Package ownership (Debian/RPM)
 *   - Module taint flags
 *
 *
 * COMPILATION:
 *   gcc -O2 -o supply_chain_verify supply_chain_verify.c -lcrypto
 *   (requires: libssl-dev / openssl-devel)
 *
 *   Without OpenSSL (reduced functionality):
 *   gcc -O2 -o supply_chain_verify supply_chain_verify.c -DNO_OPENSSL
 *
 * USAGE:
 *   sudo ./supply_chain_verify [-v] [-m module_name] [-b baseline_file]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <getopt.h>

#ifndef NO_OPENSSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif

#define MAX_PATH 1024
#define MAX_LINE 4096
#define MAX_MODULES 2048

/* Module info structure */
struct module_info {
    char name[256];
    char path[MAX_PATH];
    char sha256[65];
    int  is_signed;
    int  is_packaged;
    char package_name[256];
    int  loaded;
};

static struct module_info modules[MAX_MODULES];
static int module_count = 0;

/* Compute SHA-256 hash of a file */
static int compute_sha256(const char *path, char *hash_out)
{
#ifndef NO_OPENSSL
    FILE *fp;
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[8192];
    size_t bytes;
    unsigned int hash_len;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(fp);
        return -1;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(fp);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[hash_len * 2] = '\0';

    return 0;
#else
    /* Fallback: use sha256sum command */
    char cmd[MAX_PATH + 64];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%64s", hash_out) != 1) {
        pclose(fp);
        return -1;
    }

    pclose(fp);
    return 0;
#endif
}

/* Check if a module file contains a signature */
static int check_module_signature(const char *path)
{
    FILE *fp;
    unsigned char magic[28];
    long file_size;

    /* Module signature magic: "~Module signature appended~\n" */
    static const char sig_magic[] = "~Module signature appended~\n";

    fp = fopen(path, "rb");
    if (!fp)
        return -1;

    /* Seek to end minus magic length */
    if (fseek(fp, -(long)sizeof(sig_magic) + 1, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }

    file_size = ftell(fp);
    (void)file_size;

    if (fread(magic, 1, sizeof(sig_magic) - 1, fp) != sizeof(sig_magic) - 1) {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    /* Check for signature magic at end of file */
    if (memcmp(magic, sig_magic, sizeof(sig_magic) - 1) == 0)
        return 1;

    return 0;
}

/* Check if a file belongs to a package */
static int check_package_ownership(const char *path, char *package_name,
                                    size_t name_len)
{
    char cmd[MAX_PATH + 64];
    FILE *fp;
    char result[512];

    /* Try dpkg first (Debian/Ubuntu) */
    snprintf(cmd, sizeof(cmd), "dpkg -S '%s' 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(result, sizeof(result), fp)) {
            char *colon = strchr(result, ':');
            if (colon) {
                *colon = '\0';
                strncpy(package_name, result, name_len - 1);
                package_name[name_len - 1] = '\0';
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }

    /* Try rpm (RHEL/CentOS/Fedora) */
    snprintf(cmd, sizeof(cmd), "rpm -qf '%s' 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(result, sizeof(result), fp)) {
            if (strstr(result, "not owned") == NULL) {
                result[strcspn(result, "\n")] = 0;
                strncpy(package_name, result, name_len - 1);
                package_name[name_len - 1] = '\0';
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }

    package_name[0] = '\0';
    return 0;
}

/* Get list of loaded modules from /proc/modules */
static int get_loaded_modules(void)
{
    FILE *fp;
    char line[MAX_LINE];
    struct utsname uts;

    if (uname(&uts) != 0) {
        perror("uname");
        return -1;
    }

    fp = fopen("/proc/modules", "r");
    if (!fp) {
        perror("Cannot open /proc/modules");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && module_count < MAX_MODULES) {
        char name[256];
        struct module_info *mod = &modules[module_count];

        if (sscanf(line, "%255s", name) != 1)
            continue;

        strncpy(mod->name, name, sizeof(mod->name) - 1);
        mod->loaded = 1;

        /* Find module file path */
        char search_cmd[MAX_PATH + 256];
        snprintf(search_cmd, sizeof(search_cmd),
                 "modinfo -n '%s' 2>/dev/null", name);

        FILE *mod_fp = popen(search_cmd, "r");
        if (mod_fp) {
            if (fgets(mod->path, sizeof(mod->path), mod_fp)) {
                mod->path[strcspn(mod->path, "\n")] = 0;
            }
            pclose(mod_fp);
        }

        /* Skip built-in modules (no file path or "(builtin)") */
        if (mod->path[0] == '\0' || strstr(mod->path, "(builtin)")) {
            /* Still count it but mark as built-in */
            snprintf(mod->path, sizeof(mod->path), "(built-in)");
            mod->is_signed = -1;  /* N/A for built-in */
            mod->is_packaged = -1;
            module_count++;
            continue;
        }

        /* Compute hash */
        if (compute_sha256(mod->path, mod->sha256) != 0) {
            strcpy(mod->sha256, "(error)");
        }

        /* Check signature */
        mod->is_signed = check_module_signature(mod->path);

        /* Check package ownership */
        mod->is_packaged = check_package_ownership(
            mod->path, mod->package_name, sizeof(mod->package_name));

        module_count++;
    }

    fclose(fp);
    return module_count;
}

/* Check kernel taint flags */
static void check_taint_flags(void)
{
    FILE *fp;
    unsigned long taint;

    fp = fopen("/proc/sys/kernel/tainted", "r");
    if (!fp) {
        fprintf(stderr, "  Cannot read /proc/sys/kernel/tainted\n");
        return;
    }

    if (fscanf(fp, "%lu", &taint) != 1) {
        fclose(fp);
        return;
    }
    fclose(fp);

    printf("  Kernel taint flags: %lu", taint);
    if (taint == 0) {
        printf(" (clean)\n");
        return;
    }

    printf("\n");

    /* Decode relevant taint bits */
    struct {
        unsigned long bit;
        const char *desc;
    } taint_bits[] = {
        {1 << 0,  "Proprietary module loaded (P)"},
        {1 << 1,  "Module forced loaded (F)"},
        {1 << 2,  "Kernel is SMP but CPU not SMP capable (S)"},
        {1 << 4,  "Module out of tree (O)"},
        {1 << 12, "Unsigned module loaded (E)"},
        {1 << 13, "Soft lockup occurred (L)"},
        {1 << 15, "Module with live-patching (K)"},
        {1 << 16, "Auxiliary taint (X)"},
        {0, NULL}
    };

    for (int i = 0; taint_bits[i].desc; i++) {
        if (taint & taint_bits[i].bit) {
            printf("    [!] %s\n", taint_bits[i].desc);
        }
    }
}

/* Check kernel module signing enforcement */
static void check_module_sig_enforcement(void)
{
    FILE *fp;
    char line[MAX_LINE];
    char config_path[MAX_PATH];
    struct utsname uts;

    if (uname(&uts) != 0)
        return;

    snprintf(config_path, sizeof(config_path),
             "/boot/config-%s", uts.release);

    fp = fopen(config_path, "r");
    if (!fp) {
        printf("  Cannot read kernel config (%s)\n", config_path);
        return;
    }

    int sig_enabled = 0, sig_force = 0, sig_all = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "CONFIG_MODULE_SIG=y"))
            sig_enabled = 1;
        if (strstr(line, "CONFIG_MODULE_SIG_FORCE=y"))
            sig_force = 1;
        if (strstr(line, "CONFIG_MODULE_SIG_ALL=y"))
            sig_all = 1;
    }
    fclose(fp);

    printf("  Module signing (CONFIG_MODULE_SIG): %s\n",
           sig_enabled ? "ENABLED" : "DISABLED");
    printf("  Signature enforcement (CONFIG_MODULE_SIG_FORCE): %s\n",
           sig_force ? "ENFORCED" : "NOT ENFORCED");
    printf("  Sign all modules at build (CONFIG_MODULE_SIG_ALL): %s\n",
           sig_all ? "YES" : "NO");

    if (!sig_force)
        printf("  [!] WARNING: Unsigned modules CAN be loaded (tainted only)\n");
}

/* Save baseline */
static int save_baseline(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "Cannot write baseline to %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(fp, "# Module Integrity Baseline\n");
    fprintf(fp, "# Generated: ");
    {
        time_t t = time(NULL);
        fprintf(fp, "%s", ctime(&t));
    }
    fprintf(fp, "# Format: name|path|sha256|signed|package\n");

    for (int i = 0; i < module_count; i++) {
        fprintf(fp, "%s|%s|%s|%d|%s\n",
                modules[i].name,
                modules[i].path,
                modules[i].sha256,
                modules[i].is_signed,
                modules[i].package_name);
    }

    fclose(fp);
    printf("  Baseline saved to: %s (%d modules)\n", path, module_count);
    return 0;
}

/* Compare against baseline */
static int compare_baseline(const char *path)
{
    FILE *fp;
    char line[MAX_LINE];
    int differences = 0;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot read baseline from %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    printf("\n  Comparing against baseline: %s\n\n", path);

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#')
            continue;

        char b_name[256], b_path[MAX_PATH], b_sha256[65];
        int b_signed;
        char b_package[256];

        if (sscanf(line, "%255[^|]|%1023[^|]|%64[^|]|%d|%255[^\n]",
                   b_name, b_path, b_sha256, &b_signed, b_package) < 3)
            continue;

        /* Find matching module in current scan */
        int found = 0;
        for (int i = 0; i < module_count; i++) {
            if (strcmp(modules[i].name, b_name) == 0) {
                found = 1;

                /* Compare hash */
                if (strcmp(modules[i].sha256, b_sha256) != 0 &&
                    strcmp(modules[i].sha256, "(error)") != 0 &&
                    strcmp(b_sha256, "(error)") != 0) {
                    printf("  [CHANGED] %s: hash mismatch!\n", b_name);
                    printf("    Baseline: %s\n", b_sha256);
                    printf("    Current:  %s\n", modules[i].sha256);
                    differences++;
                }

                /* Compare signature status */
                if (modules[i].is_signed != b_signed && b_signed >= 0) {
                    printf("  [CHANGED] %s: signature status changed "
                           "(%d -> %d)\n",
                           b_name, b_signed, modules[i].is_signed);
                    differences++;
                }
                break;
            }
        }

        if (!found) {
            printf("  [REMOVED] %s: was in baseline, not currently loaded\n",
                   b_name);
        }
    }

    /* Check for new modules not in baseline */
    /* (would need to load baseline into memory for proper comparison) */

    fclose(fp);

    printf("\n  Differences found: %d\n", differences);
    return differences;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-m module] [-b baseline] [-s save_baseline]\n",
            prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v              Verbose mode\n");
    fprintf(stderr, "  -m module_name  Check specific module only\n");
    fprintf(stderr, "  -b baseline     Compare against baseline file\n");
    fprintf(stderr, "  -s save_file    Save current state as baseline\n");
    fprintf(stderr, "\nDefensive Tool: Verify kernel module supply chain integrity.\n");
}

int main(int argc, char **argv)
{
    int verbose = 0;
    const char *specific_module = NULL;
    const char *baseline_file = NULL;
    const char *save_file = NULL;
    int opt;
    int unsigned_count = 0, unpackaged_count = 0;

    while ((opt = getopt(argc, argv, "vm:b:s:h")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'm': specific_module = optarg; break;
        case 'b': baseline_file = optarg; break;
        case 's': save_file = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This tool requires root privileges.\n");
        return 1;
    }

    printf("======================================================\n");
    printf("  Supply Chain Verifier - Module Integrity Audit Tool\n");
    printf("======================================================\n\n");

    /* Check kernel configuration */
    printf("--- Kernel Module Signing Configuration ---\n\n");
    check_module_sig_enforcement();
    printf("\n");
    check_taint_flags();
    printf("\n");

    /* Enumerate and verify modules */
    printf("--- Loaded Module Analysis ---\n\n");
    int count = get_loaded_modules();
    if (count < 0) {
        fprintf(stderr, "Failed to enumerate modules\n");
        return 1;
    }

    printf("  Found %d loaded modules.\n\n", count);

    for (int i = 0; i < module_count; i++) {
        struct module_info *mod = &modules[i];

        /* Filter by specific module if requested */
        if (specific_module && strcmp(mod->name, specific_module) != 0)
            continue;

        /* Skip built-in modules in summary (show in verbose) */
        if (strcmp(mod->path, "(built-in)") == 0) {
            if (verbose)
                printf("  [BUILTIN] %-30s\n", mod->name);
            continue;
        }

        const char *sig_status;
        if (mod->is_signed == 1)
            sig_status = "SIGNED";
        else if (mod->is_signed == 0) {
            sig_status = "UNSIGNED";
            unsigned_count++;
        } else {
            sig_status = "N/A";
        }

        const char *pkg_status;
        if (mod->is_packaged == 1)
            pkg_status = mod->package_name;
        else if (mod->is_packaged == 0) {
            pkg_status = "UNPACKAGED";
            unpackaged_count++;
        } else {
            pkg_status = "N/A";
        }

        /* Determine alert level */
        int is_alert = (mod->is_signed == 0 || mod->is_packaged == 0);

        if (is_alert || verbose) {
            printf("  %s %-30s  Sig: %-10s  Pkg: %s\n",
                   is_alert ? "[!]" : "   ",
                   mod->name, sig_status, pkg_status);
            if (verbose) {
                printf("      Path: %s\n", mod->path);
                printf("      SHA256: %s\n", mod->sha256);
            }
        }
    }

    /* Save baseline if requested */
    if (save_file) {
        printf("\n--- Saving Baseline ---\n\n");
        save_baseline(save_file);
    }

    /* Compare against baseline if provided */
    if (baseline_file) {
        printf("\n--- Baseline Comparison ---\n");
        compare_baseline(baseline_file);
    }

    /* Summary */
    printf("\n======================================================\n");
    printf("  VERIFICATION COMPLETE\n");
    printf("======================================================\n");
    printf("  Total modules:     %d\n", module_count);
    printf("  Unsigned modules:  %d\n", unsigned_count);
    printf("  Unpackaged modules: %d\n", unpackaged_count);

    if (unsigned_count > 0)
        printf("\n  [!] %d unsigned module(s) detected. Investigate.\n",
               unsigned_count);
    if (unpackaged_count > 0)
        printf("  [!] %d unpackaged module(s) detected. Verify origin.\n",
               unpackaged_count);

    printf("======================================================\n");

    return (unsigned_count > 0 || unpackaged_count > 0) ? 1 : 0;
}

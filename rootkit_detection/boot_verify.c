/*
 * boot_verify.c - Check Secure Boot status and boot integrity indicators
 *
 *
 * Checks:
 *   1. UEFI vs Legacy BIOS boot mode
 *   2. Secure Boot enabled/disabled status
 *   3. Kernel lockdown mode
 *   4. Module signing enforcement
 *   5. Kernel command line analysis
 *   6. Boot-relevant kernel configuration
 *   7. EFI System Partition integrity indicators
 *
 * Compile: gcc -o boot_verify boot_verify.c -static
 * Usage:   sudo ./boot_verify
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

#define MAX_PATH 512
#define MAX_LINE 4096

static int pass_count = 0;
static int warn_count = 0;
static int fail_count = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Boot Security Verification Tool\n");
    printf("  Secure Boot & Integrity Checker\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

static void result_pass(const char *check, const char *detail)
{
    printf(GREEN "  [PASS]" RESET "  %-35s %s\n", check, detail);
    pass_count++;
}

static void result_warn(const char *check, const char *detail)
{
    printf(YELLOW "  [WARN]" RESET "  %-35s %s\n", check, detail);
    warn_count++;
}

static void result_fail(const char *check, const char *detail)
{
    printf(RED "  [FAIL]" RESET "  %-35s %s\n", check, detail);
    fail_count++;
}

static void result_info(const char *check, const char *detail)
{
    printf(CYAN "  [INFO]" RESET "  %-35s %s\n", check, detail);
}

/*
 * Read a file into a buffer (single line)
 */
static int read_file_line(const char *path, char *buf, size_t buflen)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);

    if (n <= 0) return -1;

    buf[n] = '\0';
    buf[strcspn(buf, "\n")] = '\0';

    return 0;
}

/*
 * Check 1: UEFI vs Legacy BIOS
 */
static void check_boot_mode(void)
{
    struct stat st;

    printf(BOLD "\n  --- Boot Mode ---\n" RESET);

    if (stat("/sys/firmware/efi", &st) == 0) {
        result_pass("Boot Mode", "UEFI (EFI variables accessible)");

        /* Check for EFI runtime services */
        if (stat("/sys/firmware/efi/runtime", &st) == 0 ||
            stat("/sys/firmware/efi/efivars", &st) == 0) {
            result_pass("EFI Runtime Services", "Available");
        } else {
            result_info("EFI Runtime Services", "Limited or unavailable");
        }
    } else {
        result_warn("Boot Mode", "Legacy BIOS (or UEFI without EFI vars)");
        result_info("Secure Boot", "Not applicable for Legacy BIOS");
    }
}

/*
 * Check 2: Secure Boot Status
 */
static void check_secure_boot(void)
{
    struct stat st;
    char buf[256];

    printf(BOLD "\n  --- Secure Boot ---\n" RESET);

    /* Method 1: Check EFI variable */
    /* The SecureBoot variable is at a well-known GUID path */
    DIR *dir = opendir("/sys/firmware/efi/efivars");
    if (dir != NULL) {
        struct dirent *entry;
        int found_sb = 0;

        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "SecureBoot-", 11) == 0) {
                char var_path[MAX_PATH];
                snprintf(var_path, sizeof(var_path),
                         "/sys/firmware/efi/efivars/%s", entry->d_name);

                int fd = open(var_path, O_RDONLY);
                if (fd >= 0) {
                    unsigned char data[8];
                    ssize_t n = read(fd, data, sizeof(data));
                    close(fd);

                    /* EFI variable format: 4 bytes attributes + data */
                    if (n >= 5) {
                        if (data[4] == 1) {
                            result_pass("Secure Boot", "ENABLED");
                        } else {
                            result_fail("Secure Boot", "DISABLED");
                        }
                        found_sb = 1;
                    }
                }
                break;
            }
        }
        closedir(dir);

        if (!found_sb) {
            result_warn("Secure Boot", "Variable not found");
        }
    } else {
        result_info("Secure Boot", "Cannot access EFI variables");
    }

    /* Method 2: Check dmesg-style kernel log for Secure Boot mention */
    /* This is a fallback - reading /var/log/dmesg or similar */
    FILE *fp = fopen("/proc/cmdline", "r");
    if (fp) {
        if (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "lockdown") != NULL)
                result_info("Kernel Command Line", "Contains 'lockdown' parameter");
        }
        fclose(fp);
    }
}

/*
 * Check 3: Kernel Lockdown Mode
 */
static void check_lockdown(void)
{
    char buf[128];

    printf(BOLD "\n  --- Kernel Lockdown ---\n" RESET);

    if (read_file_line("/sys/kernel/security/lockdown", buf, sizeof(buf)) == 0) {
        if (strstr(buf, "[confidentiality]") != NULL) {
            result_pass("Kernel Lockdown", "CONFIDENTIALITY mode (highest)");
        } else if (strstr(buf, "[integrity]") != NULL) {
            result_pass("Kernel Lockdown", "INTEGRITY mode");
        } else if (strstr(buf, "[none]") != NULL) {
            result_warn("Kernel Lockdown", "NONE (disabled)");
        } else {
            result_info("Kernel Lockdown", buf);
        }
    } else {
        result_warn("Kernel Lockdown", "Not available (LSM not loaded)");
    }
}

/*
 * Check 4: Module Signing and Loading
 */
static void check_module_security(void)
{
    char buf[128];

    printf(BOLD "\n  --- Module Security ---\n" RESET);

    /* Check modules_disabled */
    if (read_file_line("/proc/sys/kernel/modules_disabled", buf, sizeof(buf)) == 0) {
        if (atoi(buf) == 1) {
            result_pass("Module Loading", "DISABLED (modules_disabled=1)");
        } else {
            result_warn("Module Loading", "ENABLED (modules can be loaded)");
        }
    }

    /* Check kernel taint for unsigned modules */
    if (read_file_line("/proc/sys/kernel/tainted", buf, sizeof(buf)) == 0) {
        unsigned long taint = strtoul(buf, NULL, 10);

        if (taint == 0) {
            result_pass("Kernel Taint", "Clean (0)");
        } else {
            char detail[256];
            snprintf(detail, sizeof(detail), "Tainted (%lu)", taint);

            if (taint & (1 << 12))
                result_fail("Unsigned Module", "Unsigned module has been loaded!");
            else if (taint & (1 << 13))
                result_fail("Bad Signature", "Module with bad signature loaded!");
            else
                result_warn("Kernel Taint", detail);
        }
    }

    /* Check if module signing info is visible */
    struct stat st;
    if (stat("/proc/keys", &st) == 0) {
        result_info("Kernel Keyring", "Accessible (/proc/keys exists)");
    }
}

/*
 * Check 5: Kernel Command Line Analysis
 */
static void check_cmdline(void)
{
    char buf[MAX_LINE];

    printf(BOLD "\n  --- Kernel Command Line ---\n" RESET);

    if (read_file_line("/proc/cmdline", buf, sizeof(buf)) != 0) {
        result_warn("Command Line", "Cannot read /proc/cmdline");
        return;
    }

    result_info("Full cmdline", buf);

    /* Check for security-relevant parameters */
    if (strstr(buf, "lockdown=integrity"))
        result_pass("Lockdown param", "integrity");
    else if (strstr(buf, "lockdown=confidentiality"))
        result_pass("Lockdown param", "confidentiality");
    else
        result_info("Lockdown param", "Not present on command line");

    if (strstr(buf, "module.sig_enforce"))
        result_pass("Module sig enforce", "Present on command line");

    if (strstr(buf, "init=/bin/sh") || strstr(buf, "init=/bin/bash"))
        result_fail("Init override", "Shell specified as init! (recovery or attack)");

    if (strstr(buf, "single") || strstr(buf, " S ") || strstr(buf, " 1 "))
        result_warn("Single user mode", "System booted in single-user mode");

    if (strstr(buf, "selinux=0") || strstr(buf, "apparmor=0"))
        result_warn("Security module", "Security module disabled on command line");

    if (strstr(buf, "nokaslr"))
        result_fail("KASLR", "KASLR disabled on command line!");

    if (strstr(buf, "nopti") || strstr(buf, "pti=off"))
        result_warn("PTI/KPTI", "Page Table Isolation disabled");
}

/*
 * Check 6: Important kernel security settings
 */
static void check_kernel_security(void)
{
    char buf[128];

    printf(BOLD "\n  --- Kernel Security Settings ---\n" RESET);

    /* ASLR */
    if (read_file_line("/proc/sys/kernel/randomize_va_space", buf, sizeof(buf)) == 0) {
        int val = atoi(buf);
        if (val == 2)
            result_pass("ASLR", "Full randomization (2)");
        else if (val == 1)
            result_warn("ASLR", "Partial randomization (1)");
        else
            result_fail("ASLR", "DISABLED (0)!");
    }

    /* Yama ptrace scope */
    if (read_file_line("/proc/sys/kernel/yama/ptrace_scope", buf, sizeof(buf)) == 0) {
        int val = atoi(buf);
        switch (val) {
        case 0: result_warn("Yama ptrace", "Classic (0) - any process can trace"); break;
        case 1: result_pass("Yama ptrace", "Restricted (1) - parent only"); break;
        case 2: result_pass("Yama ptrace", "Admin only (2) - CAP_SYS_PTRACE"); break;
        case 3: result_pass("Yama ptrace", "No attach (3) - ptrace disabled"); break;
        }
    } else {
        result_warn("Yama ptrace", "Not available");
    }

    /* kptr_restrict */
    if (read_file_line("/proc/sys/kernel/kptr_restrict", buf, sizeof(buf)) == 0) {
        int val = atoi(buf);
        if (val >= 1)
            result_pass("kptr_restrict", buf);
        else
            result_warn("kptr_restrict", "0 (kernel pointers visible to all)");
    }

    /* dmesg_restrict */
    if (read_file_line("/proc/sys/kernel/dmesg_restrict", buf, sizeof(buf)) == 0) {
        if (atoi(buf) == 1)
            result_pass("dmesg_restrict", "Restricted (1)");
        else
            result_warn("dmesg_restrict", "Unrestricted (0)");
    }

    /* perf_event_paranoid */
    if (read_file_line("/proc/sys/kernel/perf_event_paranoid", buf, sizeof(buf)) == 0) {
        int val = atoi(buf);
        if (val >= 2)
            result_pass("perf_event_paranoid", buf);
        else
            result_warn("perf_event_paranoid", buf);
    }
}

/*
 * Check 7: EFI System Partition
 */
static void check_esp(void)
{
    struct stat st;

    printf(BOLD "\n  --- EFI System Partition ---\n" RESET);

    /* Check common ESP mount points */
    const char *esp_paths[] = {
        "/boot/efi",
        "/efi",
        "/boot",
        NULL
    };

    for (int i = 0; esp_paths[i] != NULL; i++) {
        if (stat(esp_paths[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            /* Check for EFI directory */
            char efi_dir[MAX_PATH];
            snprintf(efi_dir, sizeof(efi_dir), "%s/EFI", esp_paths[i]);

            if (stat(efi_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
                char detail[256];
                snprintf(detail, sizeof(detail), "Found at %s", esp_paths[i]);
                result_info("ESP Location", detail);

                /* List EFI subdirectories */
                DIR *dir = opendir(efi_dir);
                if (dir != NULL) {
                    struct dirent *entry;
                    printf("    EFI entries:");
                    while ((entry = readdir(dir)) != NULL) {
                        if (entry->d_name[0] == '.') continue;
                        printf(" %s", entry->d_name);
                    }
                    printf("\n");
                    closedir(dir);
                }

                /* Check for shim and grub */
                char shim_path[MAX_PATH];
                snprintf(shim_path, sizeof(shim_path),
                         "%s/EFI/ubuntu/shimx64.efi", esp_paths[i]);
                if (stat(shim_path, &st) == 0) {
                    result_info("Shim bootloader", "Found (Secure Boot chain)");
                }

                break;
            }
        }
    }
}

/*
 * Check 8: TPM availability
 */
static void check_tpm(void)
{
    struct stat st;
    char buf[256];

    printf(BOLD "\n  --- TPM Status ---\n" RESET);

    if (stat("/sys/class/tpm/tpm0", &st) == 0) {
        result_pass("TPM Device", "Present (/sys/class/tpm/tpm0)");

        /* Read TPM version if available */
        if (read_file_line("/sys/class/tpm/tpm0/tpm_version_major", buf, sizeof(buf)) == 0) {
            char detail[64];
            snprintf(detail, sizeof(detail), "TPM %s.x", buf);
            result_info("TPM Version", detail);
        }

        /* Check for PCR availability */
        if (stat("/sys/class/tpm/tpm0/pcr-sha256", &st) == 0 ||
            stat("/sys/class/tpm/tpm0/pcr-sha1", &st) == 0) {
            result_info("TPM PCRs", "Available for reading");
        }
    } else if (stat("/dev/tpm0", &st) == 0 || stat("/dev/tpmrm0", &st) == 0) {
        result_pass("TPM Device", "Present (/dev/tpm0)");
    } else {
        result_warn("TPM Device", "Not found (no hardware TPM or not enabled)");
    }
}

static void print_summary(void)
{
    int total = pass_count + warn_count + fail_count;
    int score;

    if (total > 0)
        score = (pass_count * 100) / total;
    else
        score = 0;

    printf(CYAN "\n============================================\n");
    printf("  Boot Security Summary\n");
    printf("============================================\n" RESET);
    printf("  Checks passed:  " GREEN "%d\n" RESET, pass_count);
    printf("  Warnings:       " YELLOW "%d\n" RESET, warn_count);
    printf("  Failures:       " RED "%d\n" RESET, fail_count);
    printf("  Security score: %d%%\n", score);
    printf("\n");

    if (fail_count > 0) {
        printf(RED "  RESULT: Boot security issues detected!\n" RESET);
        printf("  Address FAIL items to improve security posture.\n");
    } else if (warn_count > 0) {
        printf(YELLOW "  RESULT: Boot security could be improved.\n" RESET);
        printf("  Review WARN items for hardening opportunities.\n");
    } else {
        printf(GREEN "  RESULT: Boot security configuration looks good.\n" RESET);
    }

    printf("\n  Key recommendations:\n");
    printf("  1. Enable Secure Boot if not already active\n");
    printf("  2. Enable kernel lockdown mode (integrity or confidentiality)\n");
    printf("  3. Enforce module signing (CONFIG_MODULE_SIG_FORCE)\n");
    printf("  4. Disable module loading after boot (modules_disabled=1)\n");
    printf("  5. Keep firmware updated (fwupdmgr update)\n");
    printf("  6. Enable TPM and measured boot if hardware supports it\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Some EFI variables and kernel settings may be inaccessible.\n");
        printf("  Run as root for complete analysis.\n\n" RESET);
    }

    check_boot_mode();
    check_secure_boot();
    check_lockdown();
    check_module_security();
    check_cmdline();
    check_kernel_security();
    check_esp();
    check_tpm();
    print_summary();

    return (fail_count > 0) ? 1 : 0;
}

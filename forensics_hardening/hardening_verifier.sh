#!/bin/bash
#
# hardening_verifier.sh - System Hardening Verification Script
#
#
# Verifies system hardening against a CIS-inspired security checklist.
# Reports compliance status for each check and generates a summary score.
#
# Usage: sudo ./hardening_verifier.sh [--verbose] [--output FILE]
#
# Exit codes:
#   0 = All checks passed (score >= 80%)
#   1 = Some checks failed (score < 80%)
#   2 = Critical failures detected
#

set -euo pipefail

VERBOSE=0
OUTPUT_FILE=""
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
SKIPPED_CHECKS=0
CRITICAL_FAILS=0

# ── Parse arguments ─────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose|-v) VERBOSE=1; shift ;;
        --output|-o)  OUTPUT_FILE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--output FILE]"
            echo ""
            echo "Verifies system hardening against a security checklist."
            echo "Must be run as root."
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $(id -u) -ne 0 ]]; then
    echo "ERROR: Must be run as root for complete verification."
    exit 2
fi

# ── Output functions ────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_output() {
    local msg="$1"
    echo -e "$msg"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

check_pass() {
    local id="$1" desc="$2"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    log_output "  ${GREEN}[PASS]${NC} $id: $desc"
}

check_fail() {
    local id="$1" desc="$2" fix="${3:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    log_output "  ${RED}[FAIL]${NC} $id: $desc"
    if [[ $VERBOSE -eq 1 && -n "$fix" ]]; then
        log_output "         Fix: $fix"
    fi
}

check_critical() {
    local id="$1" desc="$2" fix="${3:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    CRITICAL_FAILS=$((CRITICAL_FAILS + 1))
    log_output "  ${RED}[CRIT]${NC} $id: $desc"
    if [[ $VERBOSE -eq 1 && -n "$fix" ]]; then
        log_output "         Fix: $fix"
    fi
}

check_skip() {
    local id="$1" desc="$2"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
    log_output "  ${YELLOW}[SKIP]${NC} $id: $desc"
}

section_header() {
    log_output ""
    log_output "${BLUE}=== $1 ===${NC}"
}

# ── Helpers ─────────────────────────────────────────────────────

get_sysctl() {
    local key="$1"
    local path="/proc/sys/${key//\.//}"
    if [[ -f "$path" ]]; then
        cat "$path" 2>/dev/null
    else
        echo "N/A"
    fi
}

# ── Initialize ──────────────────────────────────────────────────

if [[ -n "$OUTPUT_FILE" ]]; then
    > "$OUTPUT_FILE"
fi

log_output "============================================================"
log_output "  System Hardening Verification Report"
log_output "  Date: $(date)"
log_output "  Host: $(hostname)"
log_output "  Kernel: $(uname -r)"
log_output "============================================================"

# ── Section 1: Boot Security ───────────────────────────────────

section_header "Section 1: Boot Security"

# 1.1 UEFI Secure Boot
if [[ -d /sys/firmware/efi ]]; then
    if command -v mokutil &>/dev/null; then
        if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
            check_pass "1.1" "UEFI Secure Boot is enabled"
        else
            check_fail "1.1" "UEFI Secure Boot is NOT enabled" "Enable in BIOS settings"
        fi
    else
        check_skip "1.1" "mokutil not available (cannot verify Secure Boot)"
    fi
else
    check_skip "1.1" "System is not using UEFI"
fi

# 1.2 GRUB password
if [[ -f /boot/grub/grub.cfg ]]; then
    if grep -q 'password_pbkdf2' /boot/grub/grub.cfg 2>/dev/null; then
        check_pass "1.2" "GRUB password protection is configured"
    else
        check_fail "1.2" "GRUB password is NOT set" "Run grub-mkpasswd-pbkdf2 and configure"
    fi
elif [[ -f /boot/grub2/grub.cfg ]]; then
    if grep -q 'password_pbkdf2' /boot/grub2/grub.cfg 2>/dev/null; then
        check_pass "1.2" "GRUB password protection is configured"
    else
        check_fail "1.2" "GRUB password is NOT set" "Run grub2-mkpasswd-pbkdf2 and configure"
    fi
else
    check_skip "1.2" "GRUB configuration not found"
fi

# 1.3 GRUB config permissions
for grub_cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    if [[ -f "$grub_cfg" ]]; then
        perms=$(stat -c "%a" "$grub_cfg" 2>/dev/null)
        if [[ "$perms" == "600" || "$perms" == "400" ]]; then
            check_pass "1.3" "GRUB config permissions are restrictive ($perms)"
        else
            check_fail "1.3" "GRUB config permissions too open ($perms)" "chmod 600 $grub_cfg"
        fi
        break
    fi
done

# 1.4 Kernel lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
    lockdown=$(cat /sys/kernel/security/lockdown)
    if echo "$lockdown" | grep -q '\[integrity\]\|confidentiality\]'; then
        check_pass "1.4" "Kernel lockdown is enabled: $lockdown"
    else
        check_fail "1.4" "Kernel lockdown is NOT enabled" "Add lockdown=integrity to boot params"
    fi
else
    check_skip "1.4" "Lockdown LSM not available"
fi

# ── Section 2: Kernel Hardening ────────────────────────────────

section_header "Section 2: Kernel Hardening (sysctl)"

declare -A SYSCTL_CHECKS=(
    ["2.1|kernel.kptr_restrict|2"]="Kernel pointer restriction (hide addresses)"
    ["2.2|kernel.dmesg_restrict|1"]="Restrict dmesg to root"
    ["2.3|kernel.randomize_va_space|2"]="Full ASLR enabled"
    ["2.4|kernel.yama.ptrace_scope|2"]="Restrict ptrace to root"
    ["2.5|kernel.sysrq|0"]="Magic SysRq key disabled"
    ["2.6|fs.suid_dumpable|0"]="SUID core dumps disabled"
    ["2.7|kernel.unprivileged_bpf_disabled|1"]="Unprivileged BPF disabled"
    ["2.8|fs.protected_hardlinks|1"]="Hardlink protection enabled"
    ["2.9|fs.protected_symlinks|1"]="Symlink protection enabled"
    ["2.10|net.ipv4.ip_forward|0"]="IP forwarding disabled"
    ["2.11|net.ipv4.conf.all.accept_source_route|0"]="Source routing rejected"
    ["2.12|net.ipv4.conf.all.accept_redirects|0"]="ICMP redirects ignored"
    ["2.13|net.ipv4.conf.all.send_redirects|0"]="ICMP redirect sending disabled"
    ["2.14|net.ipv4.conf.all.rp_filter|1"]="Reverse path filtering enabled"
    ["2.15|net.ipv4.conf.all.log_martians|1"]="Martian packet logging enabled"
    ["2.16|net.ipv4.icmp_echo_ignore_broadcasts|1"]="Broadcast ICMP ignored"
    ["2.17|net.ipv4.tcp_syncookies|1"]="SYN cookies enabled"
    ["2.18|net.ipv6.conf.all.accept_redirects|0"]="IPv6 redirects ignored"
    ["2.19|net.ipv6.conf.all.accept_source_route|0"]="IPv6 source routing rejected"
)

for key_entry in "${!SYSCTL_CHECKS[@]}"; do
    IFS='|' read -r check_id sysctl_key expected <<< "$key_entry"
    desc="${SYSCTL_CHECKS[$key_entry]}"
    current=$(get_sysctl "$sysctl_key")

    if [[ "$current" == "N/A" ]]; then
        check_skip "$check_id" "$desc (setting not available)"
    elif [[ "$current" == "$expected" ]]; then
        check_pass "$check_id" "$desc ($sysctl_key = $current)"
    else
        check_fail "$check_id" "$desc ($sysctl_key = $current, expected $expected)" \
            "sysctl -w $sysctl_key=$expected"
    fi
done

# ── Section 3: Filesystem Hardening ────────────────────────────

section_header "Section 3: Filesystem Hardening"

# 3.1 /tmp mount options
if mount | grep -q 'on /tmp '; then
    tmp_opts=$(mount | grep 'on /tmp ' | head -1)
    if echo "$tmp_opts" | grep -q 'noexec'; then
        check_pass "3.1" "/tmp mounted with noexec"
    else
        check_fail "3.1" "/tmp NOT mounted with noexec" "Add noexec to /tmp in fstab"
    fi
    if echo "$tmp_opts" | grep -q 'nosuid'; then
        check_pass "3.2" "/tmp mounted with nosuid"
    else
        check_fail "3.2" "/tmp NOT mounted with nosuid" "Add nosuid to /tmp in fstab"
    fi
    if echo "$tmp_opts" | grep -q 'nodev'; then
        check_pass "3.3" "/tmp mounted with nodev"
    else
        check_fail "3.3" "/tmp NOT mounted with nodev" "Add nodev to /tmp in fstab"
    fi
else
    check_fail "3.1" "/tmp is not a separate mount" "Create separate /tmp partition"
    check_skip "3.2" "/tmp nosuid (not separate mount)"
    check_skip "3.3" "/tmp nodev (not separate mount)"
fi

# 3.4 /dev/shm options
if mount | grep -q 'on /dev/shm '; then
    shm_opts=$(mount | grep 'on /dev/shm ' | head -1)
    if echo "$shm_opts" | grep -q 'noexec'; then
        check_pass "3.4" "/dev/shm mounted with noexec"
    else
        check_fail "3.4" "/dev/shm NOT mounted with noexec" "Add noexec to /dev/shm in fstab"
    fi
else
    check_skip "3.4" "/dev/shm not found in mounts"
fi

# 3.5 Critical file permissions
declare -A FILE_PERMS=(
    ["/etc/shadow"]="600"
    ["/etc/gshadow"]="600"
    ["/etc/passwd"]="644"
    ["/etc/group"]="644"
)

check_num=5
for filepath in "${!FILE_PERMS[@]}"; do
    expected_perm="${FILE_PERMS[$filepath]}"
    if [[ -f "$filepath" ]]; then
        actual_perm=$(stat -c "%a" "$filepath")
        if [[ "$actual_perm" == "$expected_perm" ]]; then
            check_pass "3.$check_num" "$filepath permissions correct ($actual_perm)"
        else
            check_fail "3.$check_num" "$filepath permissions ($actual_perm, expected $expected_perm)" \
                "chmod $expected_perm $filepath"
        fi
    fi
    check_num=$((check_num + 1))
done

# ── Section 4: Module Security ─────────────────────────────────

section_header "Section 4: Kernel Module Security"

# 4.1 Kernel taint (unsigned modules)
taint=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "0")
if [[ "$taint" == "0" ]]; then
    check_pass "4.1" "Kernel is not tainted (no unsigned modules)"
elif (( taint & 4096 )); then
    check_critical "4.1" "Kernel is tainted with unsigned module flag" \
        "Remove unsigned modules; enable CONFIG_MODULE_SIG_FORCE"
else
    check_fail "4.1" "Kernel is tainted (value: $taint)" "Investigate taint source"
fi

# 4.2 Module signature enforcement
if grep -q "CONFIG_MODULE_SIG_FORCE=y" /boot/config-$(uname -r) 2>/dev/null; then
    check_pass "4.2" "Module signature enforcement is enabled"
else
    check_fail "4.2" "Module signature enforcement is NOT enabled" \
        "Rebuild kernel with CONFIG_MODULE_SIG_FORCE=y"
fi

# 4.3 Blacklisted modules
blacklisted_fs=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf")
blacklisted_count=0
for mod in "${blacklisted_fs[@]}"; do
    if grep -rq "install $mod /bin/false\|install $mod /bin/true\|blacklist $mod" /etc/modprobe.d/ 2>/dev/null; then
        blacklisted_count=$((blacklisted_count + 1))
    fi
done

if [[ $blacklisted_count -eq ${#blacklisted_fs[@]} ]]; then
    check_pass "4.3" "All unused filesystems blacklisted ($blacklisted_count/${#blacklisted_fs[@]})"
else
    check_fail "4.3" "Not all unused filesystems blacklisted ($blacklisted_count/${#blacklisted_fs[@]})" \
        "Add 'install <fs> /bin/false' to /etc/modprobe.d/"
fi

# ── Section 5: Network Security ────────────────────────────────

section_header "Section 5: Network Security"

# 5.1 Firewall active
if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain input'; then
    check_pass "5.1" "nftables firewall is configured"
elif command -v iptables &>/dev/null && iptables -L INPUT 2>/dev/null | grep -q 'DROP\|REJECT'; then
    check_pass "5.1" "iptables firewall has restrictive policy"
else
    check_fail "5.1" "No active firewall detected" "Configure nftables or iptables"
fi

# 5.2 SSH root login
if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -Eq "^PermitRootLogin\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "5.2" "SSH root login is disabled"
    else
        check_fail "5.2" "SSH root login may be allowed" \
            "Set 'PermitRootLogin no' in sshd_config"
    fi

    if grep -Eq "^PasswordAuthentication\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "5.3" "SSH password authentication is disabled"
    else
        check_fail "5.3" "SSH password authentication may be enabled" \
            "Set 'PasswordAuthentication no' in sshd_config"
    fi
fi

# ── Section 6: Monitoring ──────────────────────────────────────

section_header "Section 6: Security Monitoring"

# 6.1 auditd running
if systemctl is-active --quiet auditd 2>/dev/null; then
    check_pass "6.1" "auditd is running"
    rule_count=$(auditctl -l 2>/dev/null | wc -l)
    if [[ $rule_count -gt 10 ]]; then
        check_pass "6.2" "auditd has $rule_count rules loaded"
    else
        check_fail "6.2" "auditd has only $rule_count rules (expected 10+)" \
            "Run audit_config.sh --install"
    fi
else
    check_critical "6.1" "auditd is NOT running" "systemctl enable --now auditd"
    check_skip "6.2" "auditd rules (service not running)"
fi

# 6.3 File integrity monitoring
if command -v aide &>/dev/null || command -v /usr/sbin/aide &>/dev/null; then
    if [[ -f /var/lib/aide/aide.db ]]; then
        check_pass "6.3" "AIDE is installed with baseline database"
    else
        check_fail "6.3" "AIDE installed but no baseline" "Run aideinit"
    fi
elif dpkg -l 2>/dev/null | grep -q 'wazuh-agent\|ossec'; then
    check_pass "6.3" "Wazuh/OSSEC agent installed for FIM"
else
    check_fail "6.3" "No file integrity monitoring detected" "Install AIDE or Wazuh"
fi

# 6.4 Logging
if [[ -f /var/log/audit/audit.log ]]; then
    check_pass "6.4" "Audit log exists at /var/log/audit/audit.log"
else
    check_fail "6.4" "Audit log not found" "Start auditd service"
fi

# ── Section 7: Service Minimization ────────────────────────────

section_header "Section 7: Service Minimization"

unnecessary_services=("avahi-daemon" "cups" "bluetooth" "ModemManager")
active_unnecessary=0

for svc in "${unnecessary_services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        check_fail "7.x" "Unnecessary service running: $svc" \
            "systemctl disable --now $svc"
        active_unnecessary=$((active_unnecessary + 1))
    fi
done

if [[ $active_unnecessary -eq 0 ]]; then
    check_pass "7.1" "No common unnecessary services running"
fi

# Check listening ports
listen_count=$(ss -tlnp 2>/dev/null | tail -n +2 | wc -l)
if [[ $listen_count -le 5 ]]; then
    check_pass "7.2" "Only $listen_count listening ports (minimal)"
elif [[ $listen_count -le 10 ]]; then
    check_fail "7.2" "$listen_count listening ports (could be reduced)" \
        "Review: ss -tlnp"
else
    check_fail "7.2" "$listen_count listening ports (too many)" \
        "Review and disable unnecessary services"
fi

# ── Summary ─────────────────────────────────────────────────────

log_output ""
log_output "============================================================"
log_output "  HARDENING VERIFICATION SUMMARY"
log_output "============================================================"
log_output ""
log_output "  Total checks:    $TOTAL_CHECKS"
log_output "  Passed:          ${GREEN}$PASSED_CHECKS${NC}"
log_output "  Failed:          ${RED}$FAILED_CHECKS${NC}"
log_output "  Skipped:         ${YELLOW}$SKIPPED_CHECKS${NC}"
log_output "  Critical fails:  ${RED}$CRITICAL_FAILS${NC}"
log_output ""

if [[ $TOTAL_CHECKS -gt 0 ]]; then
    SCORE=$(( (PASSED_CHECKS * 100) / (TOTAL_CHECKS - SKIPPED_CHECKS) ))
else
    SCORE=0
fi

log_output "  Compliance Score: ${SCORE}%"
log_output ""

if [[ $SCORE -ge 90 ]]; then
    log_output "  Rating: ${GREEN}EXCELLENT${NC} - System is well hardened"
elif [[ $SCORE -ge 80 ]]; then
    log_output "  Rating: ${GREEN}GOOD${NC} - Minor improvements recommended"
elif [[ $SCORE -ge 60 ]]; then
    log_output "  Rating: ${YELLOW}FAIR${NC} - Significant hardening needed"
else
    log_output "  Rating: ${RED}POOR${NC} - System requires immediate hardening"
fi

log_output ""
log_output "============================================================"

if [[ -n "$OUTPUT_FILE" ]]; then
    echo "Report saved to: $OUTPUT_FILE"
fi

# Exit code
if [[ $CRITICAL_FAILS -gt 0 ]]; then
    exit 2
elif [[ $SCORE -ge 80 ]]; then
    exit 0
else
    exit 1
fi

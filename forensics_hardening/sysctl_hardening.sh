#!/bin/bash
#
# sysctl_hardening.sh - Comprehensive Sysctl Hardening Script
#
#
# Applies kernel security hardening via sysctl settings.
# Each setting is documented with its purpose and security impact.
#
# Usage: sudo ./sysctl_hardening.sh [--apply|--check|--revert]
#
# Modes:
#   --apply    Apply all hardening settings
#   --check    Check current state against recommended settings
#   --revert   Revert to default values
#   --dry-run  Show what would be changed without applying
#

set -euo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-security-hardening.conf"
LOG_FILE="/var/log/sysctl_hardening.log"
DRY_RUN=0
MODE="check"

# ── Parse arguments ─────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)    MODE="apply"; shift ;;
        --check)    MODE="check"; shift ;;
        --revert)   MODE="revert"; shift ;;
        --dry-run)  DRY_RUN=1; MODE="apply"; shift ;;
        --help|-h)
            echo "Usage: $0 [--apply|--check|--revert] [--dry-run]"
            echo ""
            echo "Modes:"
            echo "  --apply    Apply all hardening settings (creates $SYSCTL_FILE)"
            echo "  --check    Check current settings against recommendations (default)"
            echo "  --revert   Remove hardening file and reload defaults"
            echo "  --dry-run  Show what would be changed without applying"
            echo ""
            echo "Must be run as root."
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $(id -u) -ne 0 ]]; then
    echo "ERROR: Must be run as root."
    exit 1
fi

# ── Hardening settings database ─────────────────────────────────
# Format: "sysctl_key|recommended_value|category|description|default_value"

SETTINGS=(
    # ── Kernel Memory Protection ──
    "kernel.kptr_restrict|2|memory|Hide kernel pointers from all users (prevents info leak)|0"
    "kernel.dmesg_restrict|1|memory|Restrict dmesg access to root only|0"
    "kernel.perf_event_paranoid|3|memory|Restrict perf events to root (prevent side-channel)|2"
    "kernel.unprivileged_bpf_disabled|1|memory|Disable unprivileged BPF (prevents BPF exploits)|0"
    "vm.unprivileged_userfaultfd|0|memory|Restrict userfaultfd to root (mitigates UAF exploits)|1"
    "kernel.randomize_va_space|2|memory|Full ASLR for all processes|2"

    # ── Process Protection ──
    "kernel.yama.ptrace_scope|2|process|Restrict ptrace to root/CAP_SYS_PTRACE only|1"
    "fs.suid_dumpable|0|process|Prevent core dumps from SUID programs|0"
    "kernel.sysrq|0|process|Disable Magic SysRq key (prevents kernel-level keystrokes)|176"
    "kernel.core_uses_pid|1|process|Append PID to core dump filenames|1"
    "fs.protected_hardlinks|1|process|Prevent hardlink-based privilege escalation|1"
    "fs.protected_symlinks|1|process|Prevent symlink-based race conditions|1"
    "fs.protected_fifos|2|process|Restrict FIFO creation in world-writable dirs|0"
    "fs.protected_regular|2|process|Restrict regular file creation in world-writable dirs|0"

    # ── IPv4 Network Hardening ──
    "net.ipv4.ip_forward|0|network|Disable IP forwarding (not a router)|1"
    "net.ipv4.conf.all.accept_source_route|0|network|Reject source-routed packets (prevent spoofing)|0"
    "net.ipv4.conf.default.accept_source_route|0|network|Default: reject source-routed packets|1"
    "net.ipv4.conf.all.accept_redirects|0|network|Ignore ICMP redirects (prevent route poisoning)|1"
    "net.ipv4.conf.default.accept_redirects|0|network|Default: ignore ICMP redirects|1"
    "net.ipv4.conf.all.secure_redirects|0|network|Ignore secure ICMP redirects|1"
    "net.ipv4.conf.default.secure_redirects|0|network|Default: ignore secure ICMP redirects|1"
    "net.ipv4.conf.all.send_redirects|0|network|Do not send ICMP redirects|1"
    "net.ipv4.conf.default.send_redirects|0|network|Default: do not send ICMP redirects|1"
    "net.ipv4.conf.all.rp_filter|1|network|Enable reverse path filtering (anti-spoofing)|0"
    "net.ipv4.conf.default.rp_filter|1|network|Default: enable reverse path filtering|0"
    "net.ipv4.conf.all.log_martians|1|network|Log packets with impossible addresses|0"
    "net.ipv4.conf.default.log_martians|1|network|Default: log martian packets|0"
    "net.ipv4.icmp_echo_ignore_broadcasts|1|network|Ignore broadcast ICMP (prevent smurf)|1"
    "net.ipv4.icmp_ignore_bogus_error_responses|1|network|Ignore bogus ICMP errors|1"
    "net.ipv4.tcp_syncookies|1|network|Enable SYN cookies (mitigate SYN flood)|1"
    "net.ipv4.tcp_syn_retries|3|network|Limit SYN retransmissions|6"
    "net.ipv4.tcp_synack_retries|2|network|Limit SYN-ACK retransmissions|5"
    "net.ipv4.tcp_max_syn_backlog|2048|network|Increase SYN backlog for DDoS resilience|128"
    "net.ipv4.tcp_rfc1337|1|network|Enable RFC 1337 fix (TIME-WAIT assassination)|0"

    # ── IPv6 Network Hardening ──
    "net.ipv6.conf.all.accept_redirects|0|network|IPv6: ignore redirects|1"
    "net.ipv6.conf.default.accept_redirects|0|network|IPv6 default: ignore redirects|1"
    "net.ipv6.conf.all.accept_source_route|0|network|IPv6: reject source routing|0"
    "net.ipv6.conf.default.accept_source_route|0|network|IPv6 default: reject source routing|0"
    "net.ipv6.conf.all.accept_ra|0|network|IPv6: ignore router advertisements|1"
    "net.ipv6.conf.default.accept_ra|0|network|IPv6 default: ignore router advertisements|1"
)

# ── Color output ────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Functions ───────────────────────────────────────────────────

get_current_value() {
    local key="$1"
    local path="/proc/sys/${key//\.//}"
    if [[ -f "$path" ]]; then
        cat "$path" 2>/dev/null || echo "N/A"
    else
        echo "N/A"
    fi
}

check_settings() {
    echo "============================================================"
    echo "  Sysctl Security Hardening Check"
    echo "  $(date)"
    echo "============================================================"
    echo ""

    local total=0
    local compliant=0
    local non_compliant=0
    local unavailable=0
    local prev_category=""

    for entry in "${SETTINGS[@]}"; do
        IFS='|' read -r key recommended category description default_val <<< "$entry"

        if [[ "$category" != "$prev_category" ]]; then
            echo ""
            echo "--- Category: ${category^^} ---"
            prev_category="$category"
        fi

        local current
        current=$(get_current_value "$key")
        total=$((total + 1))

        if [[ "$current" == "N/A" ]]; then
            printf "  ${YELLOW}[N/A]${NC}  %-45s (setting not available)\n" "$key"
            unavailable=$((unavailable + 1))
        elif [[ "$current" == "$recommended" ]]; then
            printf "  ${GREEN}[OK]${NC}   %-45s = %-5s (recommended: %s)\n" \
                "$key" "$current" "$recommended"
            compliant=$((compliant + 1))
        else
            printf "  ${RED}[FAIL]${NC} %-45s = %-5s (recommended: %s)\n" \
                "$key" "$current" "$recommended"
            printf "         %s\n" "$description"
            non_compliant=$((non_compliant + 1))
        fi
    done

    echo ""
    echo "============================================================"
    echo "  Summary:"
    echo "    Total settings:   $total"
    printf "    Compliant:        ${GREEN}%d${NC}\n" "$compliant"
    printf "    Non-compliant:    ${RED}%d${NC}\n" "$non_compliant"
    printf "    Unavailable:      ${YELLOW}%d${NC}\n" "$unavailable"
    echo ""
    local pct=$((compliant * 100 / total))
    echo "    Compliance: ${pct}%"
    echo "============================================================"

    if [[ $non_compliant -gt 0 ]]; then
        echo ""
        echo "To apply hardening: $0 --apply"
    fi
}

apply_settings() {
    echo "============================================================"
    echo "  Applying Sysctl Security Hardening"
    echo "  $(date)"
    echo "============================================================"
    echo ""

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "*** DRY RUN MODE - No changes will be made ***"
        echo ""
    fi

    # Create sysctl configuration file
    local tmpfile
    tmpfile=$(mktemp)

    cat > "$tmpfile" << 'HEADER'
#
# Security Hardening Sysctl Settings
# Auto-generated by sysctl_hardening.sh
# DO NOT EDIT MANUALLY - Use sysctl_hardening.sh to manage
#
HEADER
    echo "# Generated: $(date)" >> "$tmpfile"
    echo "# Hostname: $(hostname)" >> "$tmpfile"
    echo "#" >> "$tmpfile"

    local prev_category=""
    local applied=0
    local skipped=0

    for entry in "${SETTINGS[@]}"; do
        IFS='|' read -r key recommended category description default_val <<< "$entry"

        if [[ "$category" != "$prev_category" ]]; then
            echo "" >> "$tmpfile"
            echo "# --- ${category^^} ---" >> "$tmpfile"
            prev_category="$category"
        fi

        local current
        current=$(get_current_value "$key")

        echo "# $description" >> "$tmpfile"
        echo "# Default: $default_val" >> "$tmpfile"
        echo "$key = $recommended" >> "$tmpfile"

        if [[ "$current" != "$recommended" && "$current" != "N/A" ]]; then
            printf "  CHANGE: %-45s %s -> %s\n" "$key" "$current" "$recommended"
            applied=$((applied + 1))
        else
            printf "  OK:     %-45s = %s\n" "$key" "$recommended"
            skipped=$((skipped + 1))
        fi
    done

    echo ""
    echo "Settings to change: $applied"
    echo "Settings already OK: $skipped"
    echo ""

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "DRY RUN: Would write to $SYSCTL_FILE"
        echo "DRY RUN: Would run 'sysctl --system'"
        rm -f "$tmpfile"
        return
    fi

    # Install the configuration file
    cp "$tmpfile" "$SYSCTL_FILE"
    rm -f "$tmpfile"
    echo "Configuration written to: $SYSCTL_FILE"

    # Apply settings
    echo "Applying settings..."
    sysctl --system 2>&1 | grep -v "^$" | head -20

    # Log the action
    echo "$(date): sysctl hardening applied ($applied changes)" >> "$LOG_FILE"

    echo ""
    echo "Hardening applied successfully."
    echo "Run '$0 --check' to verify."
}

revert_settings() {
    echo "============================================================"
    echo "  Reverting Sysctl Hardening"
    echo "============================================================"
    echo ""

    if [[ -f "$SYSCTL_FILE" ]]; then
        echo "Removing: $SYSCTL_FILE"
        rm -f "$SYSCTL_FILE"
        echo "Reloading default sysctl settings..."
        sysctl --system 2>&1 | head -10
        echo ""
        echo "Hardening reverted. System will use default settings."
        echo "$(date): sysctl hardening reverted" >> "$LOG_FILE"
    else
        echo "No hardening file found at $SYSCTL_FILE"
        echo "Nothing to revert."
    fi
}

# ── Main ────────────────────────────────────────────────────────

case "$MODE" in
    check)  check_settings ;;
    apply)  apply_settings ;;
    revert) revert_settings ;;
    *)      echo "Unknown mode: $MODE"; exit 1 ;;
esac

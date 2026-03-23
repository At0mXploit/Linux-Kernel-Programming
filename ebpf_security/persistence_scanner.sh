#!/bin/bash
#
# persistence_scanner.sh - Scan for Common Persistence Mechanisms
# ================================================================
#
# This script scans for common persistence mechanisms on a Linux system
# including systemd services, udev rules, cron jobs, initramfs hooks,
# eBPF pins, kernel module configurations, and more.
#
#
# USAGE:
#   sudo ./persistence_scanner.sh [-v] [-o output_file]
#
#   -v  Verbose mode (show all entries, not just suspicious)
#   -o  Write results to output file (in addition to stdout)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VERBOSE=0
OUTPUT_FILE=""
ALERT_COUNT=0
TOTAL_ITEMS=0

# Parse arguments
while getopts "vo:h" opt; do
    case $opt in
        v) VERBOSE=1 ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h)
            echo "Usage: $0 [-v] [-o output_file]"
            echo ""
            echo "Scan for common persistence mechanisms."
            echo "  -v  Verbose mode"
            echo "  -o  Write results to file"
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

# Output function that handles both stdout and file
output() {
    echo -e "$@"
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "$@" | sed 's/\x1B\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

alert() {
    output "${RED}  [ALERT]${NC} $@"
    ALERT_COUNT=$((ALERT_COUNT + 1))
}

info() {
    output "${BLUE}  [INFO]${NC} $@"
    TOTAL_ITEMS=$((TOTAL_ITEMS + 1))
}

warn() {
    output "${YELLOW}  [WARN]${NC} $@"
}

ok() {
    if [ $VERBOSE -eq 1 ]; then
        output "${GREEN}  [OK]${NC} $@"
    fi
}

section() {
    output ""
    output "${BLUE}=== $@ ===${NC}"
    output ""
}

# Initialize output file
if [ -n "$OUTPUT_FILE" ]; then
    echo "Persistence Scanner Report - $(date)" > "$OUTPUT_FILE"
    echo "=================================" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    output "${RED}ERROR: This tool requires root privileges.${NC}"
    output "Run with: sudo $0"
    exit 1
fi

output "================================================================"
output "  Persistence Scanner - Defensive Security Audit Tool"
output "================================================================"
output "  Scan time: $(date)"
output "  Hostname:  $(hostname)"
output "  Kernel:    $(uname -r)"
output "================================================================"

# ========================================
# 1. systemd Services
# ========================================
section "1. systemd Services"

# Check for user-created services (not from packages)
if command -v systemctl &>/dev/null; then
    while IFS= read -r service_file; do
        if [ -f "$service_file" ]; then
            # Check if the file belongs to a package
            is_packaged=0
            if command -v dpkg &>/dev/null; then
                dpkg -S "$service_file" &>/dev/null && is_packaged=1
            elif command -v rpm &>/dev/null; then
                rpm -qf "$service_file" &>/dev/null && is_packaged=1
            fi

            if [ $is_packaged -eq 0 ]; then
                alert "Unpackaged systemd service: $service_file"
                if [ $VERBOSE -eq 1 ]; then
                    grep -E "^(ExecStart|ExecStartPre|ExecStartPost)=" \
                        "$service_file" 2>/dev/null | while read -r line; do
                        output "    $line"
                    done
                fi
            else
                ok "Packaged service: $service_file"
            fi
        fi
    done < <(find /etc/systemd/system/ -name "*.service" -type f 2>/dev/null)
else
    warn "systemctl not found, skipping systemd checks"
fi

# Check for systemd timers
output ""
output "  Checking systemd timers..."
find /etc/systemd/system/ -name "*.timer" -type f 2>/dev/null | while read -r timer; do
    info "Timer found: $timer"
done

# Check for systemd generators
output ""
output "  Checking systemd generators..."
for gendir in /etc/systemd/system-generators/ /etc/systemd/user-generators/; do
    if [ -d "$gendir" ]; then
        for gen in "$gendir"/*; do
            [ -f "$gen" ] && alert "Custom systemd generator: $gen"
        done
    fi
done

# Check for drop-in overrides
output ""
output "  Checking systemd drop-in overrides..."
find /etc/systemd/system/ -name "*.d" -type d 2>/dev/null | while read -r dropdir; do
    for override in "$dropdir"/*.conf; do
        [ -f "$override" ] && info "Drop-in override: $override"
    done
done

# ========================================
# 2. udev Rules
# ========================================
section "2. udev Rules"

for ruledir in /etc/udev/rules.d/ /usr/lib/udev/rules.d/; do
    if [ -d "$ruledir" ]; then
        for rule in "$ruledir"/*; do
            [ -f "$rule" ] || continue

            # Check for RUN directives
            if grep -q "RUN" "$rule" 2>/dev/null; then
                info "udev rule with RUN directive: $rule"
                if [ $VERBOSE -eq 1 ]; then
                    grep "RUN" "$rule" 2>/dev/null | while read -r line; do
                        output "    $line"
                    done
                fi
            fi

            # Check if packaged
            is_packaged=0
            if command -v dpkg &>/dev/null; then
                dpkg -S "$rule" &>/dev/null && is_packaged=1
            elif command -v rpm &>/dev/null; then
                rpm -qf "$rule" &>/dev/null && is_packaged=1
            fi

            if [ $is_packaged -eq 0 ] && [ "$ruledir" = "/etc/udev/rules.d/" ]; then
                alert "Unpackaged udev rule: $rule"
            fi
        done
    fi
done

# ========================================
# 3. Cron Jobs
# ========================================
section "3. Cron Jobs"

# System crontab
if [ -f /etc/crontab ]; then
    cron_entries=$(grep -v "^#" /etc/crontab 2>/dev/null | grep -v "^$" | wc -l)
    info "/etc/crontab has $cron_entries active entries"
fi

# cron.d directory
if [ -d /etc/cron.d/ ]; then
    for cronfile in /etc/cron.d/*; do
        [ -f "$cronfile" ] || continue
        is_packaged=0
        if command -v dpkg &>/dev/null; then
            dpkg -S "$cronfile" &>/dev/null && is_packaged=1
        fi
        if [ $is_packaged -eq 0 ]; then
            alert "Unpackaged cron.d entry: $cronfile"
        else
            ok "Packaged cron.d: $cronfile"
        fi
    done
fi

# Per-user crontabs
output ""
output "  Checking user crontabs..."
if [ -d /var/spool/cron/crontabs ]; then
    for usercron in /var/spool/cron/crontabs/*; do
        [ -f "$usercron" ] || continue
        user=$(basename "$usercron")
        entries=$(grep -v "^#" "$usercron" 2>/dev/null | grep -v "^$" | wc -l)
        info "User crontab for '$user': $entries entries"
    done
elif [ -d /var/spool/cron ]; then
    for usercron in /var/spool/cron/*; do
        [ -f "$usercron" ] || continue
        user=$(basename "$usercron")
        entries=$(grep -v "^#" "$usercron" 2>/dev/null | grep -v "^$" | wc -l)
        info "User crontab for '$user': $entries entries"
    done
fi

# at jobs
output ""
output "  Checking at jobs..."
if command -v atq &>/dev/null; then
    at_count=$(atq 2>/dev/null | wc -l)
    if [ "$at_count" -gt 0 ]; then
        info "$at_count pending at job(s)"
    fi
fi

# ========================================
# 4. initramfs Configuration
# ========================================
section "4. initramfs Configuration"

# initramfs-tools hooks
if [ -d /etc/initramfs-tools/hooks ]; then
    for hook in /etc/initramfs-tools/hooks/*; do
        [ -f "$hook" ] || continue
        is_packaged=0
        if command -v dpkg &>/dev/null; then
            dpkg -S "$hook" &>/dev/null && is_packaged=1
        fi
        if [ $is_packaged -eq 0 ]; then
            alert "Unpackaged initramfs hook: $hook"
        else
            ok "Packaged initramfs hook: $hook"
        fi
    done
fi

# initramfs scripts
for scriptdir in /etc/initramfs-tools/scripts/*/; do
    [ -d "$scriptdir" ] || continue
    for script in "$scriptdir"*; do
        [ -f "$script" ] || continue
        info "initramfs script: $script"
    done
done

# initramfs integrity
output ""
output "  Checking initramfs integrity..."
for initrd in /boot/initrd.img-* /boot/initramfs-*.img; do
    if [ -f "$initrd" ]; then
        sha=$(sha256sum "$initrd" 2>/dev/null | awk '{print $1}')
        info "initramfs: $initrd (SHA256: ${sha:0:16}...)"
    fi
done

# ========================================
# 5. eBPF Pins
# ========================================
section "5. eBPF Pins (/sys/fs/bpf/)"

if [ -d /sys/fs/bpf ]; then
    pin_count=0
    while IFS= read -r pin; do
        info "BPF pin: $pin"
        pin_count=$((pin_count + 1))
    done < <(find /sys/fs/bpf/ -type f 2>/dev/null)

    if [ $pin_count -eq 0 ]; then
        ok "No BPF pins found"
    else
        output "  Total BPF pins: $pin_count"
    fi

    # Check for BPF programs
    if command -v bpftool &>/dev/null; then
        output ""
        output "  Loaded BPF programs:"
        bpf_count=$(bpftool prog list 2>/dev/null | grep -c "^[0-9]" || true)
        info "$bpf_count BPF programs currently loaded"
    fi
else
    warn "/sys/fs/bpf not mounted"
fi

# ========================================
# 6. Kernel Module Configuration
# ========================================
section "6. Kernel Module Configuration"

# /etc/modules
if [ -f /etc/modules ]; then
    modules=$(grep -v "^#" /etc/modules 2>/dev/null | grep -v "^$" | wc -l)
    info "/etc/modules: $modules modules configured for auto-load"
fi

# modules-load.d
for modconf in /etc/modules-load.d/*.conf; do
    [ -f "$modconf" ] || continue
    info "Module load config: $modconf"
done

# modprobe.d install hooks (HIGH RISK)
output ""
output "  Checking modprobe.d for install hooks..."
for modprobe_conf in /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf; do
    [ -f "$modprobe_conf" ] || continue
    if grep -q "^install " "$modprobe_conf" 2>/dev/null; then
        alert "modprobe install hook found: $modprobe_conf"
        if [ $VERBOSE -eq 1 ]; then
            grep "^install " "$modprobe_conf" 2>/dev/null | while read -r line; do
                output "    $line"
            done
        fi
    fi
done

# DKMS modules
output ""
output "  Checking DKMS modules..."
if command -v dkms &>/dev/null; then
    dkms status 2>/dev/null | while read -r line; do
        info "DKMS module: $line"
    done
fi

# ========================================
# 7. SSH Configuration
# ========================================
section "7. SSH Authorized Keys"

for home in /root /home/*; do
    authkeys="$home/.ssh/authorized_keys"
    if [ -f "$authkeys" ]; then
        key_count=$(grep -c "^ssh-" "$authkeys" 2>/dev/null || true)
        info "$authkeys: $key_count key(s)"
    fi
done

# ========================================
# 8. LD_PRELOAD and Library Injection
# ========================================
section "8. LD_PRELOAD and Library Injection"

if [ -f /etc/ld.so.preload ]; then
    if [ -s /etc/ld.so.preload ]; then
        alert "/etc/ld.so.preload contains entries:"
        cat /etc/ld.so.preload | while read -r line; do
            output "    $line"
        done
    else
        ok "/etc/ld.so.preload is empty"
    fi
else
    ok "/etc/ld.so.preload does not exist"
fi

# Check for LD_PRELOAD in environment of running processes
output ""
output "  Checking process environments for LD_PRELOAD..."
for pid_dir in /proc/[0-9]*/; do
    pid=$(basename "$pid_dir")
    env_file="$pid_dir/environ"
    if [ -r "$env_file" ]; then
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q "^LD_PRELOAD="; then
            comm=$(cat "$pid_dir/comm" 2>/dev/null || echo "unknown")
            preload=$(tr '\0' '\n' < "$env_file" 2>/dev/null | grep "^LD_PRELOAD=")
            alert "PID $pid ($comm) has $preload"
        fi
    fi
done 2>/dev/null

# ========================================
# 9. PAM Configuration
# ========================================
section "9. PAM Configuration"

if [ -d /etc/pam.d ]; then
    for pamfile in /etc/pam.d/*; do
        [ -f "$pamfile" ] || continue
        is_packaged=0
        if command -v dpkg &>/dev/null; then
            dpkg -S "$pamfile" &>/dev/null && is_packaged=1
        fi
        if [ $is_packaged -eq 0 ]; then
            alert "Unpackaged PAM config: $pamfile"
        fi
    done
fi

# ========================================
# 10. Shell Profile Scripts
# ========================================
section "10. Shell Profiles"

for profile in /etc/profile.d/*.sh; do
    [ -f "$profile" ] || continue
    is_packaged=0
    if command -v dpkg &>/dev/null; then
        dpkg -S "$profile" &>/dev/null && is_packaged=1
    fi
    if [ $is_packaged -eq 0 ]; then
        warn "Unpackaged profile script: $profile"
    fi
done

# rc.local
if [ -f /etc/rc.local ] && [ -x /etc/rc.local ]; then
    if [ -s /etc/rc.local ]; then
        lines=$(grep -v "^#" /etc/rc.local 2>/dev/null | grep -v "^$" | \
                grep -v "^exit 0$" | wc -l)
        if [ "$lines" -gt 0 ]; then
            alert "/etc/rc.local contains $lines executable lines"
        fi
    fi
fi

# ========================================
# Summary
# ========================================
output ""
output "================================================================"
output "  SCAN COMPLETE"
output "================================================================"
output "  Total items checked:  $TOTAL_ITEMS"
output "  Alerts generated:     $ALERT_COUNT"
output ""

if [ $ALERT_COUNT -gt 0 ]; then
    output "${RED}  $ALERT_COUNT alert(s) require investigation.${NC}"
    output "  Review each ALERT above and verify legitimacy."
else
    output "${GREEN}  No alerts generated. System looks clean.${NC}"
fi

output "================================================================"

if [ -n "$OUTPUT_FILE" ]; then
    output "  Report saved to: $OUTPUT_FILE"
fi

exit 0

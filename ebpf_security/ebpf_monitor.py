#!/usr/bin/env python3
"""
ebpf_monitor.py - Monitor eBPF Program Loading Events
======================================================
This script uses BCC (BPF Compiler Collection) to monitor all eBPF program
loading events on the system. It attaches to the bpf() syscall and reports
when new BPF programs are loaded, providing visibility into potentially
malicious BPF activity.

USAGE:
    sudo python3 ebpf_monitor.py

REQUIREMENTS:
    - Python 3.6+
    - BCC (bpf compiler collection): apt install bpfcc-tools python3-bpfcc
    - Root privileges (CAP_SYS_ADMIN or CAP_BPF)

"""

import sys
import os
import time
import json
import signal
import argparse
from datetime import datetime

# Attempt to import BCC
try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC (BPF Compiler Collection) is not installed.")
    print("Install with: sudo apt install bpfcc-tools python3-bpfcc")
    print("Or: pip install bcc")
    print("")
    print("This script monitors eBPF program loading events for security purposes.")
    print("Without BCC, a simulated/fallback mode will be used for demonstration.")
    BPF = None

# BPF program types (from include/uapi/linux/bpf.h)
BPF_PROG_TYPES = {
    0:  "BPF_PROG_TYPE_UNSPEC",
    1:  "BPF_PROG_TYPE_SOCKET_FILTER",
    2:  "BPF_PROG_TYPE_KPROBE",
    3:  "BPF_PROG_TYPE_SCHED_CLS",
    4:  "BPF_PROG_TYPE_SCHED_ACT",
    5:  "BPF_PROG_TYPE_TRACEPOINT",
    6:  "BPF_PROG_TYPE_XDP",
    7:  "BPF_PROG_TYPE_PERF_EVENT",
    8:  "BPF_PROG_TYPE_CGROUP_SKB",
    9:  "BPF_PROG_TYPE_CGROUP_SOCK",
    10: "BPF_PROG_TYPE_LWT_IN",
    11: "BPF_PROG_TYPE_LWT_OUT",
    12: "BPF_PROG_TYPE_LWT_XMIT",
    13: "BPF_PROG_TYPE_SOCK_OPS",
    14: "BPF_PROG_TYPE_SK_SKB",
    15: "BPF_PROG_TYPE_CGROUP_DEVICE",
    16: "BPF_PROG_TYPE_SK_MSG",
    17: "BPF_PROG_TYPE_RAW_TRACEPOINT",
    18: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    19: "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    20: "BPF_PROG_TYPE_LIRC_MODE2",
    21: "BPF_PROG_TYPE_SK_REUSEPORT",
    22: "BPF_PROG_TYPE_FLOW_DISSECTOR",
    23: "BPF_PROG_TYPE_CGROUP_SYSCTL",
    24: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    25: "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    26: "BPF_PROG_TYPE_TRACING",
    27: "BPF_PROG_TYPE_STRUCT_OPS",
    28: "BPF_PROG_TYPE_EXT",
    29: "BPF_PROG_TYPE_LSM",
    30: "BPF_PROG_TYPE_SK_LOOKUP",
    31: "BPF_PROG_TYPE_SYSCALL",
}

# BPF commands (from include/uapi/linux/bpf.h)
BPF_COMMANDS = {
    0:  "BPF_MAP_CREATE",
    1:  "BPF_MAP_LOOKUP_ELEM",
    2:  "BPF_MAP_UPDATE_ELEM",
    3:  "BPF_MAP_DELETE_ELEM",
    4:  "BPF_MAP_GET_NEXT_KEY",
    5:  "BPF_PROG_LOAD",
    6:  "BPF_OBJ_PIN",
    7:  "BPF_OBJ_GET",
    8:  "BPF_PROG_ATTACH",
    9:  "BPF_PROG_DETACH",
    10: "BPF_PROG_TEST_RUN",
    11: "BPF_PROG_GET_NEXT_ID",
    12: "BPF_MAP_GET_NEXT_ID",
    13: "BPF_PROG_GET_FD_BY_ID",
    14: "BPF_MAP_GET_FD_BY_ID",
    15: "BPF_OBJ_GET_INFO_BY_FD",
    16: "BPF_PROG_QUERY",
    17: "BPF_RAW_TRACEPOINT_OPEN",
    18: "BPF_BTF_LOAD",
    19: "BPF_BTF_GET_FD_BY_ID",
    20: "BPF_TASK_FD_QUERY",
    21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
    22: "BPF_MAP_FREEZE",
    23: "BPF_BTF_GET_NEXT_ID",
    24: "BPF_MAP_LOOKUP_BATCH",
    25: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
    26: "BPF_MAP_UPDATE_BATCH",
    27: "BPF_MAP_DELETE_BATCH",
    28: "BPF_LINK_CREATE",
    29: "BPF_LINK_UPDATE",
    30: "BPF_LINK_GET_FD_BY_ID",
    31: "BPF_LINK_GET_NEXT_ID",
    32: "BPF_ENABLE_STATS",
    33: "BPF_ITER_CREATE",
    34: "BPF_LINK_DETACH",
    35: "BPF_PROG_BIND_MAP",
}

# High-risk BPF program types that warrant extra scrutiny
HIGH_RISK_PROG_TYPES = {
    2,   # KPROBE - can hook any kernel function
    26,  # TRACING (fentry/fexit) - modern kprobe, can modify returns
    29,  # LSM - can override security policies
    6,   # XDP - can drop/redirect packets
    3,   # SCHED_CLS (TC) - can manipulate traffic
}

# High-risk BPF commands
HIGH_RISK_COMMANDS = {
    5,   # BPF_PROG_LOAD - loading new programs
    8,   # BPF_PROG_ATTACH - attaching to hooks
    6,   # BPF_OBJ_PIN - persisting objects
    28,  # BPF_LINK_CREATE - creating links
}

# BPF C program for tracing bpf() syscall
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Event structure for communicating with userspace
struct bpf_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    u32 bpf_cmd;
    u32 prog_type;
    int ret;
    char comm[16];
};

// Ring buffer for events (or perf buffer for older kernels)
BPF_PERF_OUTPUT(events);

// Hash map to store entry arguments (keyed by pid_tgid)
BPF_HASH(entry_args, u64, u32);
BPF_HASH(entry_prog_type, u64, u32);

// Trace bpf() syscall entry
// Syscall signature: int bpf(int cmd, union bpf_attr *attr, unsigned int size)
TRACEPOINT_PROBE(syscalls, sys_enter_bpf)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 cmd = (u32)args->cmd;

    // Store the command for use in the exit probe
    entry_args.update(&pid_tgid, &cmd);

    // Try to extract prog_type if this is a PROG_LOAD command
    if (cmd == 5) {  // BPF_PROG_LOAD
        // args->uattr is the union bpf_attr pointer
        // prog_type is the first field
        u32 prog_type = 0;
        bpf_probe_read_user(&prog_type, sizeof(prog_type),
                            (void *)args->uattr);
        entry_prog_type.update(&pid_tgid, &prog_type);
    }

    return 0;
}

// Trace bpf() syscall exit
TRACEPOINT_PROBE(syscalls, sys_exit_bpf)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Retrieve the command from entry
    u32 *cmd_ptr = entry_args.lookup(&pid_tgid);
    if (!cmd_ptr)
        return 0;

    u32 cmd = *cmd_ptr;
    entry_args.delete(&pid_tgid);

    // Build the event
    struct bpf_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.bpf_cmd = cmd;
    event.ret = (int)args->ret;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Get prog_type if available
    u32 *prog_type_ptr = entry_prog_type.lookup(&pid_tgid);
    if (prog_type_ptr) {
        event.prog_type = *prog_type_ptr;
        entry_prog_type.delete(&pid_tgid);
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class BPFEventLogger:
    """Logs and analyzes BPF events for security monitoring."""

    def __init__(self, log_file=None, alert_high_risk=True, json_output=False):
        self.log_file = log_file
        self.alert_high_risk = alert_high_risk
        self.json_output = json_output
        self.event_count = 0
        self.alert_count = 0
        self.start_time = datetime.now()

        if log_file:
            self.log_fd = open(log_file, 'a')
        else:
            self.log_fd = None

    def process_event(self, cpu, data, size):
        """Process a single BPF event from the kernel."""
        # This would be called by BCC's perf_buffer callback
        # For now, we define the expected interface
        pass

    def format_event(self, timestamp, pid, uid, comm, cmd, prog_type, ret):
        """Format a BPF event for display."""
        cmd_name = BPF_COMMANDS.get(cmd, f"UNKNOWN({cmd})")
        prog_type_name = BPF_PROG_TYPES.get(prog_type, f"UNKNOWN({prog_type})")

        is_high_risk = (cmd in HIGH_RISK_COMMANDS or
                        prog_type in HIGH_RISK_PROG_TYPES)

        ts_str = datetime.fromtimestamp(timestamp / 1e9).strftime('%H:%M:%S.%f')
        status = "OK" if ret >= 0 else f"ERR({ret})"

        if self.json_output:
            event = {
                "timestamp": ts_str,
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "command": cmd_name,
                "prog_type": prog_type_name if cmd == 5 else "N/A",
                "return": ret,
                "status": status,
                "high_risk": is_high_risk,
            }
            return json.dumps(event)
        else:
            risk_marker = " [HIGH RISK]" if is_high_risk else ""
            prog_info = f" prog_type={prog_type_name}" if cmd == 5 else ""
            return (f"[{ts_str}] PID={pid:<6} UID={uid:<5} "
                    f"COMM={comm:<16} CMD={cmd_name:<30} "
                    f"{status}{prog_info}{risk_marker}")

    def log(self, message):
        """Write message to log file and/or stdout."""
        print(message)
        if self.log_fd:
            self.log_fd.write(message + '\n')
            self.log_fd.flush()

    def print_summary(self):
        """Print session summary."""
        elapsed = datetime.now() - self.start_time
        print(f"\n{'='*70}")
        print(f"Session Summary")
        print(f"{'='*70}")
        print(f"Duration:     {elapsed}")
        print(f"Total events: {self.event_count}")
        print(f"Alerts:       {self.alert_count}")
        print(f"{'='*70}")

    def close(self):
        """Clean up resources."""
        if self.log_fd:
            self.log_fd.close()


def run_with_bcc(args):
    """Run the monitor using BCC (requires root and BCC installation)."""
    logger = BPFEventLogger(
        log_file=args.log_file,
        alert_high_risk=args.alert,
        json_output=args.json
    )

    print("="*70)
    print("eBPF Program Loading Monitor (Defensive Security Tool)")
    print("="*70)
    print(f"Start time: {datetime.now().isoformat()}")
    print(f"Log file:   {args.log_file or 'stdout only'}")
    print(f"JSON mode:  {args.json}")
    print(f"Alerts:     {args.alert}")
    print("="*70)
    print("")

    # Load BPF program
    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        print(f"ERROR: Failed to load BPF program: {e}")
        print("Ensure you are running as root with BCC installed.")
        sys.exit(1)

    # Define callback for perf events
    def handle_event(cpu, data, size):
        event = b["events"].event(data)

        timestamp = event.timestamp
        pid = event.pid
        uid = event.uid
        comm = event.comm.decode('utf-8', errors='replace')
        cmd = event.bpf_cmd
        prog_type = event.prog_type
        ret = event.ret

        formatted = logger.format_event(
            timestamp, pid, uid, comm, cmd, prog_type, ret
        )
        logger.log(formatted)
        logger.event_count += 1

        # Check for high-risk events
        if args.alert and (cmd in HIGH_RISK_COMMANDS or
                           prog_type in HIGH_RISK_PROG_TYPES):
            logger.alert_count += 1
            alert_msg = (f"  ALERT: High-risk BPF operation detected! "
                         f"PID={pid} CMD={BPF_COMMANDS.get(cmd, cmd)}")
            if cmd == 5:
                alert_msg += (f" TYPE="
                              f"{BPF_PROG_TYPES.get(prog_type, prog_type)}")
            logger.log(alert_msg)

    # Open perf buffer
    b["events"].open_perf_buffer(handle_event)

    print("Monitoring bpf() syscall... Press Ctrl+C to stop.\n")
    print(f"{'Timestamp':<20} {'PID':<8} {'UID':<7} {'Command':<16} "
          f"{'BPF Command':<32} Status")
    print("-"*100)

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    logger.print_summary()
    logger.close()


def run_fallback_mode(args):
    """
    Fallback mode when BCC is not available.
    Uses /proc and bpftool to periodically check for new BPF programs.
    """
    logger = BPFEventLogger(
        log_file=args.log_file,
        alert_high_risk=args.alert,
        json_output=args.json
    )

    print("="*70)
    print("eBPF Monitor - Fallback Mode (polling)")
    print("="*70)
    print("BCC not available. Using periodic bpftool polling instead.")
    print(f"Poll interval: {args.interval} seconds")
    print("="*70)
    print("")

    import subprocess

    known_progs = set()

    def get_bpf_progs():
        """Get list of loaded BPF programs using bpftool."""
        try:
            result = subprocess.run(
                ["bpftool", "prog", "list", "--json"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None

    def get_bpf_progs_proc():
        """Fallback: scan /proc for BPF file descriptors."""
        bpf_procs = []
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                fd_dir = f'/proc/{pid_dir}/fd'
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f'{fd_dir}/{fd}')
                            if 'bpf-prog' in link or 'bpf-map' in link:
                                try:
                                    with open(f'/proc/{pid_dir}/comm') as f:
                                        comm = f.read().strip()
                                except (IOError, OSError):
                                    comm = "unknown"
                                bpf_procs.append({
                                    'pid': int(pid_dir),
                                    'fd': fd,
                                    'type': link,
                                    'comm': comm
                                })
                        except (OSError, IOError):
                            continue
                except (OSError, IOError):
                    continue
        except (OSError, IOError):
            pass
        return bpf_procs

    print("Performing initial BPF program scan...\n")

    # Initial scan
    progs = get_bpf_progs()
    if progs is not None:
        print(f"Found {len(progs)} loaded BPF programs:")
        for prog in progs:
            prog_id = prog.get('id', 'N/A')
            prog_type = prog.get('type', 'unknown')
            prog_name = prog.get('name', 'unnamed')
            known_progs.add(prog_id)
            risk = " [HIGH RISK]" if prog_type in (
                'kprobe', 'tracing', 'lsm', 'xdp', 'sched_cls'
            ) else ""
            print(f"  ID={prog_id:<6} TYPE={prog_type:<20} "
                  f"NAME={prog_name}{risk}")
        print("")
    else:
        print("bpftool not available. Using /proc scanning fallback.\n")
        bpf_procs = get_bpf_progs_proc()
        print(f"Found {len(bpf_procs)} processes with BPF file descriptors:")
        for p in bpf_procs:
            print(f"  PID={p['pid']:<6} COMM={p['comm']:<16} FD={p['fd']} "
                  f"TYPE={p['type']}")
        print("")

    print(f"Monitoring for changes (polling every {args.interval}s)... "
          f"Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(args.interval)
            timestamp = datetime.now().strftime('%H:%M:%S.%f')

            progs = get_bpf_progs()
            if progs is not None:
                current_ids = {p.get('id') for p in progs}

                # Detect new programs
                new_ids = current_ids - known_progs
                for prog in progs:
                    if prog.get('id') in new_ids:
                        prog_id = prog.get('id')
                        prog_type = prog.get('type', 'unknown')
                        prog_name = prog.get('name', 'unnamed')
                        is_high_risk = prog_type in (
                            'kprobe', 'tracing', 'lsm', 'xdp', 'sched_cls'
                        )
                        risk = " [HIGH RISK]" if is_high_risk else ""

                        msg = (f"[{timestamp}] NEW BPF PROGRAM: ID={prog_id} "
                               f"TYPE={prog_type} NAME={prog_name}{risk}")
                        logger.log(msg)
                        logger.event_count += 1

                        if is_high_risk and args.alert:
                            logger.alert_count += 1
                            logger.log(f"  ALERT: High-risk BPF program loaded!")

                # Detect removed programs
                removed_ids = known_progs - current_ids
                for prog_id in removed_ids:
                    msg = (f"[{timestamp}] BPF PROGRAM REMOVED: ID={prog_id}")
                    logger.log(msg)
                    logger.event_count += 1

                known_progs.clear()
                known_progs.update(current_ids)

    except KeyboardInterrupt:
        pass

    logger.print_summary()
    logger.close()


def main():
    parser = argparse.ArgumentParser(
        description='eBPF Program Loading Monitor - Defensive Security Tool',
        epilog='This tool monitors all BPF operations for security analysis.'
    )
    parser.add_argument(
        '-l', '--log-file',
        help='Write events to log file (in addition to stdout)'
    )
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Output events in JSON format'
    )
    parser.add_argument(
        '-a', '--alert',
        action='store_true',
        default=True,
        help='Alert on high-risk BPF operations (default: enabled)'
    )
    parser.add_argument(
        '--no-alert',
        action='store_true',
        help='Disable high-risk alerts'
    )
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Polling interval in seconds for fallback mode (default: 5)'
    )

    args = parser.parse_args()
    if args.no_alert:
        args.alert = False

    # Check for root privileges
    if os.geteuid() != 0:
        print("WARNING: This tool requires root privileges for full functionality.")
        print("Some features may not work without root access.")
        print("")

    # Try BCC mode first, fall back to polling mode
    if BPF is not None and os.geteuid() == 0:
        run_with_bcc(args)
    else:
        run_fallback_mode(args)


if __name__ == '__main__':
    main()

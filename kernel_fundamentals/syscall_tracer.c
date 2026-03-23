/*
 * syscall_tracer.c - Trace system calls of a child process using ptrace
 *
 * This program demonstrates the ptrace system call to intercept and log
 * all system calls made by a child process. It shows:
 *   - Process creation with fork()
 *   - ptrace PTRACE_TRACEME, PTRACE_SYSCALL, PTRACE_GETREGS
 *   - System call entry/exit detection
 *   - Register inspection for syscall number and arguments
 *
 * Compile: gcc -Wall -Wextra -o syscall_tracer syscall_tracer.c
 * Usage:   ./syscall_tracer <command> [args...]
 * Example: ./syscall_tracer /bin/ls /tmp
 *
 * Related: Lesson 4 (Syscalls - Complete Execution Path)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

/*
 * Syscall name table for common x86_64 system calls.
 * A production tracer would use a complete table or read from
 * /usr/include/asm/unistd_64.h, but we include the most common ones here.
 */
static const char *syscall_names[] = {
    [0]   = "read",
    [1]   = "write",
    [2]   = "open",
    [3]   = "close",
    [4]   = "stat",
    [5]   = "fstat",
    [6]   = "lstat",
    [7]   = "poll",
    [8]   = "lseek",
    [9]   = "mmap",
    [10]  = "mprotect",
    [11]  = "munmap",
    [12]  = "brk",
    [13]  = "rt_sigaction",
    [14]  = "rt_sigprocmask",
    [15]  = "rt_sigreturn",
    [16]  = "ioctl",
    [17]  = "pread64",
    [18]  = "pwrite64",
    [19]  = "readv",
    [20]  = "writev",
    [21]  = "access",
    [22]  = "pipe",
    [23]  = "select",
    [24]  = "sched_yield",
    [25]  = "mremap",
    [32]  = "dup",
    [33]  = "dup2",
    [35]  = "nanosleep",
    [39]  = "getpid",
    [41]  = "socket",
    [42]  = "connect",
    [43]  = "accept",
    [44]  = "sendto",
    [45]  = "recvfrom",
    [56]  = "clone",
    [57]  = "fork",
    [58]  = "vfork",
    [59]  = "execve",
    [60]  = "exit",
    [61]  = "wait4",
    [62]  = "kill",
    [63]  = "uname",
    [72]  = "fcntl",
    [78]  = "getdents",
    [79]  = "getcwd",
    [80]  = "chdir",
    [83]  = "mkdir",
    [84]  = "rmdir",
    [87]  = "unlink",
    [89]  = "readlink",
    [96]  = "gettimeofday",
    [97]  = "getrlimit",
    [99]  = "sysinfo",
    [102] = "getuid",
    [104] = "getgid",
    [110] = "getppid",
    [158] = "arch_prctl",
    [186] = "gettid",
    [217] = "getdents64",
    [218] = "set_tid_address",
    [228] = "clock_gettime",
    [231] = "exit_group",
    [257] = "openat",
    [262] = "newfstatat",
    [302] = "prlimit64",
    [318] = "getrandom",
    [332] = "statx",
    [334] = "rseq",
};

#define SYSCALL_TABLE_SIZE (sizeof(syscall_names) / sizeof(syscall_names[0]))

/*
 * get_syscall_name - Look up the name for a syscall number
 * @num: The syscall number (from RAX register)
 *
 * Returns a human-readable name or "unknown".
 */
static const char *get_syscall_name(long num)
{
    if (num >= 0 && (size_t)num < SYSCALL_TABLE_SIZE && syscall_names[num])
        return syscall_names[num];
    return "unknown";
}

/*
 * trace_child - Main tracing loop for the child process
 * @child_pid: PID of the child process being traced
 *
 * Uses PTRACE_SYSCALL to stop the child at every syscall entry and exit.
 * On entry, we read the syscall number and arguments from registers.
 * On exit, we read the return value.
 */
static void trace_child(pid_t child_pid)
{
    int status;
    int in_syscall = 0;  /* Toggle: 0 = entering syscall, 1 = exiting */
    unsigned long syscall_count = 0;
    unsigned long error_count = 0;

    /* Wait for child to stop at first execve */
    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status)) {
        fprintf(stderr, "Child exited before tracing started.\n");
        return;
    }

    /* Set options: trace child forks and exec */
    ptrace(PTRACE_SETOPTIONS, child_pid, 0,
           PTRACE_O_TRACESYSGOOD |  /* Set bit 7 of signal on syscall stops */
           PTRACE_O_TRACEEXEC);     /* Stop at exec */

    /* Resume child, stop at next syscall entry/exit */
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);

    fprintf(stderr, "--- Tracing PID %d ---\n\n", child_pid);
    fprintf(stderr, "%-6s %-20s %-18s %-18s %-18s -> %s\n",
            "NUM", "SYSCALL", "ARG1", "ARG2", "ARG3", "RETURN");
    fprintf(stderr, "%-6s %-20s %-18s %-18s %-18s    %s\n",
            "---", "-------", "----", "----", "----", "------");

    while (1) {
        waitpid(child_pid, &status, 0);

        /* Check if child has exited */
        if (WIFEXITED(status)) {
            fprintf(stderr, "\n--- Child exited with status %d ---\n",
                    WEXITSTATUS(status));
            break;
        }

        /* Check if child was killed by a signal */
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "\n--- Child killed by signal %d ---\n",
                    WTERMSIG(status));
            break;
        }

        /* Check if stopped by a syscall (bit 7 set due to TRACESYSGOOD) */
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
            struct user_regs_struct regs;

            if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
                perror("ptrace GETREGS");
                break;
            }

            if (!in_syscall) {
                /*
                 * Syscall ENTRY:
                 * RAX = syscall number (orig_rax holds the original value)
                 * RDI = arg1, RSI = arg2, RDX = arg3
                 * R10 = arg4, R8  = arg5, R9  = arg6
                 */
                fprintf(stderr, "%-6lld %-20s 0x%-16llx 0x%-16llx 0x%-16llx",
                        (long long)regs.orig_rax,
                        get_syscall_name(regs.orig_rax),
                        (unsigned long long)regs.rdi,
                        (unsigned long long)regs.rsi,
                        (unsigned long long)regs.rdx);
                in_syscall = 1;
            } else {
                /*
                 * Syscall EXIT:
                 * RAX = return value (negative = error)
                 */
                long ret = (long)regs.rax;
                if (ret < 0 && ret >= -4095) {
                    fprintf(stderr, " -> -1 (errno %ld: %s)\n",
                            -ret, strerror((int)(-ret)));
                    error_count++;
                } else {
                    fprintf(stderr, " -> 0x%llx (%lld)\n",
                            (unsigned long long)regs.rax,
                            (long long)regs.rax);
                }
                in_syscall = 0;
                syscall_count++;
            }
        } else if (WIFSTOPPED(status)) {
            /* Stopped by a signal other than syscall -- deliver it */
            int sig = WSTOPSIG(status);
            ptrace(PTRACE_SYSCALL, child_pid, 0, sig);
            continue;
        }

        /* Resume and wait for next syscall */
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    }

    /* Print summary */
    fprintf(stderr, "\n=== Summary ===\n");
    fprintf(stderr, "Total syscalls:  %lu\n", syscall_count);
    fprintf(stderr, "Errors:          %lu\n", error_count);
}

/*
 * main - Entry point
 *
 * Forks a child process, the child requests to be traced and execs the
 * target command. The parent enters the trace loop.
 */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s /bin/ls -la /tmp\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /*
         * CHILD PROCESS
         *
         * PTRACE_TRACEME tells the kernel: "my parent is tracing me."
         * The child will stop at the next exec() and at every signal.
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
            _exit(1);
        }

        /* Stop ourselves so parent can set up tracing options */
        raise(SIGSTOP);

        /* Execute the target command */
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(1);
    }

    /*
     * PARENT PROCESS
     * Wait for child to stop (from SIGSTOP), then trace.
     */
    trace_child(child);

    return 0;
}

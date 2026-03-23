/*
 * custom_syscall_user.c - Invoke system calls directly using syscall()
 *
 * This program demonstrates bypassing glibc wrappers and invoking system
 * calls directly via the syscall() function. This is useful when:
 *   - A syscall has no glibc wrapper (e.g., newer syscalls)
 *   - You want to measure raw syscall overhead
 *   - You need to understand the exact syscall interface
 *
 * Compile: gcc -Wall -Wextra -O2 -o custom_syscall_user custom_syscall_user.c
 * Usage:   ./custom_syscall_user
 *
 * Related: Lesson 4 (Syscalls - Complete Execution Path)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

/*
 * demo_getpid - Compare glibc getpid() vs direct syscall
 *
 * glibc caches getpid() after the first call, so subsequent calls
 * don't actually enter the kernel. syscall(SYS_getpid) always enters.
 */
static void demo_getpid(void)
{
    printf("--- 1. getpid: glibc vs direct syscall ---\n\n");

    /* glibc version (may be cached) */
    pid_t pid_glibc = getpid();

    /* Direct syscall (always enters kernel) */
    pid_t pid_direct = syscall(SYS_getpid);

    printf("  glibc getpid():       %d\n", pid_glibc);
    printf("  syscall(SYS_getpid):  %d\n", pid_direct);
    printf("  Match: %s\n\n", (pid_glibc == pid_direct) ? "YES" : "NO");
}

/*
 * demo_gettid - Get thread ID (no traditional glibc wrapper)
 *
 * gettid() was historically missing from glibc (added in glibc 2.30).
 * Using syscall() was the only way to get the thread ID.
 */
static void demo_gettid(void)
{
    printf("--- 2. gettid: Thread ID ---\n\n");

    pid_t tid = syscall(SYS_gettid);
    pid_t pid = syscall(SYS_getpid);

    printf("  PID (process ID): %d\n", pid);
    printf("  TID (thread ID):  %d\n", tid);
    printf("  Same thread group: %s\n", (pid == tid) ? "YES (main thread)" : "NO");
    printf("  In the kernel: pid != tid for non-leader threads in a thread group\n\n");
}

/*
 * demo_write - Direct write() syscall
 *
 * Demonstrates the register convention:
 *   RAX = 1 (SYS_write)
 *   RDI = fd (1 = stdout)
 *   RSI = buffer pointer
 *   RDX = count
 */
static void demo_write(void)
{
    printf("--- 3. write: Direct file I/O ---\n\n");

    const char msg[] = "  >> This line was written by syscall(SYS_write)!\n";

    /*
     * syscall(SYS_write, fd, buf, count)
     * Returns number of bytes written, or -1 on error (errno set)
     */
    ssize_t ret = syscall(SYS_write, STDOUT_FILENO, msg, strlen(msg));
    printf("  Bytes written: %zd\n\n", ret);
}

/*
 * demo_uname - Get system information via direct syscall
 */
static void demo_uname(void)
{
    printf("--- 4. uname: System information ---\n\n");

    struct utsname uts;

    /* Direct syscall */
    long ret = syscall(SYS_uname, &uts);
    if (ret == 0) {
        printf("  System name:  %s\n", uts.sysname);
        printf("  Node name:    %s\n", uts.nodename);
        printf("  Release:      %s\n", uts.release);
        printf("  Version:      %s\n", uts.version);
        printf("  Machine:      %s\n", uts.machine);
    } else {
        printf("  syscall(SYS_uname) failed: %s\n", strerror(errno));
    }
    printf("\n");
}

/*
 * demo_openat_read_close - File operations via direct syscalls
 *
 * Modern Linux uses openat() (AT_FDCWD) instead of open().
 * This demonstrates a complete read-file operation using only syscall().
 */
static void demo_openat_read_close(void)
{
    printf("--- 5. openat/read/close: File I/O without glibc wrappers ---\n\n");

    char buf[256];
    memset(buf, 0, sizeof(buf));

    /*
     * SYS_openat(dirfd, pathname, flags, mode)
     * AT_FDCWD means "relative to current directory" (like plain open())
     */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/version", O_RDONLY, 0);
    if (fd < 0) {
        printf("  openat failed: %s\n\n", strerror(errno));
        return;
    }
    printf("  openat(\"/proc/version\") = fd %d\n", fd);

    /* SYS_read(fd, buf, count) */
    ssize_t n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("  read() returned %zd bytes\n", n);
        printf("  Content: %.80s...\n", buf);
    }

    /* SYS_close(fd) */
    syscall(SYS_close, fd);
    printf("  close(fd=%d) done\n\n", fd);
}

/*
 * demo_clock_gettime - Compare vDSO vs actual syscall performance
 *
 * clock_gettime() is typically serviced by the vDSO (no kernel entry).
 * Using syscall() forces actual kernel entry, which is much slower.
 */
static void demo_clock_gettime(void)
{
    printf("--- 6. clock_gettime: vDSO vs actual syscall performance ---\n\n");

    struct timespec ts;
    int iterations = 1000000;

    /* Warm up */
    for (int i = 0; i < 1000; i++)
        clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Measure glibc/vDSO version */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++)
        clock_gettime(CLOCK_MONOTONIC, &ts);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double vdso_ns = ((end.tv_sec - start.tv_sec) * 1e9 +
                      (end.tv_nsec - start.tv_nsec)) / iterations;

    /* Measure direct syscall version */
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++)
        syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double syscall_ns = ((end.tv_sec - start.tv_sec) * 1e9 +
                         (end.tv_nsec - start.tv_nsec)) / iterations;

    printf("  glibc (vDSO) clock_gettime:  %.1f ns/call\n", vdso_ns);
    printf("  syscall() clock_gettime:     %.1f ns/call\n", syscall_ns);
    printf("  Speedup from vDSO:           %.1fx\n",
           syscall_ns / vdso_ns);
    printf("  vDSO avoids kernel entry entirely for read-only time queries.\n\n");
}

/*
 * demo_getpid_benchmark - Measure raw syscall overhead
 */
static void demo_getpid_benchmark(void)
{
    printf("--- 7. Syscall overhead benchmark (getpid) ---\n\n");

    int iterations = 2000000;
    struct timespec start, end;

    /* Warm up */
    for (int i = 0; i < 10000; i++)
        syscall(SYS_getpid);

    /* Measure */
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++)
        syscall(SYS_getpid);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) * 1e9 +
                     (end.tv_nsec - start.tv_nsec);
    double per_call = elapsed / iterations;

    printf("  Iterations:      %d\n", iterations);
    printf("  Total time:      %.3f ms\n", elapsed / 1e6);
    printf("  Per syscall:     %.1f ns\n", per_call);
    printf("  Syscalls/second: %.0f\n\n", 1e9 / per_call);

    printf("  Note: This overhead includes KPTI (Meltdown mitigation) and\n");
    printf("  Spectre mitigations. On older/unpatched kernels, it would be faster.\n\n");
}

/*
 * demo_error_handling - Show how syscall errors work
 */
static void demo_error_handling(void)
{
    printf("--- 8. Error handling: errno from direct syscalls ---\n\n");

    /* Try to open a non-existent file */
    long ret = syscall(SYS_openat, AT_FDCWD, "/nonexistent/file",
                       O_RDONLY, 0);
    printf("  syscall(openat, \"/nonexistent/file\") = %ld\n", ret);
    printf("  errno = %d (%s)\n\n", errno, strerror(errno));

    /* Try to kill a non-existent process */
    ret = syscall(SYS_kill, 99999999, 0);
    printf("  syscall(kill, 99999999, 0) = %ld\n", ret);
    printf("  errno = %d (%s)\n\n", errno, strerror(errno));

    /* Try an invalid syscall number */
    errno = 0;
    ret = syscall(9999);
    printf("  syscall(9999) = %ld\n", ret);
    printf("  errno = %d (%s)\n\n", errno, strerror(errno));

    printf("  Convention: negative return values in range [-1, -4095] indicate errors.\n");
    printf("  glibc translates: sets errno = |return_value|, returns -1.\n\n");
}

/*
 * demo_getrandom - Modern syscall (added in 3.17)
 */
static void demo_getrandom(void)
{
    printf("--- 9. getrandom: Modern syscall example ---\n\n");

    unsigned char buf[16];

    /*
     * SYS_getrandom(buf, buflen, flags)
     * flags: 0 = /dev/urandom equivalent (non-blocking after init)
     */
    ssize_t ret = syscall(SYS_getrandom, buf, sizeof(buf), 0);
    if (ret < 0) {
        printf("  getrandom failed: %s\n", strerror(errno));
        return;
    }

    printf("  getrandom() returned %zd random bytes:\n  ", ret);
    for (int i = 0; i < (int)ret; i++)
        printf("%02x ", buf[i]);
    printf("\n\n");
}

int main(void)
{
    printf("=============================================\n");
    printf("  Direct System Call Invocation Demo\n");
    printf("=============================================\n\n");

    printf("  This program calls kernel system calls directly\n");
    printf("  using syscall() instead of glibc wrappers.\n\n");

    demo_getpid();
    demo_gettid();
    demo_write();
    demo_uname();
    demo_openat_read_close();
    demo_clock_gettime();
    demo_getpid_benchmark();
    demo_error_handling();
    demo_getrandom();

    printf("=============================================\n");
    printf("  All demos complete.\n");
    printf("=============================================\n");

    return 0;
}

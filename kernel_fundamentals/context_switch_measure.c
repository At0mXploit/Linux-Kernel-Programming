/*
 * context_switch_measure.c - Benchmark context switch time using pipes
 *
 * This program measures the cost of a context switch by having two processes
 * (or threads) ping-pong a byte through a pair of pipes. Each round-trip
 * requires two context switches (sender->receiver, receiver->sender).
 *
 * Method:
 *   1. Create two pipes: pipe_a (parent->child) and pipe_b (child->parent)
 *   2. Fork a child process
 *   3. Parent writes 1 byte to pipe_a, reads 1 byte from pipe_b
 *   4. Child reads 1 byte from pipe_a, writes 1 byte to pipe_b
 *   5. Measure the time for N round trips
 *   6. Each round trip = 2 context switches
 *
 * Compile: gcc -Wall -Wextra -O2 -o context_switch_measure context_switch_measure.c
 * Usage:   ./context_switch_measure [iterations] [pin_cpus]
 *          iterations: number of round trips (default: 100000)
 *          pin_cpus:   1 to pin both processes to CPU 0 (default: 0)
 *
 * With CPU pinning, we force context switches (not parallel execution).
 * Without pinning, on multi-core systems, processes may run in parallel.
 *
 * Related: Lesson 6 (Scheduler - CFS, Runqueues, Priorities)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>

/* Default number of round-trip iterations */
#define DEFAULT_ITERATIONS 100000

/*
 * pin_to_cpu - Pin the current process to a specific CPU core
 * @cpu: CPU number to pin to
 *
 * Returns 0 on success, -1 on failure.
 * When both parent and child are pinned to the same CPU, every read/write
 * pair forces a real context switch (the scheduler must swap processes).
 */
static int pin_to_cpu(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
        return -1;
    }
    return 0;
}

/*
 * get_time_ns - Get current time in nanoseconds (monotonic clock)
 *
 * Uses CLOCK_MONOTONIC to avoid issues with wall-clock adjustments.
 */
static unsigned long long get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * run_pipe_benchmark - Measure context switch latency using pipe ping-pong
 * @iterations: Number of round trips
 * @pin:        If nonzero, pin both processes to CPU 0
 */
static void run_pipe_benchmark(int iterations, int pin)
{
    int pipe_a[2]; /* Parent writes, child reads */
    int pipe_b[2]; /* Child writes, parent reads */
    pid_t child;

    if (pipe(pipe_a) == -1 || pipe(pipe_b) == -1) {
        perror("pipe");
        exit(1);
    }

    child = fork();
    if (child == -1) {
        perror("fork");
        exit(1);
    }

    if (child == 0) {
        /* ===== CHILD PROCESS ===== */
        close(pipe_a[1]); /* Close write end of pipe_a */
        close(pipe_b[0]); /* Close read end of pipe_b */

        if (pin)
            pin_to_cpu(0);

        char buf;
        for (int i = 0; i < iterations; i++) {
            /* Read from parent */
            if (read(pipe_a[0], &buf, 1) != 1) {
                perror("child read");
                _exit(1);
            }
            /* Write back to parent */
            if (write(pipe_b[1], &buf, 1) != 1) {
                perror("child write");
                _exit(1);
            }
        }

        close(pipe_a[0]);
        close(pipe_b[1]);
        _exit(0);
    }

    /* ===== PARENT PROCESS ===== */
    close(pipe_a[0]); /* Close read end of pipe_a */
    close(pipe_b[1]); /* Close write end of pipe_b */

    if (pin)
        pin_to_cpu(0);

    char buf = 'x';

    /* Warm up: do a few iterations to prime caches */
    for (int i = 0; i < 100; i++) {
        write(pipe_a[1], &buf, 1);
        read(pipe_b[0], &buf, 1);
    }

    /* Timed measurement */
    unsigned long long start = get_time_ns();

    for (int i = 0; i < iterations; i++) {
        if (write(pipe_a[1], &buf, 1) != 1) {
            perror("parent write");
            break;
        }
        if (read(pipe_b[0], &buf, 1) != 1) {
            perror("parent read");
            break;
        }
    }

    unsigned long long end = get_time_ns();

    close(pipe_a[1]);
    close(pipe_b[0]);

    /* Wait for child */
    int status;
    waitpid(child, &status, 0);

    /* Calculate results */
    unsigned long long total_ns = end - start;
    double per_roundtrip_ns = (double)total_ns / iterations;
    double per_switch_ns = per_roundtrip_ns / 2.0;

    printf("  Iterations:           %d\n", iterations);
    printf("  CPU pinning:          %s\n", pin ? "YES (same CPU)" : "NO (may run in parallel)");
    printf("  Total time:           %.3f ms\n", total_ns / 1e6);
    printf("  Per round-trip:       %.1f ns\n", per_roundtrip_ns);
    printf("  Per context switch:   %.1f ns (%.3f us)\n",
           per_switch_ns, per_switch_ns / 1000.0);
    printf("  Context switches/sec: %.0f\n", 1e9 / per_switch_ns);
}

/*
 * run_thread_benchmark - Measure context switch with threads (same address space)
 * @iterations: Number of round trips
 *
 * Threads share the same mm_struct, so context switches are cheaper
 * (no TLB flush / CR3 switch needed).
 */
static void run_thread_benchmark(int iterations)
{
    int pipe_a[2], pipe_b[2];
    if (pipe(pipe_a) == -1 || pipe(pipe_b) == -1) {
        perror("pipe");
        return;
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork for thread-like test");
        return;
    }

    if (child == 0) {
        close(pipe_a[1]);
        close(pipe_b[0]);
        pin_to_cpu(0);

        char buf;
        for (int i = 0; i < iterations; i++) {
            read(pipe_a[0], &buf, 1);
            write(pipe_b[1], &buf, 1);
        }
        _exit(0);
    }

    close(pipe_a[0]);
    close(pipe_b[1]);
    pin_to_cpu(0);

    char buf = 'x';

    /* Warm up */
    for (int i = 0; i < 100; i++) {
        write(pipe_a[1], &buf, 1);
        read(pipe_b[0], &buf, 1);
    }

    unsigned long long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        write(pipe_a[1], &buf, 1);
        read(pipe_b[0], &buf, 1);
    }
    unsigned long long end = get_time_ns();

    close(pipe_a[1]);
    close(pipe_b[0]);

    int status;
    waitpid(child, &status, 0);

    unsigned long long total_ns = end - start;
    double per_switch_ns = (double)total_ns / iterations / 2.0;

    printf("  Per context switch (pinned processes): %.1f ns (%.3f us)\n",
           per_switch_ns, per_switch_ns / 1000.0);
}

/*
 * run_syscall_baseline - Measure raw syscall overhead for comparison
 * @iterations: Number of syscalls to make
 *
 * This provides a baseline: the minimum overhead of entering/leaving
 * the kernel (without a context switch).
 */
static void run_syscall_baseline(int iterations)
{
    unsigned long long start = get_time_ns();

    for (int i = 0; i < iterations; i++) {
        /* getpid() is a very fast syscall (cached in glibc) */
        /* Use syscall() to force actual kernel entry */
        syscall(39); /* SYS_getpid */
    }

    unsigned long long end = get_time_ns();
    double per_syscall = (double)(end - start) / iterations;

    printf("  Syscall overhead (getpid): %.1f ns\n", per_syscall);
}

int main(int argc, char *argv[])
{
    int iterations = DEFAULT_ITERATIONS;
    int pin = 0;

    if (argc > 1)
        iterations = atoi(argv[1]);
    if (argc > 2)
        pin = atoi(argv[2]);

    if (iterations <= 0)
        iterations = DEFAULT_ITERATIONS;

    printf("==============================================\n");
    printf("  Context Switch Benchmark\n");
    printf("==============================================\n\n");

    /* Show system info */
    printf("--- System Info ---\n");
    printf("  CPUs online:   %d\n", (int)sysconf(_SC_NPROCESSORS_ONLN));

    /* Read scheduler */
    FILE *fp = fopen("/proc/version", "r");
    if (fp) {
        char ver[256];
        if (fgets(ver, sizeof(ver), fp))
            printf("  Kernel:        %.60s...\n", ver);
        fclose(fp);
    }
    printf("\n");

    /* Test 1: No CPU pinning (processes may run in parallel) */
    printf("--- Test 1: Without CPU Pinning ---\n");
    run_pipe_benchmark(iterations, 0);
    printf("\n");

    /* Test 2: With CPU pinning (forces context switches) */
    printf("--- Test 2: With CPU Pinning (forced context switches) ---\n");
    run_pipe_benchmark(iterations, 1);
    printf("\n");

    /* Test 3: Syscall baseline */
    printf("--- Test 3: Syscall Baseline (no context switch) ---\n");
    run_syscall_baseline(iterations);
    printf("\n");

    /* Comparison */
    printf("--- Test 4: Pinned Process Context Switch ---\n");
    run_thread_benchmark(iterations);
    printf("\n");

    printf("=== Notes ===\n");
    printf("  - 'Per context switch' = half a round-trip (write+read = 2 switches)\n");
    printf("  - Pinned results are more accurate for actual context switch cost\n");
    printf("  - Unpinned may show lower latency due to parallel execution\n");
    printf("  - Real context switch cost includes TLB flush for different processes\n");
    printf("  - Thread context switches (same mm) are cheaper than process switches\n");
    printf("\n");

    return 0;
}

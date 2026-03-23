/*
 * page_fault_counter.c - Monitor page faults using getrusage and /proc
 *
 * This program demonstrates page fault mechanics by:
 *   1. Allocating memory with mmap (no physical pages yet)
 *   2. Touching pages to trigger demand paging (page faults)
 *   3. Counting minor and major faults via getrusage()
 *   4. Comparing mmap+touch vs mmap+mlock (pre-fault)
 *   5. Demonstrating the difference between minor and major faults
 *
 * The program uses getrusage(RUSAGE_SELF) to count page faults, which
 * reads from the task_struct's fault counters in the kernel.
 *
 * On Linux, perf_event_open() can also be used for hardware performance
 * counter monitoring, but getrusage is more portable.
 *
 * Compile: gcc -Wall -Wextra -O2 -o page_fault_counter page_fault_counter.c
 * Usage:   ./page_fault_counter [size_in_mb]
 *
 * Related: Lesson 7 (Memory Management - Virtual, Pages, Zones)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>

/* Default allocation size in MB */
#define DEFAULT_SIZE_MB 64

/*
 * fault_stats - Structure to hold page fault counts
 */
struct fault_stats {
    long minor_before;
    long minor_after;
    long major_before;
    long major_after;
    double elapsed_ns;
};

/*
 * get_faults - Read current page fault counts from getrusage
 * @minor: Output for minor (soft) page faults
 * @major: Output for major (hard) page faults
 */
static void get_faults(long *minor, long *major)
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    *minor = usage.ru_minflt;  /* Minor faults: page in memory but not mapped */
    *major = usage.ru_majflt;  /* Major faults: page must be read from disk */
}

/*
 * get_time_ns - Get current time in nanoseconds
 */
static unsigned long long get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * test_demand_paging - Demonstrate demand paging with mmap + sequential touch
 * @size: Number of bytes to allocate
 * @stats: Output fault statistics
 */
static void test_demand_paging(size_t size, struct fault_stats *stats)
{
    /* mmap: creates virtual mapping but allocates NO physical pages */
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    get_faults(&stats->minor_before, &stats->major_before);
    unsigned long long start = get_time_ns();

    /*
     * Touch every page (4KB apart).
     * Each first access to a page triggers a page fault:
     *   1. CPU raises #PF exception
     *   2. Kernel's do_page_fault() runs
     *   3. Kernel allocates a physical page (zeroed)
     *   4. Kernel installs PTE in the process's page table
     *   5. CPU retries the instruction -- succeeds
     */
    long page_size = sysconf(_SC_PAGESIZE);
    for (size_t i = 0; i < size; i += page_size)
        mem[i] = (char)(i & 0xFF);

    unsigned long long end = get_time_ns();
    get_faults(&stats->minor_after, &stats->major_after);
    stats->elapsed_ns = (double)(end - start);

    munmap(mem, size);
}

/*
 * test_prefaulted - Demonstrate pre-faulted allocation with MAP_POPULATE
 * @size: Number of bytes to allocate
 * @stats: Output fault statistics
 */
static void test_prefaulted(size_t size, struct fault_stats *stats)
{
    get_faults(&stats->minor_before, &stats->major_before);
    unsigned long long start = get_time_ns();

    /*
     * MAP_POPULATE causes the kernel to pre-fault all pages at mmap time.
     * This means no page faults during subsequent access.
     */
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap MAP_POPULATE");
        return;
    }

    /* Touch every page (should NOT cause additional faults) */
    long page_size = sysconf(_SC_PAGESIZE);
    for (size_t i = 0; i < size; i += page_size)
        mem[i] = (char)(i & 0xFF);

    unsigned long long end = get_time_ns();
    get_faults(&stats->minor_after, &stats->major_after);
    stats->elapsed_ns = (double)(end - start);

    munmap(mem, size);
}

/*
 * test_random_access - Test page faults with random access pattern
 * @size: Number of bytes to allocate
 * @stats: Output fault statistics
 */
static void test_random_access(size_t size, struct fault_stats *stats)
{
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    size_t num_pages = size / page_size;

    /* Create a random permutation of page indices */
    size_t *indices = malloc(num_pages * sizeof(size_t));
    if (!indices) {
        munmap(mem, size);
        return;
    }
    for (size_t i = 0; i < num_pages; i++)
        indices[i] = i;

    /* Fisher-Yates shuffle */
    srand(42);
    for (size_t i = num_pages - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        size_t tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }

    get_faults(&stats->minor_before, &stats->major_before);
    unsigned long long start = get_time_ns();

    /* Touch pages in random order */
    for (size_t i = 0; i < num_pages; i++)
        mem[indices[i] * page_size] = 'x';

    unsigned long long end = get_time_ns();
    get_faults(&stats->minor_after, &stats->major_after);
    stats->elapsed_ns = (double)(end - start);

    free(indices);
    munmap(mem, size);
}

/*
 * test_cow_faults - Demonstrate copy-on-write page faults after fork
 * @size: Number of bytes to allocate
 * @stats: Output fault statistics (for the child process)
 */
static void test_cow_faults(size_t size, struct fault_stats *stats)
{
    long page_size = sysconf(_SC_PAGESIZE);

    /* Allocate and touch all pages (parent owns physical pages) */
    char *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    /* Pre-fault all pages in parent */
    for (size_t i = 0; i < size; i += page_size)
        mem[i] = 'A';

    /* Fork: child shares pages (marked read-only for COW) */
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        munmap(mem, size);
        return;
    }

    if (pid == 0) {
        /* CHILD: writing triggers COW faults */
        get_faults(&stats->minor_before, &stats->major_before);
        unsigned long long start = get_time_ns();

        /* Write to every page: each write triggers a COW fault */
        for (size_t i = 0; i < size; i += page_size)
            mem[i] = 'B';

        unsigned long long end = get_time_ns();
        get_faults(&stats->minor_after, &stats->major_after);
        stats->elapsed_ns = (double)(end - start);

        /* Print from child since stats are in child's address space */
        long minor_faults = stats->minor_after - stats->minor_before;
        long major_faults = stats->major_after - stats->major_before;
        size_t expected = size / page_size;

        printf("  COW faults (child process):\n");
        printf("    Minor faults:    %ld (expected ~%zu)\n",
               minor_faults, expected);
        printf("    Major faults:    %ld\n", major_faults);
        printf("    Time:            %.3f ms\n", stats->elapsed_ns / 1e6);
        printf("    Per COW fault:   %.1f ns\n",
               minor_faults > 0 ? stats->elapsed_ns / minor_faults : 0);

        munmap(mem, size);
        _exit(0);
    }

    /* Parent: wait for child */
    int status;
    waitpid(pid, &status, 0);
    munmap(mem, size);
}

/*
 * print_result - Display test results
 */
static void print_result(const char *test_name, struct fault_stats *stats,
                         size_t size)
{
    long minor_faults = stats->minor_after - stats->minor_before;
    long major_faults = stats->major_after - stats->major_before;
    long page_size = sysconf(_SC_PAGESIZE);
    size_t expected_pages = size / page_size;

    printf("  %s:\n", test_name);
    printf("    Allocation size: %zu MB (%zu pages)\n",
           size / (1024 * 1024), expected_pages);
    printf("    Minor faults:    %ld", minor_faults);
    if (expected_pages > 0)
        printf(" (expected ~%zu)", expected_pages);
    printf("\n");
    printf("    Major faults:    %ld\n", major_faults);
    printf("    Total time:      %.3f ms\n", stats->elapsed_ns / 1e6);

    if (minor_faults > 0) {
        printf("    Per-fault time:  %.1f ns (%.3f us)\n",
               stats->elapsed_ns / minor_faults,
               stats->elapsed_ns / minor_faults / 1000.0);
        printf("    Fault rate:      %.0f faults/ms\n",
               minor_faults / (stats->elapsed_ns / 1e6));
    }
    printf("\n");
}

/*
 * show_proc_vmstat - Display relevant VM statistics from /proc
 */
static void show_proc_vmstat(void)
{
    printf("=== System VM Statistics ===\n\n");

    FILE *fp = fopen("/proc/vmstat", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "pgfault", 7) == 0 ||
            strncmp(line, "pgmajfault", 10) == 0 ||
            strncmp(line, "pgfree", 6) == 0 ||
            strncmp(line, "pgalloc_normal", 14) == 0 ||
            strncmp(line, "thp_fault_alloc", 15) == 0 ||
            strncmp(line, "thp_fault_fallback", 18) == 0) {
            printf("  %s", line);
        }
    }
    fclose(fp);

    /* Show THP (Transparent Huge Pages) status */
    fp = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (fp) {
        char thp[128];
        if (fgets(thp, sizeof(thp), fp))
            printf("  THP status: %s", thp);
        fclose(fp);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    size_t size_mb = DEFAULT_SIZE_MB;
    if (argc > 1)
        size_mb = (size_t)atoi(argv[1]);
    if (size_mb == 0)
        size_mb = DEFAULT_SIZE_MB;

    size_t size = size_mb * 1024 * 1024;
    long page_size = sysconf(_SC_PAGESIZE);

    printf("=================================================\n");
    printf("  Page Fault Counter and Analyzer\n");
    printf("=================================================\n\n");

    printf("  Page size:        %ld bytes\n", page_size);
    printf("  Allocation size:  %zu MB (%zu pages)\n",
           size_mb, size / page_size);
    printf("  PID:              %d\n\n", getpid());

    show_proc_vmstat();

    struct fault_stats stats;

    /* Test 1: Sequential demand paging */
    printf("--- Test 1: Sequential Demand Paging (mmap + touch) ---\n\n");
    test_demand_paging(size, &stats);
    print_result("Sequential touch", &stats, size);

    /* Test 2: Pre-faulted with MAP_POPULATE */
    printf("--- Test 2: Pre-faulted Allocation (MAP_POPULATE) ---\n\n");
    test_prefaulted(size, &stats);
    print_result("Pre-faulted (MAP_POPULATE)", &stats, size);

    /* Test 3: Random access pattern */
    printf("--- Test 3: Random Access Pattern ---\n\n");
    test_random_access(size, &stats);
    print_result("Random touch", &stats, size);

    /* Test 4: Copy-on-Write faults */
    printf("--- Test 4: Copy-on-Write Faults (after fork) ---\n\n");
    test_cow_faults(size, &stats);

    /* Summary */
    printf("=== Summary ===\n\n");
    printf("  1. Demand paging:  Faults occur on first access to each page.\n");
    printf("  2. MAP_POPULATE:   Pre-faults all pages at mmap time (no later faults).\n");
    printf("  3. Random access:  Same number of faults, but possibly worse TLB behavior.\n");
    printf("  4. COW faults:     After fork, writes trigger copy-on-write faults.\n");
    printf("\n  Minor faults are fast (~1-5 us): page is allocated from free list.\n");
    printf("  Major faults are slow (~1-10 ms): page must be read from disk/swap.\n");

    return 0;
}

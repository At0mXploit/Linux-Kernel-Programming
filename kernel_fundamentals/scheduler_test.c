/*
 * scheduler_test.c - Demonstrate different Linux scheduling policies
 *
 * This program creates multiple threads with different scheduling policies
 * and priorities, then measures how much CPU time each receives. It
 * demonstrates:
 *   - SCHED_OTHER (CFS default) with different nice values
 *   - SCHED_FIFO (real-time first-in-first-out)
 *   - SCHED_RR (real-time round-robin)
 *   - CPU affinity and scheduling parameters
 *
 * Must be run as root (or with CAP_SYS_NICE) for real-time policies.
 *
 * Compile: gcc -Wall -Wextra -O2 -o scheduler_test scheduler_test.c -lpthread
 * Usage:   sudo ./scheduler_test
 *
 * Related: Lesson 6 (Scheduler - CFS, Runqueues, Priorities)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

/* Duration for CPU burn test (seconds) */
#define TEST_DURATION 3

/* Maximum number of test threads */
#define MAX_THREADS 8

/* Shared flag to signal threads to stop */
static volatile int g_running = 0;

/*
 * Thread configuration structure
 */
struct thread_config {
    int id;                 /* Thread identifier */
    int policy;             /* SCHED_OTHER, SCHED_FIFO, SCHED_RR */
    int priority;           /* RT priority (1-99) or 0 for CFS */
    int nice_val;           /* Nice value for SCHED_OTHER (-20 to 19) */
    int pin_cpu;            /* CPU to pin to (-1 for no pinning) */
    unsigned long long iterations; /* Counted iterations (output) */
    double cpu_time;        /* CPU time consumed (output) */
    char description[64];   /* Human-readable description */
};

/*
 * policy_name - Convert scheduling policy constant to string
 */
static const char *policy_name(int policy)
{
    switch (policy) {
    case SCHED_OTHER: return "SCHED_OTHER";
    case SCHED_FIFO:  return "SCHED_FIFO";
    case SCHED_RR:    return "SCHED_RR";
#ifdef SCHED_BATCH
    case SCHED_BATCH: return "SCHED_BATCH";
#endif
#ifdef SCHED_IDLE
    case SCHED_IDLE:  return "SCHED_IDLE";
#endif
    default:          return "UNKNOWN";
    }
}

/*
 * get_thread_time - Get CPU time consumed by the calling thread
 *
 * Uses CLOCK_THREAD_CPUTIME_ID for per-thread CPU time measurement.
 */
static double get_thread_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * burn_cpu - Thread function that burns CPU and counts iterations
 * @arg: Pointer to thread_config structure
 *
 * The thread configures its scheduling policy/priority, then enters a
 * tight loop counting iterations until g_running becomes 0.
 */
static void *burn_cpu(void *arg)
{
    struct thread_config *cfg = (struct thread_config *)arg;
    pid_t tid = syscall(SYS_gettid);

    /* Pin to CPU if requested */
    if (cfg->pin_cpu >= 0) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(cfg->pin_cpu, &mask);
        if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
            fprintf(stderr, "Thread %d: sched_setaffinity failed: %s\n",
                    cfg->id, strerror(errno));
        }
    }

    /* Set scheduling policy and priority */
    if (cfg->policy == SCHED_FIFO || cfg->policy == SCHED_RR) {
        struct sched_param param;
        memset(&param, 0, sizeof(param));
        param.sched_priority = cfg->priority;
        if (sched_setscheduler(0, cfg->policy, &param) == -1) {
            fprintf(stderr, "Thread %d: sched_setscheduler(%s, %d) failed: %s\n",
                    cfg->id, policy_name(cfg->policy), cfg->priority,
                    strerror(errno));
            fprintf(stderr, "  (Need root/CAP_SYS_NICE for RT scheduling)\n");
            /* Fall back to SCHED_OTHER */
            cfg->policy = SCHED_OTHER;
        }
    }

    /* Set nice value for SCHED_OTHER */
    if (cfg->policy == SCHED_OTHER && cfg->nice_val != 0) {
        if (setpriority(PRIO_PROCESS, 0, cfg->nice_val) == -1) {
            fprintf(stderr, "Thread %d: setpriority(%d) failed: %s\n",
                    cfg->id, cfg->nice_val, strerror(errno));
        }
    }

    /* Report actual configuration */
    int actual_policy = cycalloc(0);
    (void)actual_policy;

    printf("  Thread %d (TID %d): %s  %s\n", cfg->id, tid,
           cfg->description, "(ready)");

    /* Wait for start signal */
    while (!g_running) {
        sched_yield();
    }

    /* Burn CPU and count iterations */
    double start_cpu = get_thread_time();
    unsigned long long count = 0;

    while (g_running) {
        /*
         * Volatile prevents the compiler from optimizing away the loop.
         * The loop is intentionally simple to maximize context-switch
         * effects relative to per-iteration work.
         */
        volatile unsigned int dummy = 0;
        for (int j = 0; j < 1000; j++)
            dummy += j;
        count++;
        (void)dummy;
    }

    double end_cpu = get_thread_time();

    cfg->iterations = count;
    cfg->cpu_time = end_cpu - start_cpu;

    return NULL;
}

/*
 * Wrapper: we had a typo above. Let's fix it by making
 * cycalloc a simple function returning the scheduler.
 */
static int cycalloc(pid_t pid)
{
    return sched_getscheduler(pid);
}

/*
 * test_cfs_fairness - Test CFS with different nice values
 *
 * Creates threads with nice values 0, 5, 10, 19.
 * CFS should give proportionally more CPU to lower nice values.
 */
static void test_cfs_fairness(void)
{
    printf("\n=== Test 1: CFS Fairness (SCHED_OTHER with different nice values) ===\n\n");

    struct thread_config configs[] = {
        { .id = 0, .policy = SCHED_OTHER, .nice_val =  0, .pin_cpu = 0,
          .description = "SCHED_OTHER nice=0  (default)" },
        { .id = 1, .policy = SCHED_OTHER, .nice_val =  5, .pin_cpu = 0,
          .description = "SCHED_OTHER nice=5  (lower prio)" },
        { .id = 2, .policy = SCHED_OTHER, .nice_val = 10, .pin_cpu = 0,
          .description = "SCHED_OTHER nice=10 (lower prio)" },
        { .id = 3, .policy = SCHED_OTHER, .nice_val = 19, .pin_cpu = 0,
          .description = "SCHED_OTHER nice=19 (lowest prio)" },
    };

    int nthreads = sizeof(configs) / sizeof(configs[0]);
    pthread_t threads[MAX_THREADS];

    g_running = 0;

    /* Create threads */
    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&threads[i], NULL, burn_cpu, &configs[i]) != 0) {
            perror("pthread_create");
            return;
        }
    }

    /* Give threads time to initialize */
    usleep(100000);

    /* Start the test */
    printf("  Starting %d-second CPU burn...\n\n", TEST_DURATION);
    g_running = 1;
    sleep(TEST_DURATION);
    g_running = 0;

    /* Collect results */
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    /* Display results */
    printf("  Results:\n");
    printf("  %-45s %12s %10s %8s\n", "Description", "Iterations", "CPU Time", "Share");
    printf("  %-45s %12s %10s %8s\n", "-----------", "----------", "--------", "-----");

    double total_cpu = 0;
    for (int i = 0; i < nthreads; i++)
        total_cpu += configs[i].cpu_time;

    for (int i = 0; i < nthreads; i++) {
        double share = (total_cpu > 0) ? (configs[i].cpu_time / total_cpu * 100) : 0;
        printf("  %-45s %12llu %9.3fs %7.1f%%\n",
               configs[i].description,
               configs[i].iterations,
               configs[i].cpu_time,
               share);
    }

    printf("\n  Expected: nice=0 gets the most CPU, nice=19 gets the least.\n");
    printf("  Each nice level changes weight by ~1.25x.\n");
}

/*
 * test_rt_vs_normal - Test RT scheduling vs normal scheduling
 *
 * Creates one SCHED_FIFO thread and one SCHED_OTHER thread on the same CPU.
 * The FIFO thread should dominate.
 */
static void test_rt_vs_normal(void)
{
    printf("\n=== Test 2: Real-Time vs Normal Scheduling ===\n\n");

    struct thread_config configs[] = {
        { .id = 0, .policy = SCHED_FIFO, .priority = 50, .nice_val = 0, .pin_cpu = 0,
          .description = "SCHED_FIFO prio=50 (real-time)" },
        { .id = 1, .policy = SCHED_OTHER, .priority = 0, .nice_val = 0, .pin_cpu = 0,
          .description = "SCHED_OTHER nice=0 (normal)" },
    };

    int nthreads = 2;
    pthread_t threads[MAX_THREADS];

    g_running = 0;

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&threads[i], NULL, burn_cpu, &configs[i]) != 0) {
            perror("pthread_create");
            return;
        }
    }

    usleep(100000);
    printf("  Starting %d-second CPU burn...\n\n", TEST_DURATION);
    g_running = 1;
    sleep(TEST_DURATION);
    g_running = 0;

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    printf("  Results:\n");
    printf("  %-45s %12s %10s\n", "Description", "Iterations", "CPU Time");
    printf("  %-45s %12s %10s\n", "-----------", "----------", "--------");

    for (int i = 0; i < nthreads; i++) {
        printf("  %-45s %12llu %9.3fs\n",
               configs[i].description,
               configs[i].iterations,
               configs[i].cpu_time);
    }

    printf("\n  Expected: SCHED_FIFO gets nearly all CPU time.\n");
    printf("  The SCHED_OTHER thread is starved (or gets very little CPU).\n");
    printf("  WARNING: On single-CPU systems, SCHED_FIFO can hang the system!\n");
}

/*
 * test_rt_priorities - Test different RT priority levels
 */
static void test_rt_priorities(void)
{
    printf("\n=== Test 3: RT Priority Levels (SCHED_FIFO) ===\n\n");

    struct thread_config configs[] = {
        { .id = 0, .policy = SCHED_FIFO, .priority = 90, .pin_cpu = 0,
          .description = "SCHED_FIFO prio=90 (high)" },
        { .id = 1, .policy = SCHED_FIFO, .priority = 50, .pin_cpu = 0,
          .description = "SCHED_FIFO prio=50 (medium)" },
        { .id = 2, .policy = SCHED_FIFO, .priority = 10, .pin_cpu = 0,
          .description = "SCHED_FIFO prio=10 (low)" },
    };

    int nthreads = 3;
    pthread_t threads[MAX_THREADS];

    g_running = 0;

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&threads[i], NULL, burn_cpu, &configs[i]) != 0) {
            perror("pthread_create");
            return;
        }
    }

    usleep(100000);
    printf("  Starting %d-second CPU burn...\n\n", TEST_DURATION);
    g_running = 1;
    sleep(TEST_DURATION);
    g_running = 0;

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    printf("  Results:\n");
    printf("  %-45s %12s %10s\n", "Description", "Iterations", "CPU Time");
    printf("  %-45s %12s %10s\n", "-----------", "----------", "--------");

    for (int i = 0; i < nthreads; i++) {
        printf("  %-45s %12llu %9.3fs\n",
               configs[i].description,
               configs[i].iterations,
               configs[i].cpu_time);
    }

    printf("\n  Expected: prio=90 gets all CPU (FIFO = no timeslice).\n");
    printf("  Lower-priority FIFO threads are completely starved.\n");
}

/*
 * show_scheduler_info - Display scheduler configuration
 */
static void show_scheduler_info(void)
{
    printf("=== Scheduler Information ===\n\n");

    printf("  SCHED_OTHER priority range: %d - %d\n",
           sched_get_priority_min(SCHED_OTHER),
           sched_get_priority_max(SCHED_OTHER));
    printf("  SCHED_FIFO priority range:  %d - %d\n",
           sched_get_priority_min(SCHED_FIFO),
           sched_get_priority_max(SCHED_FIFO));
    printf("  SCHED_RR priority range:    %d - %d\n",
           sched_get_priority_min(SCHED_RR),
           sched_get_priority_max(SCHED_RR));

    struct timespec ts;
    if (sched_rr_get_interval(0, &ts) == 0) {
        printf("  SCHED_RR timeslice:         %ld ms\n",
               ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }

    printf("  Online CPUs:                %d\n",
           (int)sysconf(_SC_NPROCESSORS_ONLN));

    int current_policy = sched_getscheduler(0);
    printf("  Current process policy:     %s\n", policy_name(current_policy));
    printf("  Current nice value:         %d\n", getpriority(PRIO_PROCESS, 0));
    printf("  Test duration:              %d seconds per test\n", TEST_DURATION);
}

int main(void)
{
    printf("=============================================\n");
    printf("  Linux Scheduler Policy Test\n");
    printf("=============================================\n\n");

    show_scheduler_info();

    /* Test 1: CFS fairness with nice values (no root needed) */
    test_cfs_fairness();

    /* Tests 2-3 require root for RT scheduling */
    if (geteuid() == 0) {
        test_rt_vs_normal();
        test_rt_priorities();
    } else {
        printf("\n=== Tests 2 & 3 skipped (requires root for RT scheduling) ===\n");
        printf("  Re-run with: sudo %s\n", program_invocation_name);
    }

    printf("\n=============================================\n");
    printf("  All tests complete.\n");
    printf("=============================================\n");

    return 0;
}

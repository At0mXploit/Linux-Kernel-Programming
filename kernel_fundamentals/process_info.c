/*
 * process_info.c - Read and display detailed process information from /proc
 *
 * This program demonstrates how user-space programs can inspect kernel data
 * structures through the /proc filesystem. It reads:
 *   - /proc/self/status   (task_struct fields: PID, state, memory, etc.)
 *   - /proc/self/maps     (virtual memory areas / VMAs)
 *   - /proc/self/stat     (scheduling statistics)
 *   - /proc/self/limits   (resource limits)
 *
 * Compile: gcc -Wall -Wextra -o process_info process_info.c -lpthread
 * Usage:   ./process_info
 *
 * Related: Lesson 5 (task_struct and Process Management)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sched.h>
#include <pthread.h>

/* Maximum line length when reading /proc files */
#define MAX_LINE 512

/*
 * read_proc_file - Read and print selected lines from a /proc file
 * @path:     Path to the /proc file
 * @prefixes: Array of line prefixes to match (NULL-terminated)
 * @header:   Header to print before output
 *
 * Reads the file line by line and prints only lines whose beginning
 * matches one of the given prefixes. If prefixes is NULL, prints all lines.
 */
static void read_proc_file(const char *path, const char **prefixes,
                           const char *header)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return;
    }

    printf("\n=== %s ===\n", header);
    printf("Source: %s\n\n", path);

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        if (prefixes == NULL) {
            /* Print all lines */
            printf("  %s", line);
        } else {
            /* Print only matching lines */
            for (const char **p = prefixes; *p; p++) {
                if (strncmp(line, *p, strlen(*p)) == 0) {
                    printf("  %s", line);
                    break;
                }
            }
        }
    }
    fclose(fp);
}

/*
 * show_status - Display key fields from /proc/self/status
 *
 * These fields directly correspond to task_struct members:
 *   Name   -> task->comm
 *   State  -> task->__state
 *   Pid    -> task->pid
 *   Tgid   -> task->tgid (thread group ID = user-visible PID)
 *   PPid   -> task->real_parent->tgid
 *   Uid    -> task->cred->uid, euid, suid, fsuid
 *   VmSize -> total virtual memory (from mm_struct)
 *   VmRSS  -> resident set size (physical memory used)
 *   Threads -> number of threads in thread group
 */
static void show_status(void)
{
    const char *fields[] = {
        "Name:",
        "Umask:",
        "State:",
        "Tgid:",
        "Pid:",
        "PPid:",
        "TracerPid:",
        "Uid:",
        "Gid:",
        "FDSize:",
        "VmPeak:",
        "VmSize:",
        "VmLck:",
        "VmRSS:",
        "VmData:",
        "VmStk:",
        "VmExe:",
        "VmLib:",
        "Threads:",
        "Cpus_allowed:",
        "voluntary_ctxt_switches:",
        "nonvoluntary_ctxt_switches:",
        NULL
    };
    read_proc_file("/proc/self/status", fields,
                   "Process Status (task_struct fields)");
}

/*
 * show_maps - Display the virtual memory map
 *
 * Each line in /proc/self/maps represents a VMA (vm_area_struct):
 *   address range  perms  offset  dev  inode  pathname
 *   558800000000-558800001000 r--p 00000000 08:01 12345 /usr/bin/prog
 *
 * Permissions: r=read, w=write, x=execute, p=private/s=shared
 */
static void show_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("/proc/self/maps");
        return;
    }

    printf("\n=== Virtual Memory Map (VMAs) ===\n");
    printf("Source: /proc/self/maps\n\n");
    printf("  %-35s %-5s %-10s %s\n", "ADDRESS RANGE", "PERMS", "OFFSET", "MAPPING");
    printf("  %-35s %-5s %-10s %s\n", "-------------", "-----", "------", "-------");

    char line[MAX_LINE];
    unsigned long total_vma_size = 0;
    int vma_count = 0;
    int rw_count = 0;
    int rx_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[8], offset[16], dev[16], pathname[256];
        unsigned long inode;

        pathname[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %15s %15s %lu %255[^\n]",
                   &start, &end, perms, offset, dev, &inode, pathname) >= 5) {

            /* Trim leading spaces from pathname */
            char *name = pathname;
            while (*name == ' ') name++;

            printf("  %012lx-%012lx %-5s %-10s %s\n",
                   start, end, perms, offset,
                   *name ? name : "(anonymous)");

            total_vma_size += (end - start);
            vma_count++;

            if (strchr(perms, 'r') && strchr(perms, 'w'))
                rw_count++;
            if (strchr(perms, 'r') && strchr(perms, 'x'))
                rx_count++;
        }
    }
    fclose(fp);

    printf("\n  Summary:\n");
    printf("    Total VMAs:        %d\n", vma_count);
    printf("    Total mapped size: %lu KB (%lu MB)\n",
           total_vma_size / 1024, total_vma_size / (1024 * 1024));
    printf("    RW mappings:       %d\n", rw_count);
    printf("    RX mappings:       %d\n", rx_count);
}

/*
 * show_stat - Parse /proc/self/stat for scheduling information
 *
 * The stat file contains a single line with many fields separated by spaces.
 * Key fields (1-indexed):
 *   1:  pid
 *   2:  comm (in parentheses)
 *   3:  state (R/S/D/Z/T)
 *   4:  ppid
 *   10: minflt (minor page faults)
 *   12: majflt (major page faults)
 *   14: utime (user mode ticks)
 *   15: stime (kernel mode ticks)
 *   18: priority
 *   19: nice
 *   20: num_threads
 *   22: starttime (ticks since boot)
 *   39: processor (last CPU)
 */
static void show_stat(void)
{
    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) {
        perror("/proc/self/stat");
        return;
    }

    printf("\n=== Scheduling Statistics ===\n");
    printf("Source: /proc/self/stat\n\n");

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }
    fclose(fp);

    /*
     * Parse stat file. The comm field may contain spaces and parentheses,
     * so we find the last ')' and parse from there.
     */
    char *comm_start = strchr(line, '(');
    char *comm_end = strrchr(line, ')');
    if (!comm_start || !comm_end) return;

    /* Extract comm */
    char comm[64];
    int len = (int)(comm_end - comm_start - 1);
    if (len >= (int)sizeof(comm)) len = sizeof(comm) - 1;
    strncpy(comm, comm_start + 1, len);
    comm[len] = '\0';

    /* Parse remaining fields after ')' */
    char state;
    int ppid;
    long minflt, majflt, utime, stime, priority, nice_val;
    long num_threads;
    unsigned long long starttime;
    int processor;

    /* Skip to the character after ')' */
    char *rest = comm_end + 2;
    sscanf(rest,
           "%c %d %*d %*d %*d %*d %*u "   /* state ppid pgrp session tty_nr tpgid flags */
           "%ld %*ld %ld %*ld "             /* minflt cminflt majflt cmajflt */
           "%ld %ld "                       /* utime stime */
           "%*ld %*ld "                     /* cutime cstime */
           "%ld %ld "                       /* priority nice */
           "%ld %*ld "                      /* num_threads itrealvalue */
           "%llu "                          /* starttime */
           "%*lu %*ld %*lu %*lu %*lu "      /* vsize rss rsslim ... */
           "%*lu %*lu %*lu %*lu %*lu "
           "%*lu %*lu %*lu %*lu "
           "%d",                            /* processor */
           &state, &ppid,
           &minflt, &majflt,
           &utime, &stime,
           &priority, &nice_val,
           &num_threads,
           &starttime,
           &processor);

    long ticks_per_sec = sysconf(_SC_CLK_TCK);

    printf("  Process name:       %s\n", comm);
    printf("  State:              %c", state);
    switch (state) {
        case 'R': printf(" (Running)\n"); break;
        case 'S': printf(" (Sleeping - interruptible)\n"); break;
        case 'D': printf(" (Sleeping - uninterruptible)\n"); break;
        case 'Z': printf(" (Zombie)\n"); break;
        case 'T': printf(" (Stopped)\n"); break;
        case 'I': printf(" (Idle)\n"); break;
        default:  printf(" (Unknown)\n"); break;
    }
    printf("  Parent PID:         %d\n", ppid);
    printf("  Minor page faults:  %ld\n", minflt);
    printf("  Major page faults:  %ld\n", majflt);
    printf("  User time:          %.3f seconds (%ld ticks)\n",
           (double)utime / ticks_per_sec, utime);
    printf("  Kernel time:        %.3f seconds (%ld ticks)\n",
           (double)stime / ticks_per_sec, stime);
    printf("  Priority:           %ld\n", priority);
    printf("  Nice:               %ld\n", nice_val);
    printf("  Threads:            %ld\n", num_threads);
    printf("  Start time:         %llu ticks after boot\n", starttime);
    printf("  Last CPU:           %d\n", processor);
    printf("  Clock ticks/sec:    %ld\n", ticks_per_sec);
}

/*
 * show_limits - Display resource limits
 */
static void show_limits(void)
{
    printf("\n=== Resource Limits ===\n");
    printf("Source: /proc/self/limits\n\n");

    FILE *fp = fopen("/proc/self/limits", "r");
    if (!fp) {
        perror("/proc/self/limits");
        return;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        printf("  %s", line);
    }
    fclose(fp);
}

/*
 * show_system_info - Display general system information
 */
static void show_system_info(void)
{
    printf("=== System Information ===\n\n");

    /* Kernel version */
    FILE *fp = fopen("/proc/version", "r");
    if (fp) {
        char line[MAX_LINE];
        if (fgets(line, sizeof(line), fp))
            printf("  Kernel: %s", line);
        fclose(fp);
    }

    /* CPU count */
    printf("  Online CPUs:    %d\n", (int)sysconf(_SC_NPROCESSORS_ONLN));
    printf("  Page size:      %ld bytes\n", sysconf(_SC_PAGESIZE));
    printf("  Phys pages:     %ld (%ld MB RAM)\n",
           sysconf(_SC_PHYS_PAGES),
           sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / (1024 * 1024));

    /* Current process */
    printf("\n  PID:            %d\n", getpid());
    printf("  PPID:           %d\n", getppid());
    printf("  TID:            %ld\n", syscall(SYS_gettid));
    printf("  UID:            %d\n", getuid());
    printf("  EUID:           %d\n", geteuid());
    printf("  GID:            %d\n", getgid());
    printf("  Current CPU:    %d\n", sched_getcpu());
}

int main(void)
{
    printf("============================================\n");
    printf("  Linux Process Information Inspector\n");
    printf("============================================\n");

    show_system_info();
    show_status();
    show_stat();
    show_maps();
    show_limits();

    printf("\n============================================\n");
    printf("  Inspection complete.\n");
    printf("============================================\n");

    return 0;
}

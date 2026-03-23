/*
 * network_anomaly.c - Compare /proc/net/tcp with socket states
 *
 *
 * Detection methodology:
 *   1. Parse /proc/net/tcp and /proc/net/tcp6 for kernel-reported sockets
 *   2. Map sockets to processes via /proc/<pid>/fd/ scanning
 *   3. Cross-reference socket inodes between sources
 *   4. Check for listening ports not associated with known processes
 *   5. Report anomalies suggesting hidden connections
 *
 * Compile: gcc -o network_anomaly network_anomaly.c -static
 * Usage:   sudo ./network_anomaly
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_SOCKETS 4096
#define MAX_PATH 512

/* TCP connection states */
static const char *tcp_states[] = {
    "UNKNOWN",          /* 0 */
    "ESTABLISHED",      /* 1 */
    "SYN_SENT",         /* 2 */
    "SYN_RECV",         /* 3 */
    "FIN_WAIT1",        /* 4 */
    "FIN_WAIT2",        /* 5 */
    "TIME_WAIT",        /* 6 */
    "CLOSE",            /* 7 */
    "CLOSE_WAIT",       /* 8 */
    "LAST_ACK",         /* 9 */
    "LISTEN",           /* 10 (0x0A) */
    "CLOSING",          /* 11 (0x0B) */
};

struct socket_entry {
    unsigned int local_ip;
    unsigned short local_port;
    unsigned int remote_ip;
    unsigned short remote_port;
    int state;
    int uid;
    unsigned long inode;
    int pid;                    /* Mapped from /proc/<pid>/fd */
    char process_name[128];
    int has_process;            /* Whether we found an owning process */
};

static struct socket_entry sockets[MAX_SOCKETS];
static int socket_count = 0;
static int anomaly_count = 0;

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  Network Anomaly Detection Tool\n");
    printf("  Socket Cross-Reference Analysis\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Convert hex IP address (from /proc/net/tcp) to dotted notation
 * Note: /proc/net/tcp stores IPs in host byte order
 */
static void hex_ip_to_str(unsigned int ip, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%u.%u.%u.%u",
             ip & 0xFF,
             (ip >> 8) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 24) & 0xFF);
}

static const char *get_tcp_state(int state)
{
    if (state >= 0 && state < (int)(sizeof(tcp_states) / sizeof(tcp_states[0])))
        return tcp_states[state];
    return "UNKNOWN";
}

/*
 * Parse /proc/net/tcp
 *
 * Format:
 *   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
 */
static int parse_proc_net_tcp(const char *path)
{
    FILE *fp;
    char line[512];
    int count = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        perror(path);
        return -1;
    }

    /* Skip header line */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL && socket_count < MAX_SOCKETS) {
        unsigned int local_ip, remote_ip;
        unsigned int local_port, remote_port;
        unsigned int state;
        unsigned int uid;
        unsigned long inode;

        int fields = sscanf(line,
            " %*d: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %u %*d %lu",
            &local_ip, &local_port,
            &remote_ip, &remote_port,
            &state, &uid, &inode);

        if (fields >= 7) {
            struct socket_entry *s = &sockets[socket_count];
            s->local_ip = local_ip;
            s->local_port = (unsigned short)local_port;
            s->remote_ip = remote_ip;
            s->remote_port = (unsigned short)remote_port;
            s->state = (int)state;
            s->uid = (int)uid;
            s->inode = inode;
            s->pid = 0;
            s->has_process = 0;
            s->process_name[0] = '\0';

            socket_count++;
            count++;
        }
    }

    fclose(fp);
    return count;
}

/*
 * Map socket inodes to processes by scanning /proc/<pid>/fd/
 *
 * Each socket shows up as a symlink:
 *   /proc/<pid>/fd/N -> socket:[<inode>]
 */
static void map_sockets_to_processes(void)
{
    DIR *proc_dir, *fd_dir;
    struct dirent *proc_entry, *fd_entry;
    char path[MAX_PATH];
    char link_target[MAX_PATH];
    ssize_t n;

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) return;

    while ((proc_entry = readdir(proc_dir)) != NULL) {
        /* Only process PID directories */
        int is_pid = 1;
        for (int i = 0; proc_entry->d_name[i]; i++) {
            if (!isdigit((unsigned char)proc_entry->d_name[i])) {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid) continue;

        int pid = atoi(proc_entry->d_name);

        /* Read process name */
        char comm[128] = "unknown";
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *fp = fopen(path, "r");
        if (fp) {
            if (fgets(comm, sizeof(comm), fp))
                comm[strcspn(comm, "\n")] = '\0';
            fclose(fp);
        }

        /* Scan file descriptors */
        snprintf(path, sizeof(path), "/proc/%d/fd", pid);
        fd_dir = opendir(path);
        if (fd_dir == NULL) continue;

        while ((fd_entry = readdir(fd_dir)) != NULL) {
            if (fd_entry->d_name[0] == '.') continue;

            snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, fd_entry->d_name);
            n = readlink(path, link_target, sizeof(link_target) - 1);
            if (n < 0) continue;
            link_target[n] = '\0';

            /* Check if this fd is a socket */
            if (strncmp(link_target, "socket:[", 8) == 0) {
                unsigned long inode = 0;
                sscanf(link_target + 8, "%lu", &inode);

                /* Find matching socket in our table */
                for (int i = 0; i < socket_count; i++) {
                    if (sockets[i].inode == inode) {
                        sockets[i].pid = pid;
                        sockets[i].has_process = 1;
                        strncpy(sockets[i].process_name, comm,
                                sizeof(sockets[i].process_name) - 1);
                        break;
                    }
                }
            }
        }

        closedir(fd_dir);
    }

    closedir(proc_dir);
}

/*
 * Display all detected sockets with process mapping
 */
static void display_sockets(void)
{
    char local_str[32], remote_str[32];
    int listening = 0, established = 0, other = 0;
    int orphaned = 0;

    printf(CYAN "  [Results]" RESET " Socket Analysis:\n\n");

    /* Show listening sockets first */
    printf("  --- Listening Sockets ---\n");
    printf("  %-6s %-22s %-22s %-15s %-8s %s\n",
           "Proto", "Local Address", "Remote Address", "State", "PID", "Process");
    printf("  %-6s %-22s %-22s %-15s %-8s %s\n",
           "------", "----------------------", "----------------------",
           "---------------", "--------", "--------");

    for (int i = 0; i < socket_count; i++) {
        if (sockets[i].state != 10) continue; /* 10 = LISTEN */

        hex_ip_to_str(sockets[i].local_ip, local_str, sizeof(local_str));
        hex_ip_to_str(sockets[i].remote_ip, remote_str, sizeof(remote_str));

        char local_addr[48], remote_addr[48];
        snprintf(local_addr, sizeof(local_addr), "%s:%u", local_str, sockets[i].local_port);
        snprintf(remote_addr, sizeof(remote_addr), "%s:%u", remote_str, sockets[i].remote_port);

        const char *color = sockets[i].has_process ? "" : RED;
        const char *endcolor = sockets[i].has_process ? "" : RESET;

        printf("  %s%-6s %-22s %-22s %-15s %-8d %s%s\n",
               color, "tcp", local_addr, remote_addr,
               get_tcp_state(sockets[i].state),
               sockets[i].pid,
               sockets[i].has_process ? sockets[i].process_name : "[NO PROCESS!]",
               endcolor);

        listening++;
        if (!sockets[i].has_process) {
            orphaned++;
        }
    }

    /* Show established connections */
    printf("\n  --- Established Connections ---\n");
    printf("  %-6s %-22s %-22s %-15s %-8s %s\n",
           "Proto", "Local Address", "Remote Address", "State", "PID", "Process");
    printf("  %-6s %-22s %-22s %-15s %-8s %s\n",
           "------", "----------------------", "----------------------",
           "---------------", "--------", "--------");

    for (int i = 0; i < socket_count; i++) {
        if (sockets[i].state != 1) continue; /* 1 = ESTABLISHED */

        hex_ip_to_str(sockets[i].local_ip, local_str, sizeof(local_str));
        hex_ip_to_str(sockets[i].remote_ip, remote_str, sizeof(remote_str));

        char local_addr[48], remote_addr[48];
        snprintf(local_addr, sizeof(local_addr), "%s:%u", local_str, sockets[i].local_port);
        snprintf(remote_addr, sizeof(remote_addr), "%s:%u", remote_str, sockets[i].remote_port);

        const char *color = sockets[i].has_process ? "" : RED;
        const char *endcolor = sockets[i].has_process ? "" : RESET;

        printf("  %s%-6s %-22s %-22s %-15s %-8d %s%s\n",
               color, "tcp", local_addr, remote_addr,
               get_tcp_state(sockets[i].state),
               sockets[i].pid,
               sockets[i].has_process ? sockets[i].process_name : "[NO PROCESS!]",
               endcolor);

        established++;
        if (!sockets[i].has_process) {
            orphaned++;
        }
    }

    /* Count other states */
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i].state != 10 && sockets[i].state != 1) {
            other++;
            if (!sockets[i].has_process && sockets[i].inode != 0) {
                orphaned++;
            }
        }
    }

    printf("\n  Summary:\n");
    printf("  Listening:     %d\n", listening);
    printf("  Established:   %d\n", established);
    printf("  Other states:  %d\n", other);
    printf("  Total sockets: %d\n", socket_count);
    printf("\n");
}

/*
 * Analyze orphaned sockets (no associated process)
 */
static void analyze_orphaned_sockets(void)
{
    printf(CYAN "  [Analysis]" RESET " Checking for orphaned/suspicious sockets:\n\n");

    int found = 0;

    for (int i = 0; i < socket_count; i++) {
        /* Skip TIME_WAIT and CLOSE sockets - these normally have no process */
        if (sockets[i].state == 6 || sockets[i].state == 7)
            continue;

        /* Skip sockets with inode 0 (kernel internal) */
        if (sockets[i].inode == 0)
            continue;

        if (!sockets[i].has_process) {
            char local_str[32], remote_str[32];
            hex_ip_to_str(sockets[i].local_ip, local_str, sizeof(local_str));
            hex_ip_to_str(sockets[i].remote_ip, remote_str, sizeof(remote_str));

            printf(RED "  [ORPHANED]" RESET
                   " %s:%u -> %s:%u (State: %s, Inode: %lu, UID: %d)\n",
                   local_str, sockets[i].local_port,
                   remote_str, sockets[i].remote_port,
                   get_tcp_state(sockets[i].state),
                   sockets[i].inode, sockets[i].uid);
            printf("    No process found owning this socket.\n");
            printf("    Possible causes:\n");
            printf("    - Process hidden by rootkit\n");
            printf("    - Race condition (process exited during scan)\n");
            printf("    - Kernel-managed socket\n\n");
            anomaly_count++;
            found++;
        }
    }

    if (found == 0) {
        printf(GREEN "  All active sockets have associated processes.\n" RESET);
    }
}

/*
 * Check for suspicious listening ports
 */
static void check_suspicious_ports(void)
{
    printf(CYAN "  [Analysis]" RESET " Checking for suspicious listening ports:\n\n");

    /* Common suspicious ports often used by backdoors */
    int suspicious_ports[] = {
        4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,
        1337, 31337, 12345, 54321, 1234, 3333,
        0  /* Sentinel */
    };

    int found = 0;

    for (int i = 0; i < socket_count; i++) {
        if (sockets[i].state != 10) continue; /* Only LISTEN */

        for (int j = 0; suspicious_ports[j] != 0; j++) {
            if (sockets[i].local_port == suspicious_ports[j]) {
                char local_str[32];
                hex_ip_to_str(sockets[i].local_ip, local_str, sizeof(local_str));

                printf(YELLOW "  [SUSPICIOUS PORT]" RESET
                       " Listening on %s:%d",
                       local_str, sockets[i].local_port);

                if (sockets[i].has_process)
                    printf(" (Process: %s, PID: %d)",
                           sockets[i].process_name, sockets[i].pid);
                else
                    printf(RED " [NO PROCESS!]" RESET);

                printf("\n");
                found++;
                break;
            }
        }
    }

    if (found == 0) {
        printf(GREEN "  No commonly suspicious ports detected.\n" RESET);
    }
    printf("\n");
}

static void print_summary(void)
{
    printf(CYAN "============================================\n");
    printf("  Scan Summary\n");
    printf("============================================\n" RESET);
    printf("  Total TCP sockets: %d\n", socket_count);
    printf("  Anomalies found:   %d\n", anomaly_count);
    printf("\n");

    if (anomaly_count > 0) {
        printf(YELLOW "  RESULT: Network anomalies detected.\n" RESET);
        printf("  Recommended actions:\n");
        printf("  1. Compare with external packet capture (network TAP)\n");
        printf("  2. Use 'ss -tulnp' and compare with this tool's output\n");
        printf("  3. Check netfilter hooks for hidden packet filtering\n");
        printf("  4. Run on-network IDS/IPS for independent verification\n");
    } else {
        printf(GREEN "  RESULT: No network anomalies detected.\n" RESET);
        printf("  Note: This tool relies on /proc/net/tcp which may be\n");
        printf("  compromised by a kernel rootkit. For highest assurance,\n");
        printf("  use external network monitoring.\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    int tcp4_count, tcp6_count;

    print_banner();

    if (geteuid() != 0) {
        printf(YELLOW "  WARNING: Running without root privileges.\n");
        printf("  Process-to-socket mapping will be incomplete.\n\n" RESET);
    }

    /* Parse TCP sockets */
    printf(CYAN "  [Phase 1]" RESET " Parsing /proc/net/tcp...\n");
    tcp4_count = parse_proc_net_tcp("/proc/net/tcp");
    printf("  Found %d IPv4 TCP sockets\n", tcp4_count);

    printf(CYAN "  [Phase 2]" RESET " Parsing /proc/net/tcp6...\n");
    tcp6_count = parse_proc_net_tcp("/proc/net/tcp6");
    printf("  Found %d IPv6 TCP sockets\n\n", tcp6_count > 0 ? tcp6_count : 0);

    /* Map sockets to processes */
    printf(CYAN "  [Phase 3]" RESET " Mapping sockets to processes...\n\n");
    map_sockets_to_processes();

    /* Display and analyze */
    display_sockets();
    analyze_orphaned_sockets();
    check_suspicious_ports();
    print_summary();

    return (anomaly_count > 0) ? 1 : 0;
}

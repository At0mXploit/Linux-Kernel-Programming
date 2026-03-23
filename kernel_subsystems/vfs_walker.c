/*
 * vfs_walker.c - Userspace program demonstrating VFS concepts
 *
 * Demonstrates VFS concepts by walking /proc/self/fd
 * to inspect the fd -> file -> dentry -> inode chain from user space.
 *
 * This program opens several files and then inspects its own file
 * descriptor table via /proc/self/fd and /proc/self/fdinfo to show
 * how the VFS data structures relate.
 *
 * Concepts demonstrated:
 *   - File descriptor table structure
 *   - Inode information via stat()
 *   - File position and flags via /proc/self/fdinfo
 *   - Hard link detection (multiple dentries -> same inode)
 *   - Special file types (pipe, socket, etc.)
 *   - Mount information via /proc/self/mountinfo
 *
 * Compile:
 *   gcc -O2 -Wall -o vfs_walker vfs_walker.c
 *
 * Run:
 *   ./vfs_walker
 *
 * License: GPL v2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_PATH 4096
#define MAX_LINE 512

/* ──────────────── Helper functions ──────────────── */

/*
 * get_file_type_string - Convert st_mode file type to string
 */
static const char *get_file_type_string(mode_t mode)
{
    switch (mode & S_IFMT) {
    case S_IFREG:  return "Regular file";
    case S_IFDIR:  return "Directory";
    case S_IFLNK:  return "Symbolic link";
    case S_IFCHR:  return "Character device";
    case S_IFBLK:  return "Block device";
    case S_IFIFO:  return "FIFO/Pipe";
    case S_IFSOCK: return "Socket";
    default:       return "Unknown";
    }
}

/*
 * get_mount_info - Find the mount ID and filesystem type for a path
 *
 * Reads /proc/self/mountinfo to find the mount that contains
 * the given device and inode.
 */
static void get_mount_info(dev_t dev, char *fs_type, size_t fs_type_size,
                            char *mount_point, size_t mp_size)
{
    FILE *fp;
    char line[1024];
    unsigned int major = major(dev);
    unsigned int minor = minor(dev);
    char dev_str[32];

    snprintf(dev_str, sizeof(dev_str), "%u:%u", major, minor);
    strncpy(fs_type, "unknown", fs_type_size);
    strncpy(mount_point, "unknown", mp_size);

    fp = fopen("/proc/self/mountinfo", "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        /*
         * mountinfo format (space-separated):
         * mount_id parent_id major:minor root mount_point ... - fs_type source options
         */
        char *dash, *fs, *mp_field;
        char mdev[32];
        int mid, pid;

        if (sscanf(line, "%d %d %31s", &mid, &pid, mdev) < 3)
            continue;

        if (strcmp(mdev, dev_str) != 0)
            continue;

        /* Found matching device. Extract mount point. */
        char *fields[10];
        char *p = line;
        int fi = 0;

        /* Parse space-separated fields */
        while (*p && fi < 10) {
            while (*p == ' ') p++;
            fields[fi++] = p;
            while (*p && *p != ' ' && *p != '\n') p++;
            if (*p) *p++ = '\0';
        }

        if (fi >= 5) {
            strncpy(mount_point, fields[4], mp_size - 1);
            mount_point[mp_size - 1] = '\0';
        }

        /* Find the "-" separator to get fs_type */
        dash = strstr(line + (p - line), "- ");
        if (!dash) {
            /* Search the original line */
            char linecopy[1024];
            /* re-read since we modified line */
            rewind(fp);
            while (fgets(linecopy, sizeof(linecopy), fp)) {
                if (strstr(linecopy, dev_str)) {
                    dash = strstr(linecopy, " - ");
                    if (dash) {
                        dash += 3;
                        fs = dash;
                        char *sp = strchr(fs, ' ');
                        if (sp) *sp = '\0';
                        strncpy(fs_type, fs, fs_type_size - 1);
                        fs_type[fs_type_size - 1] = '\0';
                    }
                    break;
                }
            }
        }
        break;
    }

    fclose(fp);
}

/*
 * read_fdinfo - Read /proc/self/fdinfo/<fd> for file offset and flags
 */
static void read_fdinfo(int fd, off_t *pos, unsigned int *flags,
                         int *mnt_id)
{
    char path[128];
    char line[MAX_LINE];
    FILE *fp;

    *pos = 0;
    *flags = 0;
    *mnt_id = -1;

    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    fp = fopen(path, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "pos:", 4) == 0)
            sscanf(line + 4, "%ld", pos);
        else if (strncmp(line, "flags:", 6) == 0)
            sscanf(line + 6, "%o", flags);
        else if (strncmp(line, "mnt_id:", 7) == 0)
            sscanf(line + 7, "%d", mnt_id);
    }

    fclose(fp);
}

/*
 * print_separator - Print a visual separator line
 */
static void print_separator(void)
{
    printf("    +------+----------------------------------------------"
           "-------------------+\n");
}

/*
 * inspect_fd - Inspect a single file descriptor
 *
 * This demonstrates the fd -> file -> dentry -> inode chain:
 *   fd          -> index in the file descriptor table
 *   readlink    -> file path (dentry d_name chain)
 *   fdinfo      -> file offset (f_pos), flags (f_flags)
 *   fstat       -> inode information (i_ino, i_mode, i_size, etc.)
 */
static void inspect_fd(int fd)
{
    char link_path[64];
    char target[MAX_PATH];
    struct stat st;
    ssize_t len;
    off_t pos;
    unsigned int flags;
    int mnt_id;
    char fs_type[64];
    char mount_point[256];

    /* Read the symlink /proc/self/fd/<fd> to get the file path */
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    len = readlink(link_path, target, sizeof(target) - 1);
    if (len < 0) {
        printf("    | %4d | (error reading link: %s)\n", fd, strerror(errno));
        return;
    }
    target[len] = '\0';

    /* Get inode info via fstat */
    if (fstat(fd, &st) < 0) {
        printf("    | %4d | %s (fstat error: %s)\n",
               fd, target, strerror(errno));
        return;
    }

    /* Get file position and flags from fdinfo */
    read_fdinfo(fd, &pos, &flags, &mnt_id);

    /* Get filesystem type */
    get_mount_info(st.st_dev, fs_type, sizeof(fs_type),
                   mount_point, sizeof(mount_point));

    /* Print fd -> file information */
    print_separator();
    printf("    | %4d | Path: %-50s |\n", fd, target);
    printf("    |      | Type: %-20s  Mode: %06o  %-14s |\n",
           get_file_type_string(st.st_mode),
           st.st_mode & 07777, "");
    printf("    |      | Inode: %-10lu  Device: %u:%u  "
           "Nlink: %-10lu |\n",
           (unsigned long)st.st_ino,
           major(st.st_dev), minor(st.st_dev),
           (unsigned long)st.st_nlink);
    printf("    |      | Size: %-12ld  Blocks: %-8ld  "
           "BlkSize: %-7ld |\n",
           (long)st.st_size, (long)st.st_blocks,
           (long)st.st_blksize);
    printf("    |      | f_pos: %-11ld  f_flags: 0%06o  "
           "mnt_id: %-6d |\n",
           (long)pos, flags, mnt_id);
    printf("    |      | UID: %-6u  GID: %-6u  "
           "FS: %-20s |\n",
           st.st_uid, st.st_gid, fs_type);
}

/* ──────────────── Main program ──────────────── */

int main(int argc, char **argv)
{
    int fd_regular, fd_readonly, fd_pipe[2], fd_socket;
    int fd_dev_null;
    DIR *dir;
    struct dirent *entry;
    int fds[64];
    int fd_count = 0;
    char tmpfile[] = "/tmp/vfs_walker_XXXXXX";

    printf("============================================================\n");
    printf("   VFS Walker - Exploring the fd -> file -> dentry -> inode\n");
    printf("   chain from user space via /proc/self/fd\n");
    printf("============================================================\n\n");

    /* ── Step 1: Open various types of files to create interesting fds ── */
    printf("[*] Opening various file types to populate fd table...\n\n");

    /* Create a temp file and write some data */
    fd_regular = mkstemp(tmpfile);
    if (fd_regular >= 0) {
        const char *msg = "Hello from VFS Walker!\n";
        write(fd_regular, msg, strlen(msg));
        /* Seek partway through to show non-zero f_pos */
        lseek(fd_regular, 5, SEEK_SET);
        printf("    Opened temp file: %s (fd=%d)\n", tmpfile, fd_regular);
    }

    /* Open a file read-only */
    fd_readonly = open("/etc/hostname", O_RDONLY);
    if (fd_readonly >= 0) {
        char buf[16];
        read(fd_readonly, buf, 10);  /* advance f_pos */
        printf("    Opened /etc/hostname read-only (fd=%d)\n", fd_readonly);
    }

    /* Create a pipe */
    if (pipe(fd_pipe) == 0) {
        printf("    Created pipe: read_end=%d, write_end=%d\n",
               fd_pipe[0], fd_pipe[1]);
    }

    /* Create a socket */
    fd_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_socket >= 0) {
        printf("    Created TCP socket (fd=%d)\n", fd_socket);
    }

    /* Open /dev/null */
    fd_dev_null = open("/dev/null", O_WRONLY);
    if (fd_dev_null >= 0) {
        printf("    Opened /dev/null (fd=%d)\n", fd_dev_null);
    }

    printf("\n");

    /* ── Step 2: Walk /proc/self/fd to enumerate all open fds ── */
    printf("[*] Walking /proc/self/fd (our process fd table):\n\n");

    printf("    ┌──────────────────────────────────────────────────"
           "────────────────────┐\n");
    printf("    │  FD Table → struct file → struct dentry → "
           "struct inode              │\n");
    printf("    │  (Process-local)  (Shared)       (Cached)       "
           "(On-disk/in-mem)     │\n");
    printf("    └──────────────────────────────────────────────────"
           "────────────────────┘\n");

    dir = opendir("/proc/self/fd");
    if (!dir) {
        perror("Cannot open /proc/self/fd");
        goto cleanup;
    }

    /* Collect fd numbers first, then inspect (to avoid the opendir fd) */
    while ((entry = readdir(dir)) != NULL) {
        int fd;
        if (entry->d_name[0] == '.')
            continue;
        fd = atoi(entry->d_name);
        if (fd_count < 64)
            fds[fd_count++] = fd;
    }
    closedir(dir);

    /* Sort fds for clean output */
    for (int i = 0; i < fd_count - 1; i++)
        for (int j = i + 1; j < fd_count; j++)
            if (fds[i] > fds[j]) {
                int tmp = fds[i];
                fds[i] = fds[j];
                fds[j] = tmp;
            }

    /* Inspect each fd */
    for (int i = 0; i < fd_count; i++)
        inspect_fd(fds[i]);

    print_separator();

    printf("\n    Total file descriptors: %d\n", fd_count);

    /* ── Step 3: Demonstrate inode sharing (hard links) ── */
    printf("\n[*] Demonstrating inode sharing:\n\n");
    {
        struct stat st1, st2;
        if (fstat(0, &st1) == 0 && fstat(1, &st2) == 0) {
            if (st1.st_ino == st2.st_ino && st1.st_dev == st2.st_dev)
                printf("    fd 0 (stdin) and fd 1 (stdout) share the same "
                       "inode %lu\n    -> They point to the same underlying "
                       "file object\n",
                       (unsigned long)st1.st_ino);
            else
                printf("    fd 0 (stdin) inode=%lu, fd 1 (stdout) inode=%lu\n"
                       "    -> Different inodes (different files)\n",
                       (unsigned long)st1.st_ino, (unsigned long)st2.st_ino);
        }
    }

    /* ── Step 4: Show process fs information ── */
    printf("\n[*] Process filesystem context:\n\n");
    {
        char buf[MAX_PATH];
        ssize_t len;

        len = readlink("/proc/self/cwd", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            printf("    Current directory (fs->pwd):  %s\n", buf);
        }

        len = readlink("/proc/self/root", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            printf("    Root directory (fs->root):    %s\n", buf);
        }

        len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            printf("    Executable (mm->exe_file):    %s\n", buf);
        }
    }

cleanup:
    /* ── Step 5: Clean up ── */
    printf("\n[*] Cleaning up...\n");

    if (fd_regular >= 0) {
        close(fd_regular);
        unlink(tmpfile);
    }
    if (fd_readonly >= 0)
        close(fd_readonly);
    if (fd_pipe[0] >= 0) {
        close(fd_pipe[0]);
        close(fd_pipe[1]);
    }
    if (fd_socket >= 0)
        close(fd_socket);
    if (fd_dev_null >= 0)
        close(fd_dev_null);

    printf("\n============================================================\n");
    printf("   VFS Walker complete.\n");
    printf("============================================================\n");

    return 0;
}

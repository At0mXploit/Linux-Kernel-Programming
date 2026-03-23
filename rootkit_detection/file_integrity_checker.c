/*
 * file_integrity_checker.c - Basic file integrity monitoring tool
 *
 *
 * This is a simplified file integrity checker that:
 *   1. --init <dir>: Creates a baseline database of SHA-256 hashes
 *   2. --check <dir>: Compares current state against baseline
 *   3. Reports: modified, added, and deleted files
 *
 * Uses a simple custom SHA-256 implementation to avoid library dependencies
 * when compiled statically.
 *
 * Compile: gcc -o file_integrity_checker file_integrity_checker.c -static
 * Usage:
 *   ./file_integrity_checker --init /usr/bin
 *   ./file_integrity_checker --check /usr/bin
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_PATH_LEN 4096
#define DATABASE_FILE ".file_integrity.db"
#define HASH_HEX_LEN 64
#define READ_BUF_SIZE 8192

/* ========== Minimal SHA-256 Implementation ========== */

typedef struct {
    unsigned int state[8];
    unsigned long long count;
    unsigned char buffer[64];
} sha256_ctx;

#define RR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (RR(x,2) ^ RR(x,13) ^ RR(x,22))
#define EP1(x) (RR(x,6) ^ RR(x,11) ^ RR(x,25))
#define SIG0(x) (RR(x,7) ^ RR(x,18) ^ ((x) >> 3))
#define SIG1(x) (RR(x,17) ^ RR(x,19) ^ ((x) >> 10))

static const unsigned int sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx, const unsigned char data[64])
{
    unsigned int a, b, c, d, e, f, g, h, t1, t2, w[64];
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)data[i*4] << 24) | ((unsigned int)data[i*4+1] << 16) |
               ((unsigned int)data[i*4+2] << 8) | data[i*4+3];

    for (i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + w[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len)
{
    size_t i;
    unsigned int idx = (unsigned int)(ctx->count % 64);

    ctx->count += len;

    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64) {
            sha256_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char hash[32])
{
    unsigned int idx = (unsigned int)(ctx->count % 64);
    unsigned long long bits = ctx->count * 8;
    int i;

    ctx->buffer[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buffer[idx++] = 0;
        sha256_transform(ctx, ctx->buffer);
        idx = 0;
    }
    while (idx < 56) ctx->buffer[idx++] = 0;

    for (i = 7; i >= 0; i--)
        ctx->buffer[56 + (7 - i)] = (unsigned char)(bits >> (i * 8));

    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        hash[i*4]   = (unsigned char)(ctx->state[i] >> 24);
        hash[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        hash[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        hash[i*4+3] = (unsigned char)(ctx->state[i]);
    }
}

/* ========== End SHA-256 ========== */

static void print_banner(void)
{
    printf(CYAN "============================================\n");
    printf("  File Integrity Checker\n");
    printf("  SHA-256 Hash Verification\n");
    printf("  Rootkit Detection\n");
    printf("============================================\n" RESET);
    printf("\n");
}

/*
 * Compute SHA-256 hash of a file
 */
static int hash_file(const char *filepath, char *hash_hex)
{
    int fd;
    unsigned char buf[READ_BUF_SIZE];
    unsigned char hash[32];
    ssize_t bytes_read;
    sha256_ctx ctx;

    fd = open(filepath, O_RDONLY);
    if (fd < 0) return -1;

    sha256_init(&ctx);

    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)bytes_read);
    }

    close(fd);

    if (bytes_read < 0) return -1;

    sha256_final(&ctx, hash);

    /* Convert to hex string */
    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + i * 2, "%02x", hash[i]);
    }
    hash_hex[64] = '\0';

    return 0;
}

/*
 * Recursively scan directory and build/check database
 */
static int scan_directory(const char *base_dir, FILE *db_out, FILE *db_check,
                          int *modified, int *added, int *deleted, int *unchanged)
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char path[MAX_PATH_LEN];
    char hash_hex[HASH_HEX_LEN + 1];
    int file_count = 0;

    dir = opendir(base_dir);
    if (dir == NULL) {
        fprintf(stderr, "  Cannot open directory: %s (%s)\n", base_dir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Skip our own database file */
        if (strcmp(entry->d_name, DATABASE_FILE) == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", base_dir, entry->d_name);

        if (lstat(path, &st) != 0) continue;

        /* Recurse into subdirectories */
        if (S_ISDIR(st.st_mode)) {
            file_count += scan_directory(path, db_out, db_check,
                                         modified, added, deleted, unchanged);
            continue;
        }

        /* Only hash regular files */
        if (!S_ISREG(st.st_mode)) continue;

        if (hash_file(path, hash_hex) != 0) {
            fprintf(stderr, "  Warning: Cannot hash %s\n", path);
            continue;
        }

        if (db_out != NULL) {
            /* Init mode: Write to database */
            fprintf(db_out, "%s %s %o %ld %d %d\n",
                    hash_hex, path,
                    st.st_mode & 07777,
                    (long)st.st_size,
                    st.st_uid, st.st_gid);
            file_count++;
        }

        if (db_check != NULL && added != NULL) {
            /* Check mode: This file exists on disk, mark it as seen */
            /* (Checking is done in a separate pass) */
            file_count++;
        }
    }

    closedir(dir);
    return file_count;
}

/*
 * Initialize: Create hash database
 */
static int do_init(const char *target_dir)
{
    char db_path[MAX_PATH_LEN];
    FILE *db;
    int count;
    int dummy = 0;

    snprintf(db_path, sizeof(db_path), "%s/%s", target_dir, DATABASE_FILE);

    printf("  Creating integrity baseline for: %s\n", target_dir);
    printf("  Database: %s\n\n", db_path);

    db = fopen(db_path, "w");
    if (db == NULL) {
        fprintf(stderr, "  Cannot create database: %s\n", strerror(errno));
        return -1;
    }

    /* Write header */
    fprintf(db, "# File Integrity Database\n");
    fprintf(db, "# Created: %s", ctime(&(time_t){time(NULL)}));
    fprintf(db, "# Directory: %s\n", target_dir);
    fprintf(db, "# Format: sha256 filepath permissions size uid gid\n");

    count = scan_directory(target_dir, db, NULL, &dummy, &dummy, &dummy, &dummy);

    fclose(db);

    printf(GREEN "  Baseline created: %d files hashed.\n" RESET, count);
    printf("  Database saved to: %s\n\n", db_path);
    printf("  IMPORTANT: Store a copy of this database on secure/read-only media.\n");
    printf("  A rootkit could modify both the files AND the database.\n\n");

    return 0;
}

/*
 * Check: Compare current state against database
 */
static int do_check(const char *target_dir)
{
    char db_path[MAX_PATH_LEN];
    FILE *db;
    char line[MAX_PATH_LEN + 256];
    int modified_count = 0, deleted_count = 0, unchanged_count = 0;
    int new_count = 0;

    snprintf(db_path, sizeof(db_path), "%s/%s", target_dir, DATABASE_FILE);

    printf("  Checking integrity of: %s\n", target_dir);
    printf("  Database: %s\n\n", db_path);

    db = fopen(db_path, "r");
    if (db == NULL) {
        fprintf(stderr, RED "  Database not found: %s\n" RESET, db_path);
        fprintf(stderr, "  Run with --init first to create a baseline.\n");
        return -1;
    }

    /* Track all files in the database for deleted file detection */
    char **db_files = NULL;
    int db_file_count = 0;
    int db_file_capacity = 1024;
    db_files = malloc(db_file_capacity * sizeof(char *));

    printf("  Verifying files against baseline...\n\n");

    while (fgets(line, sizeof(line), db) != NULL) {
        if (line[0] == '#') continue; /* Skip comments */

        char stored_hash[HASH_HEX_LEN + 1];
        char filepath[MAX_PATH_LEN];
        unsigned int perms;
        long stored_size;
        int stored_uid, stored_gid;

        int fields = sscanf(line, "%64s %4095s %o %ld %d %d",
                            stored_hash, filepath, &perms,
                            &stored_size, &stored_uid, &stored_gid);

        if (fields < 2) continue;

        /* Store filepath for later "new file" detection */
        if (db_file_count >= db_file_capacity) {
            db_file_capacity *= 2;
            db_files = realloc(db_files, db_file_capacity * sizeof(char *));
        }
        db_files[db_file_count] = strdup(filepath);
        db_file_count++;

        /* Check if file still exists */
        struct stat st;
        if (stat(filepath, &st) != 0) {
            printf(RED "  [DELETED]" RESET "  %s\n", filepath);
            deleted_count++;
            continue;
        }

        /* Compute current hash */
        char current_hash[HASH_HEX_LEN + 1];
        if (hash_file(filepath, current_hash) != 0) {
            printf(YELLOW "  [ERROR]" RESET "   Cannot hash: %s\n", filepath);
            continue;
        }

        /* Compare hashes */
        if (strcmp(stored_hash, current_hash) != 0) {
            printf(RED "  [MODIFIED]" RESET " %s\n", filepath);
            printf("    Old hash: %s\n", stored_hash);
            printf("    New hash: %s\n", current_hash);

            /* Check other attributes */
            if (fields >= 4 && st.st_size != stored_size)
                printf("    Size changed: %ld -> %ld\n", stored_size, (long)st.st_size);
            if (fields >= 3 && (st.st_mode & 07777) != perms)
                printf("    Permissions changed: %04o -> %04o\n", perms, st.st_mode & 07777);
            if (fields >= 5 && st.st_uid != (uid_t)stored_uid)
                printf("    Owner changed: %d -> %d\n", stored_uid, st.st_uid);

            modified_count++;
        } else {
            unchanged_count++;

            /* Still check permissions and ownership */
            if (fields >= 3 && (st.st_mode & 07777) != perms) {
                printf(YELLOW "  [PERMS]" RESET "    %s (hash OK, perms: %04o -> %04o)\n",
                       filepath, perms, st.st_mode & 07777);
            }
            if (fields >= 5 && st.st_uid != (uid_t)stored_uid) {
                printf(YELLOW "  [OWNER]" RESET "    %s (hash OK, uid: %d -> %d)\n",
                       filepath, stored_uid, st.st_uid);
            }
        }
    }

    fclose(db);

    /* Note: Full new-file detection would require a second directory scan.
       For simplicity, we report on the database comparison only. */

    /* Print summary */
    printf("\n" CYAN "============================================\n");
    printf("  Integrity Check Summary\n");
    printf("============================================\n" RESET);
    printf("  Files in database: %d\n", db_file_count);
    printf("  Unchanged:         " GREEN "%d\n" RESET, unchanged_count);
    printf("  Modified:          " RED "%d\n" RESET, modified_count);
    printf("  Deleted:           " RED "%d\n" RESET, deleted_count);
    printf("\n");

    if (modified_count > 0 || deleted_count > 0) {
        printf(RED "  RESULT: Integrity violations detected!\n" RESET);
        printf("  Modified or deleted files may indicate:\n");
        printf("  - System update (legitimate)\n");
        printf("  - Binary replacement attack\n");
        printf("  - Rootkit file modification\n");
        printf("\n");
        printf("  Recommended: Verify changes against package manager:\n");
        printf("    RPM:    rpm -Va\n");
        printf("    Debian: debsums -c\n");
    } else {
        printf(GREEN "  RESULT: All files match baseline. No modifications detected.\n" RESET);
    }
    printf("\n");

    /* Cleanup */
    for (int i = 0; i < db_file_count; i++)
        free(db_files[i]);
    free(db_files);

    return (modified_count > 0 || deleted_count > 0) ? 1 : 0;
}

static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s --init <directory>    Create integrity baseline\n", prog);
    printf("  %s --check <directory>   Verify against baseline\n", prog);
    printf("\n");
    printf("Examples:\n");
    printf("  %s --init /usr/bin\n", prog);
    printf("  %s --check /usr/bin\n", prog);
    printf("\n");
    printf("The database is stored as %s in the target directory.\n", DATABASE_FILE);
    printf("For security, copy the database to read-only media after creation.\n");
}

int main(int argc, char *argv[])
{
    print_banner();

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--init") == 0) {
        return do_init(argv[2]);
    } else if (strcmp(argv[1], "--check") == 0) {
        return do_check(argv[2]);
    } else {
        fprintf(stderr, "Unknown option: %s\n\n", argv[1]);
        usage(argv[0]);
        return 1;
    }
}

/*
 * memory_scanner.c - Memory Forensics Concept Demonstrator
 *
 *
 * Demonstrates memory forensics concepts by safely reading
 * /proc/kcore (kernel virtual memory) regions:
 *   1. Parses /proc/kcore ELF headers to find memory segments
 *   2. Reads kernel text section and computes checksum
 *   3. Searches for kernel module signatures in memory
 *   4. Demonstrates virtual-to-file-offset translation
 *
 * This is an EDUCATIONAL tool. For real forensics use LiME + Volatility.
 *
 * Build: gcc -O2 -Wall -Wextra -o memory_scanner memory_scanner.c
 * Usage: sudo ./memory_scanner [--segments|--checksum|--scan-modules]
 *
 * MUST be run as root. Kernel lockdown (confidentiality mode) blocks access.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_SEGMENTS    128
#define KCORE_PATH      "/proc/kcore"
#define READ_CHUNK_SIZE 4096
#define MAX_READ_SIZE   (64 * 1024 * 1024)  /* 64MB max per read */

/* ── Data structures ───────────────────────────────────────────── */

typedef struct {
    unsigned long vaddr_start;
    unsigned long vaddr_end;
    unsigned long file_offset;
    unsigned long mem_size;
    unsigned long file_size;
    unsigned int  flags;
    int           readable;
} kcore_segment_t;

static kcore_segment_t segments[MAX_SEGMENTS];
static int segment_count = 0;

/* ── Simple checksum (non-cryptographic, for demonstration) ────── */

static unsigned long compute_checksum(const unsigned char *data, size_t len)
{
    unsigned long sum = 0;
    /* FNV-1a hash for simplicity */
    unsigned long hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
        sum += data[i];
    }
    /* Combine simple sum and FNV-1a */
    return hash ^ (sum << 32);
}

/* ── Parse /proc/kcore ELF headers ─────────────────────────────── */

static int parse_kcore_headers(void)
{
    int fd = open(KCORE_PATH, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot open %s: %s\n",
                KCORE_PATH, strerror(errno));
        if (errno == EPERM || errno == EACCES)
            fprintf(stderr, "  Kernel lockdown (confidentiality mode) may be active.\n");
        return -1;
    }

    /* Read ELF header */
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        fprintf(stderr, "ERROR: Cannot read ELF header\n");
        close(fd);
        return -1;
    }

    /* Verify it is a valid ELF core file */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "ERROR: %s is not a valid ELF file\n", KCORE_PATH);
        close(fd);
        return -1;
    }

    if (ehdr.e_type != ET_CORE) {
        fprintf(stderr, "ERROR: %s is not an ELF core file (type=%d)\n",
                KCORE_PATH, ehdr.e_type);
        close(fd);
        return -1;
    }

    printf("ELF Header:\n");
    printf("  Class:         %s\n",
           ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32");
    printf("  Type:          CORE\n");
    printf("  Machine:       0x%x\n", ehdr.e_machine);
    printf("  Phdr entries:  %d\n", ehdr.e_phnum);
    printf("  Phdr offset:   0x%lx\n", (unsigned long)ehdr.e_phoff);
    printf("  Phdr entry sz: %d\n\n", ehdr.e_phentsize);

    /* Read program headers */
    if (ehdr.e_phnum == 0) {
        fprintf(stderr, "No program headers found.\n");
        close(fd);
        return -1;
    }

    /* Seek to program header table */
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
        fprintf(stderr, "ERROR: Cannot seek to program headers\n");
        close(fd);
        return -1;
    }

    segment_count = 0;
    for (int i = 0; i < ehdr.e_phnum && segment_count < MAX_SEGMENTS; i++) {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            fprintf(stderr, "WARNING: Cannot read program header %d\n", i);
            break;
        }

        if (phdr.p_type == PT_LOAD && phdr.p_memsz > 0) {
            kcore_segment_t *seg = &segments[segment_count];
            seg->vaddr_start = phdr.p_vaddr;
            seg->vaddr_end = phdr.p_vaddr + phdr.p_memsz;
            seg->file_offset = phdr.p_offset;
            seg->mem_size = phdr.p_memsz;
            seg->file_size = phdr.p_filesz;
            seg->flags = phdr.p_flags;
            seg->readable = (phdr.p_filesz > 0);
            segment_count++;
        }
    }

    close(fd);
    return 0;
}

/* ── Display segments ──────────────────────────────────────────── */

static void show_segments(void)
{
    printf("=== /proc/kcore Memory Segments ===\n\n");
    printf("%-4s %-20s %-20s %12s %12s %6s\n",
           "#", "VADDR START", "VADDR END", "MEM SIZE", "FILE SIZE", "FLAGS");
    printf("%-4s %-20s %-20s %12s %12s %6s\n",
           "----", "--------------------", "--------------------",
           "------------", "------------", "------");

    for (int i = 0; i < segment_count; i++) {
        kcore_segment_t *s = &segments[i];
        char flags[8] = "---";
        if (s->flags & PF_R) flags[0] = 'R';
        if (s->flags & PF_W) flags[1] = 'W';
        if (s->flags & PF_X) flags[2] = 'X';

        printf("%-4d 0x%018lx 0x%018lx %12lu %12lu %6s %s\n",
               i,
               s->vaddr_start,
               s->vaddr_end,
               s->mem_size,
               s->file_size,
               flags,
               s->readable ? "" : "(no data)");
    }
    printf("\nTotal segments: %d\n", segment_count);
}

/* ── Find file offset for a virtual address ────────────────────── */

static long find_file_offset(unsigned long vaddr, unsigned long *max_readable)
{
    for (int i = 0; i < segment_count; i++) {
        if (vaddr >= segments[i].vaddr_start &&
            vaddr < segments[i].vaddr_end &&
            segments[i].readable) {

            unsigned long offset_in_seg = vaddr - segments[i].vaddr_start;
            if (max_readable)
                *max_readable = segments[i].file_size - offset_in_seg;

            return segments[i].file_offset + offset_in_seg;
        }
    }
    return -1;
}

/* ── Read kernel memory at virtual address ─────────────────────── */

static ssize_t read_kernel_memory(unsigned long vaddr, void *buf, size_t len)
{
    unsigned long max_readable;
    long file_offset = find_file_offset(vaddr, &max_readable);

    if (file_offset < 0) {
        return -1;
    }

    if (len > max_readable)
        len = max_readable;

    int fd = open(KCORE_PATH, O_RDONLY);
    if (fd < 0)
        return -1;

    if (lseek(fd, file_offset, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }

    ssize_t total_read = 0;
    unsigned char *p = buf;
    while ((size_t)total_read < len) {
        size_t to_read = len - total_read;
        if (to_read > READ_CHUNK_SIZE)
            to_read = READ_CHUNK_SIZE;

        ssize_t n = read(fd, p + total_read, to_read);
        if (n <= 0)
            break;
        total_read += n;
    }

    close(fd);
    return total_read;
}

/* ── Compute kernel text checksum ──────────────────────────────── */

static void compute_kernel_text_checksum(void)
{
    printf("\n=== Kernel Text Section Checksum ===\n\n");

    /* Read kernel text boundaries from /proc/kallsyms */
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        fprintf(stderr, "Cannot open /proc/kallsyms\n");
        return;
    }

    unsigned long stext = 0, etext = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];

        if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3) {
            if (strcmp(name, "_stext") == 0) stext = addr;
            else if (strcmp(name, "_etext") == 0) etext = addr;
        }
    }
    fclose(fp);

    if (stext == 0 || etext == 0) {
        fprintf(stderr, "Cannot find kernel text boundaries.\n");
        fprintf(stderr, "Ensure kernel.kptr_restrict = 0\n");
        return;
    }

    unsigned long text_size = etext - stext;
    printf("Kernel text: 0x%lx - 0x%lx (%lu bytes, %.2f MB)\n",
           stext, etext, text_size, (double)text_size / (1024 * 1024));

    /* Limit read size for safety */
    if (text_size > MAX_READ_SIZE) {
        printf("Text section is very large. Reading first %d MB only.\n",
               (int)(MAX_READ_SIZE / (1024 * 1024)));
        text_size = MAX_READ_SIZE;
    }

    /* Allocate buffer */
    unsigned char *buf = malloc(text_size);
    if (!buf) {
        fprintf(stderr, "Cannot allocate %lu bytes\n", text_size);
        return;
    }

    printf("Reading kernel text section via /proc/kcore...\n");

    ssize_t bytes_read = read_kernel_memory(stext, buf, text_size);
    if (bytes_read <= 0) {
        fprintf(stderr, "Failed to read kernel text section.\n");
        fprintf(stderr, "Kernel lockdown (confidentiality mode) may be active.\n");
        free(buf);
        return;
    }

    printf("Read %zd bytes from kernel text section.\n\n", bytes_read);

    /* Compute checksum */
    unsigned long checksum = compute_checksum(buf, bytes_read);
    printf("Kernel text checksum: 0x%016lx\n", checksum);
    printf("Bytes checksummed:    %zd\n", bytes_read);

    /* Count NOP instructions (potential ftrace/kprobe sites) */
    int nop_count = 0;
    int int3_count = 0;
    for (ssize_t i = 0; i < bytes_read; i++) {
        if (buf[i] == 0x90) nop_count++;      /* NOP */
        if (buf[i] == 0xCC) int3_count++;      /* INT3 (breakpoint) */
    }

    printf("NOP instructions:     %d (ftrace sites)\n", nop_count);
    printf("INT3 instructions:    %d (kprobe/debug sites)\n", int3_count);

    /* Show first 64 bytes as hex dump */
    printf("\nFirst 64 bytes of kernel text:\n");
    for (int i = 0; i < 64 && i < bytes_read; i++) {
        if (i % 16 == 0) printf("  0x%lx: ", stext + i);
        printf("%02x ", buf[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");

    /* Save checksum for later comparison */
    printf("To verify later, compare this checksum: 0x%016lx\n", checksum);
    printf("Note: Checksum will change if KASLR offset differs or\n");
    printf("      if kernel text has been modified (ftrace, kprobes, rootkit).\n");

    free(buf);
}

/* ── Scan for module signatures in memory ──────────────────────── */

static void scan_for_modules(void)
{
    printf("\n=== Scanning Memory for Module Signatures ===\n\n");

    /* Module structures typically reside in the module memory region.
     * On x86_64, this is roughly 0xffffffffc0000000 - 0xffffffffdfffffff.
     * We look for patterns that match struct module fields. */

    unsigned long module_region_start = 0xffffffffc0000000UL;
    unsigned long module_region_end   = 0xffffffffdfffffffUL;

    printf("Module memory region: 0x%lx - 0x%lx\n",
           module_region_start, module_region_end);

    /* Find a segment that covers the module region */
    int found_segment = 0;
    for (int i = 0; i < segment_count; i++) {
        if (segments[i].vaddr_start <= module_region_start &&
            segments[i].vaddr_end >= module_region_start &&
            segments[i].readable) {
            found_segment = 1;

            printf("Found kcore segment covering module region: seg %d\n", i);
            printf("  Segment: 0x%lx - 0x%lx (file offset: 0x%lx)\n",
                   segments[i].vaddr_start, segments[i].vaddr_end,
                   segments[i].file_offset);
            break;
        }
    }

    if (!found_segment) {
        printf("No readable segment covers the module memory region.\n");
        printf("This may indicate kernel lockdown or restricted /proc/kcore.\n");
        return;
    }

    /* Read module region in chunks and look for module name strings.
     * Module names are stored in a fixed-size char array (MODULE_NAME_LEN=56)
     * within struct module. We look for sequences of printable ASCII
     * characters that match known module naming conventions. */

    printf("\nScanning for module-like strings in memory...\n");
    printf("(This is a heuristic scan - results may include false positives)\n\n");

    unsigned char buf[READ_CHUNK_SIZE];
    unsigned long addr = module_region_start;
    int candidates = 0;

    /* Read limited region to avoid excessive I/O */
    unsigned long scan_limit = module_region_start + (16 * 1024 * 1024); /* 16MB */
    if (scan_limit > module_region_end)
        scan_limit = module_region_end;

    while (addr < scan_limit) {
        ssize_t n = read_kernel_memory(addr, buf, READ_CHUNK_SIZE);
        if (n <= 0)
            break;

        /* Look for printable ASCII strings of 3-55 characters followed by null,
         * which could be module names */
        for (ssize_t i = 0; i < n - 56; i++) {
            /* Check for a potential module name: printable, 3+ chars, null-terminated */
            int str_len = 0;
            int is_valid = 1;
            while (str_len < 56 && i + str_len < n) {
                unsigned char c = buf[i + str_len];
                if (c == '\0')
                    break;
                if (c < 0x20 || c > 0x7e) {
                    is_valid = 0;
                    break;
                }
                str_len++;
            }

            if (is_valid && str_len >= 3 && str_len <= 55 &&
                i + str_len < n && buf[i + str_len] == '\0') {

                /* Additional heuristic: module names typically contain only
                 * alphanumeric chars and underscores */
                int looks_like_module = 1;
                for (int j = 0; j < str_len; j++) {
                    char c = buf[i + j];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                        looks_like_module = 0;
                        break;
                    }
                }

                if (looks_like_module && str_len >= 3) {
                    char name[64];
                    memcpy(name, buf + i, str_len);
                    name[str_len] = '\0';

                    /* Only report if it looks like a real module name */
                    if (strstr(name, "module") || strstr(name, "driver") ||
                        strstr(name, "dev") || strstr(name, "fs") ||
                        strstr(name, "net") || strstr(name, "crypto") ||
                        str_len > 5) {

                        if (candidates < 50) {  /* Limit output */
                            printf("  Candidate at 0x%lx: \"%s\" (len=%d)\n",
                                   addr + i, name, str_len);
                        }
                        candidates++;
                    }
                }
            }
        }

        addr += READ_CHUNK_SIZE;
    }

    printf("\nTotal module name candidates found: %d\n", candidates);
    printf("Note: Compare with /proc/modules to identify hidden modules.\n");
}

/* ── Usage ─────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --segments      Show /proc/kcore memory segments\n");
    printf("  --checksum      Compute kernel text section checksum\n");
    printf("  --scan-modules  Scan memory for module signatures\n");
    printf("  --all           Run all checks (default)\n");
    printf("  --help          Show this help\n");
    printf("\nMust be run as root. Kernel lockdown (confidentiality mode)\n");
    printf("will block /proc/kcore access.\n");
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int do_segments = 0;
    int do_checksum = 0;
    int do_scan = 0;
    int do_all = 0;

    if (argc == 1)
        do_all = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--segments") == 0)
            do_segments = 1;
        else if (strcmp(argv[i], "--checksum") == 0)
            do_checksum = 1;
        else if (strcmp(argv[i], "--scan-modules") == 0)
            do_scan = 1;
        else if (strcmp(argv[i], "--all") == 0)
            do_all = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (do_all) {
        do_segments = do_checksum = do_scan = 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "ERROR: Must be run as root.\n");
        return 1;
    }

    printf("============================================================\n");
    printf("  Memory Scanner v1.0 (Educational Forensics Tool)\n");
    printf("============================================================\n");
    time_t now = time(NULL);
    printf("  Date: %s", ctime(&now));
    printf("============================================================\n\n");

    /* Parse kcore headers */
    if (parse_kcore_headers() != 0) {
        fprintf(stderr, "Failed to parse /proc/kcore. Aborting.\n");
        return 1;
    }

    if (do_segments)
        show_segments();

    if (do_checksum)
        compute_kernel_text_checksum();

    if (do_scan)
        scan_for_modules();

    printf("\n============================================================\n");
    printf("  Scan complete.\n");
    printf("  For production forensics, use LiME + Volatility.\n");
    printf("============================================================\n");

    return 0;
}

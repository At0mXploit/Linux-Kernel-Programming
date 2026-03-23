/*
 * memory_layout.c - Demonstrate the virtual memory layout of a Linux process
 *
 * This program displays the addresses of various memory segments to
 * illustrate the x86_64 virtual address space layout:
 *   - Text (code) segment
 *   - Data segment (initialized globals)
 *   - BSS segment (uninitialized globals)
 *   - Heap (malloc/brk)
 *   - Stack
 *   - Memory-mapped regions (mmap)
 *   - Shared libraries
 *
 * It also demonstrates ASLR by showing how addresses change across runs.
 *
 * Compile: gcc -Wall -Wextra -o memory_layout memory_layout.c
 * Usage:   ./memory_layout
 *          Run multiple times to observe ASLR randomization.
 *
 * Related: Lesson 3 (User Space vs Kernel Space)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* ===== Global variables in different segments ===== */

/* .data section: initialized global data */
int initialized_global = 0xDEAD;
static int initialized_static = 0xBEEF;
char global_string[] = "This is in .data";

/* .rodata section: read-only data */
const char *readonly_string = "This is in .rodata";
const int readonly_int = 42;

/* .bss section: uninitialized global data (zero-filled at program start) */
int uninitialized_global;
static int uninitialized_static;
char uninitialized_array[4096];

/*
 * print_address - Print a labeled address with its segment
 * @label:   Description of the variable
 * @addr:    The address to display
 * @segment: The memory segment name
 */
static void print_address(const char *label, const void *addr,
                          const char *segment)
{
    printf("  %-30s %p  [%s]\n", label, addr, segment);
}

/*
 * text_segment_function - A function in the .text (code) segment
 * Used to show the address of executable code.
 */
void text_segment_function(void)
{
    /* This function exists solely so we can take its address */
}

/*
 * recursive_stack_demo - Show stack growth direction
 * @depth: Current recursion depth
 * @prev_addr: Address of the previous frame's local variable
 */
static void recursive_stack_demo(int depth, void *prev_addr)
{
    int local_var;
    long diff = 0;

    if (prev_addr)
        diff = (long)&local_var - (long)prev_addr;

    printf("    Depth %d: stack variable at %p", depth, (void *)&local_var);
    if (prev_addr)
        printf("  (delta: %+ld bytes)", diff);
    printf("\n");

    if (depth < 5)
        recursive_stack_demo(depth + 1, (void *)&local_var);
}

/*
 * show_proc_maps - Print relevant entries from /proc/self/maps
 */
static void show_proc_maps(void)
{
    printf("\n=== /proc/self/maps (selected entries) ===\n\n");

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen /proc/self/maps");
        return;
    }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* Show entries for our binary, heap, stack, vdso, and key libs */
        if (strstr(line, "memory_layout") ||
            strstr(line, "[heap]") ||
            strstr(line, "[stack]") ||
            strstr(line, "[vdso]") ||
            strstr(line, "[vvar]") ||
            strstr(line, "[vsyscall]") ||
            strstr(line, "libc") ||
            strstr(line, "ld-linux")) {
            printf("  %s", line);
            count++;
        }
    }
    fclose(fp);

    if (count == 0) {
        printf("  (No matching entries found - check binary name)\n");
    }
}

int main(int argc, char *argv[], char *envp[])
{
    /* Local stack variables */
    int stack_var_1 = 1;
    int stack_var_2 = 2;
    char stack_array[256];

    /* Heap allocations */
    void *heap_small = malloc(64);
    void *heap_medium = malloc(4096);
    void *heap_large = malloc(1024 * 1024); /* 1 MB */

    /* Memory-mapped region */
    void *mmap_anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* Get brk (end of heap) */
    void *brk_addr = sbrk(0);

    printf("==============================================\n");
    printf("  Linux x86_64 Virtual Memory Layout Demo\n");
    printf("  PID: %d\n", getpid());
    printf("==============================================\n\n");

    /* 1. Text Segment */
    printf("--- TEXT SEGMENT (executable code) ---\n");
    print_address("main():", (void *)main, ".text");
    print_address("text_segment_function():", (void *)text_segment_function, ".text");
    print_address("printf():", (void *)printf, ".text (libc)");

    /* 2. Read-Only Data */
    printf("\n--- RODATA SEGMENT (read-only data) ---\n");
    print_address("readonly_string:", (void *)readonly_string, ".rodata");
    print_address("readonly_int:", (void *)&readonly_int, ".rodata");
    print_address("string literal:", (void *)"literal", ".rodata");

    /* 3. Initialized Data */
    printf("\n--- DATA SEGMENT (initialized globals) ---\n");
    print_address("initialized_global:", (void *)&initialized_global, ".data");
    print_address("initialized_static:", (void *)&initialized_static, ".data");
    print_address("global_string:", (void *)global_string, ".data");

    /* 4. BSS */
    printf("\n--- BSS SEGMENT (uninitialized globals) ---\n");
    print_address("uninitialized_global:", (void *)&uninitialized_global, ".bss");
    print_address("uninitialized_static:", (void *)&uninitialized_static, ".bss");
    print_address("uninitialized_array:", (void *)uninitialized_array, ".bss");

    /* 5. Heap */
    printf("\n--- HEAP (dynamic allocations, grows UP) ---\n");
    print_address("brk (heap end):", brk_addr, "heap");
    print_address("malloc(64):", heap_small, "heap");
    print_address("malloc(4096):", heap_medium, "heap");
    print_address("malloc(1MB):", heap_large, "heap/mmap");

    /* 6. mmap */
    printf("\n--- MMAP REGION ---\n");
    print_address("mmap(anonymous, 4KB):", mmap_anon, "mmap");

    /* 7. Stack */
    printf("\n--- STACK (local variables, grows DOWN) ---\n");
    print_address("argc:", (void *)&argc, "stack");
    print_address("argv:", (void *)&argv, "stack");
    print_address("envp:", (void *)&envp, "stack");
    print_address("stack_var_1:", (void *)&stack_var_1, "stack");
    print_address("stack_var_2:", (void *)&stack_var_2, "stack");
    print_address("stack_array:", (void *)stack_array, "stack");

    /* 8. Special regions */
    printf("\n--- SPECIAL REGIONS ---\n");
    /* argv and environment */
    if (argc > 0)
        print_address("argv[0] string:", (void *)argv[0], "stack (args)");
    if (envp[0])
        print_address("envp[0] string:", (void *)envp[0], "stack (env)");

    /* Summary: Address space layout overview */
    printf("\n=== ADDRESS SPACE LAYOUT SUMMARY ===\n\n");

    struct {
        const char *name;
        unsigned long addr;
    } regions[] = {
        {"Text (main)",           (unsigned long)main},
        {"Rodata",                (unsigned long)readonly_string},
        {"Data",                  (unsigned long)&initialized_global},
        {"BSS",                   (unsigned long)&uninitialized_global},
        {"Heap (small)",          (unsigned long)heap_small},
        {"Heap (large/mmap)",     (unsigned long)heap_large},
        {"Mmap (anonymous)",      (unsigned long)mmap_anon},
        {"Stack",                 (unsigned long)&stack_var_1},
    };

    int n = sizeof(regions) / sizeof(regions[0]);
    /* Sort by address */
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (regions[i].addr > regions[j].addr) {
                typeof(regions[0]) tmp = regions[i];
                regions[i] = regions[j];
                regions[j] = tmp;
            }
        }
    }

    printf("  Low addresses:\n");
    for (int i = 0; i < n; i++) {
        printf("    0x%016lx  %s\n", regions[i].addr, regions[i].name);
        if (i < n - 1) {
            unsigned long gap = regions[i + 1].addr - regions[i].addr;
            if (gap > 1024 * 1024) {
                printf("    %-18s  ... gap: %lu MB ...\n", "", gap / (1024 * 1024));
            } else if (gap > 1024) {
                printf("    %-18s  ... gap: %lu KB ...\n", "", gap / 1024);
            }
        }
    }
    printf("  High addresses\n");

    /* Stack growth demonstration */
    printf("\n=== STACK GROWTH DEMO (recursive calls) ===\n\n");
    recursive_stack_demo(0, NULL);
    printf("\n  Stack grows DOWNWARD (addresses decrease with depth)\n");

    /* Show /proc/self/maps */
    show_proc_maps();

    /* ASLR check */
    printf("\n=== ASLR CHECK ===\n");
    printf("  Run this program multiple times to verify ASLR:\n");
    printf("  Stack addr:  %p\n", (void *)&stack_var_1);
    printf("  Heap addr:   %p\n", heap_small);
    printf("  Mmap addr:   %p\n", mmap_anon);
    printf("  Main addr:   %p (PIE: changes; non-PIE: fixed)\n", (void *)main);
    printf("\n  To disable ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space\n");
    printf("  To re-enable:    echo 2 | sudo tee /proc/sys/kernel/randomize_va_space\n");

    /* Cleanup */
    free(heap_small);
    free(heap_medium);
    free(heap_large);
    if (mmap_anon != MAP_FAILED)
        munmap(mmap_anon, 4096);

    return 0;
}

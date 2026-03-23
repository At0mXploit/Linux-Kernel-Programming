/*
 * kretprobe_example.c - Kretprobe return value capture example
 *
 * Demonstrates using kretprobes to capture the
 * return value and measure the execution duration of vfs_read().
 *
 * A kretprobe works by:
 *   1. Hooking at function entry (entry_handler)
 *   2. Replacing the return address with a trampoline
 *   3. When the function returns, the trampoline calls our handler
 *   4. We inspect the return value and any data saved at entry
 *
 * This module measures how long each vfs_read() call takes and
 * logs the return value (bytes read or error code).
 *
 * Usage:
 *   insmod kretprobe_example.ko
 *   cat /etc/passwd              # triggers vfs_read
 *   dd if=/dev/zero of=/dev/null bs=4096 count=10  # many reads
 *   dmesg | grep kretprobe_vfs
 *   rmmod kretprobe_example
 *
 * Build: Part of the kernel_subsystems Makefile
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Subsystems Lab");
MODULE_DESCRIPTION("Kretprobe example capturing vfs_read return values");

/* Configurable target function */
static char func_name[256] = "vfs_read";
module_param_string(func, func_name, sizeof(func_name), 0644);
MODULE_PARM_DESC(func, "Function to probe (default: vfs_read)");

/* Threshold for logging: only log calls slower than this (ns) */
static unsigned long threshold_ns = 1000000;  /* 1ms default */
module_param(threshold_ns, ulong, 0644);
MODULE_PARM_DESC(threshold_ns, "Only log calls slower than this (ns)");

/* Statistics */
static atomic64_t total_calls = ATOMIC64_INIT(0);
static atomic64_t slow_calls = ATOMIC64_INIT(0);
static atomic64_t total_bytes = ATOMIC64_INIT(0);
static atomic64_t max_duration_ns = ATOMIC64_INIT(0);

/*
 * Per-instance data structure.
 *
 * Each concurrent invocation of the probed function gets its own
 * kretprobe_instance with space for this data. This is how we
 * pass information from the entry handler to the return handler.
 *
 * The maxactive parameter controls how many concurrent instances
 * can be active at once.
 */
struct vfs_read_data {
    ktime_t entry_time;     /* timestamp when function was entered    */
    pid_t   pid;            /* PID of the calling process             */
    char    comm[TASK_COMM_LEN]; /* command name of the calling process */
};

/*
 * entry_handler - Called when the probed function is entered
 *
 * @ri:   The kretprobe instance for this invocation
 * @regs: CPU registers at function entry
 *
 * We record the entry timestamp and process info so we can
 * compute the duration in the return handler.
 *
 * Return:
 *   0 = trace this invocation (return handler will be called)
 *   non-zero = skip this invocation (return handler will NOT be called)
 */
static int entry_handler(struct kretprobe_instance *ri,
                          struct pt_regs *regs)
{
    struct vfs_read_data *data;

    data = (struct vfs_read_data *)ri->data;
    data->entry_time = ktime_get();
    data->pid = current->pid;
    strncpy(data->comm, current->comm, TASK_COMM_LEN - 1);
    data->comm[TASK_COMM_LEN - 1] = '\0';

    return 0;
}

/*
 * ret_handler - Called when the probed function returns
 *
 * @ri:   The kretprobe instance (same as passed to entry_handler)
 * @regs: CPU registers at function return
 *
 * The return value is in the architecture's return register:
 *   x86_64: RAX (regs->ax)
 *   ARM64:  X0  (regs->regs[0])
 *
 * We use regs_return_value(regs) for portability.
 */
static int ret_handler(struct kretprobe_instance *ri,
                        struct pt_regs *regs)
{
    struct vfs_read_data *data;
    ktime_t now;
    s64 duration_ns;
    long retval;
    s64 old_max, new_max;

    data = (struct vfs_read_data *)ri->data;
    now = ktime_get();
    duration_ns = ktime_to_ns(ktime_sub(now, data->entry_time));

    /*
     * regs_return_value() is the portable way to get the return value.
     * It maps to the correct register on each architecture.
     */
    retval = regs_return_value(regs);

    /* Update statistics */
    atomic64_inc(&total_calls);

    if (retval > 0)
        atomic64_add(retval, &total_bytes);

    /* Atomically update maximum duration */
    do {
        old_max = atomic64_read(&max_duration_ns);
        new_max = max((s64)old_max, duration_ns);
        if (new_max == old_max)
            break;
    } while (atomic64_cmpxchg(&max_duration_ns, old_max, new_max) != old_max);

    /* Log calls that exceed the threshold */
    if (duration_ns > threshold_ns) {
        atomic64_inc(&slow_calls);

        pr_info("kretprobe_vfs: %s (pid=%d) %s returned %ld "
                "in %lld ns (%lld us)\n",
                data->comm, data->pid,
                func_name, retval,
                duration_ns, duration_ns / 1000);

        if (retval < 0) {
            pr_info("kretprobe_vfs:   ^ error code: %ld (%pe)\n",
                    retval, ERR_PTR(retval));
        }
    }

    return 0;
}

/* ──────────────── Kretprobe definition ──────────────── */

static struct kretprobe my_kretprobe = {
    .handler        = ret_handler,
    .entry_handler  = entry_handler,
    .data_size      = sizeof(struct vfs_read_data),
    /*
     * maxactive: maximum number of concurrent probed function invocations.
     * If more than maxactive instances are active simultaneously,
     * additional invocations are missed (counted in nmissed).
     *
     * Choose based on expected concurrency:
     *   - Single-threaded target: 1-4
     *   - Multi-threaded (e.g., web server): 20-50
     *   - System-wide hot function: 50-100+
     */
    .maxactive      = 50,
};

/* ──────────────── Module init/exit ──────────────── */

static int __init kretprobe_example_init(void)
{
    int ret;

    my_kretprobe.kp.symbol_name = func_name;

    ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        pr_err("kretprobe_vfs: register_kretprobe failed for '%s': %d\n",
               func_name, ret);
        return ret;
    }

    pr_info("kretprobe_vfs: probe registered on %s at %pS\n",
            func_name, my_kretprobe.kp.addr);
    pr_info("kretprobe_vfs: maxactive=%d, threshold=%lu ns\n",
            my_kretprobe.maxactive, threshold_ns);
    return 0;
}

static void __exit kretprobe_example_exit(void)
{
    unregister_kretprobe(&my_kretprobe);

    pr_info("kretprobe_vfs: probe unregistered from %s\n", func_name);
    pr_info("kretprobe_vfs: Statistics:\n");
    pr_info("kretprobe_vfs:   Total calls:    %lld\n",
            atomic64_read(&total_calls));
    pr_info("kretprobe_vfs:   Slow calls:     %lld (> %lu ns)\n",
            atomic64_read(&slow_calls), threshold_ns);
    pr_info("kretprobe_vfs:   Total bytes:    %lld\n",
            atomic64_read(&total_bytes));
    pr_info("kretprobe_vfs:   Max duration:   %lld ns\n",
            atomic64_read(&max_duration_ns));
    pr_info("kretprobe_vfs:   Missed probes:  %d\n",
            my_kretprobe.nmissed);
}

module_init(kretprobe_example_init);
module_exit(kretprobe_example_exit);

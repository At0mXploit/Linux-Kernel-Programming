/*
 * kprobe_example.c - Kprobe instrumentation example
 *
 * Demonstrates using kprobes to dynamically instrument
 * the do_sys_openat2 kernel function, logging every file open operation.
 *
 * This module installs a kprobe at the entry of do_sys_openat2() and
 * logs the file descriptor (dfd) and flags. It demonstrates:
 *   - struct kprobe setup and registration
 *   - Accessing function arguments via pt_regs
 *   - Pre-handler and post-handler callbacks
 *   - Rate-limited logging in probe handlers
 *
 * Usage:
 *   insmod kprobe_example.ko
 *   ls /tmp          # triggers file opens
 *   cat /etc/passwd  # triggers file open
 *   dmesg | grep kprobe_open
 *   rmmod kprobe_example
 *
 * Build: Part of the kernel_subsystems Makefile
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Subsystems Lab");
MODULE_DESCRIPTION("Kprobe example instrumenting do_sys_openat2");

/* Allow the target function to be overridden via module parameter */
static char func_name[256] = "do_sys_openat2";
module_param_string(func, func_name, sizeof(func_name), 0644);
MODULE_PARM_DESC(func, "Function to probe (default: do_sys_openat2)");

/* Statistics */
static atomic_t probe_count = ATOMIC_INIT(0);

/*
 * pre_handler - Called before the probed instruction executes
 *
 * This is where we inspect the function arguments. On x86_64:
 *   RDI = 1st argument (int dfd)
 *   RSI = 2nd argument (const char __user *filename)
 *   RDX = 3rd argument (struct open_how *how)
 *
 * For do_sys_openat2(int dfd, const char __user *filename,
 *                    struct open_how *how):
 *   regs->di  = dfd (-100 means AT_FDCWD)
 *   regs->si  = filename pointer (user-space)
 *   regs->dx  = how pointer
 *
 * IMPORTANT: We are in atomic context here. We cannot:
 *   - Sleep (no kmalloc with GFP_KERNEL, no mutex_lock)
 *   - Call functions that might fault
 *   - Spend too long (we are blocking the probed function)
 */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int count;

    count = atomic_inc_return(&probe_count);

    /*
     * Log every 50th call to avoid flooding dmesg.
     * In production, you would use a BPF map or ring buffer instead.
     */
    if (count % 50 == 1) {
#ifdef CONFIG_X86_64
        pr_info("kprobe_open: [#%d] do_sys_openat2 called by %s (pid=%d)\n"
                "  dfd=%d (AT_FDCWD=%d), filename_ptr=0x%lx\n"
                "  caller IP=%pS\n",
                count,
                current->comm, current->pid,
                (int)regs->di, AT_FDCWD,
                (unsigned long)regs->si,
                (void *)regs->ip);
#elif defined(CONFIG_ARM64)
        pr_info("kprobe_open: [#%d] do_sys_openat2 called by %s (pid=%d)\n"
                "  dfd=%d, filename_ptr=0x%lx\n"
                "  caller PC=%pS\n",
                count,
                current->comm, current->pid,
                (int)regs->regs[0],
                (unsigned long)regs->regs[1],
                (void *)regs->pc);
#else
        pr_info("kprobe_open: [#%d] do_sys_openat2 called by %s (pid=%d)\n",
                count, current->comm, current->pid);
#endif
    }

    return 0;
}

/*
 * post_handler - Called after the probed instruction executes
 *
 * The instruction pointer (IP) has advanced past the probed instruction.
 * We can observe the state after the instruction completes.
 *
 * Note: This is NOT the return of the function -- it is after the
 * single probed instruction. For function return probing, use kretprobes.
 */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
                                    unsigned long flags)
{
    /*
     * Post-handler is useful for observing side effects of the
     * probed instruction. For function-entry probes, it fires
     * right after the first instruction of the function.
     *
     * We keep this lightweight to minimize overhead.
     */
}

/* ──────────────── Kprobe definition ──────────────── */

static struct kprobe kp = {
    .symbol_name    = func_name,
    .pre_handler    = handler_pre,
    .post_handler   = handler_post,
};

/* ──────────────── Module init/exit ──────────────── */

static int __init kprobe_example_init(void)
{
    int ret;

    kp.symbol_name = func_name;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kprobe_open: register_kprobe failed for '%s': %d\n",
               func_name, ret);
        if (ret == -ENOENT)
            pr_err("kprobe_open: symbol '%s' not found. "
                   "Check /proc/kallsyms.\n", func_name);
        if (ret == -EINVAL)
            pr_err("kprobe_open: symbol '%s' is in the kprobe blacklist.\n",
                   func_name);
        return ret;
    }

    pr_info("kprobe_open: probe registered at %s (%pS)\n",
            func_name, kp.addr);
    pr_info("kprobe_open: probe address = 0x%px\n", kp.addr);
    return 0;
}

static void __exit kprobe_example_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kprobe_open: probe unregistered from %s\n", func_name);
    pr_info("kprobe_open: total probe hits: %d\n",
            atomic_read(&probe_count));
}

module_init(kprobe_example_init);
module_exit(kprobe_example_exit);

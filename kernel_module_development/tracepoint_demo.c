// SPDX-License-Identifier: GPL-2.0
/*
 * tracepoint_demo.c - Module registering probes on kernel tracepoints.
 *
 * Demonstrates:
 *   - Registering a probe on the sched_switch tracepoint
 *   - Registering a probe on the sched_process_fork tracepoint
 *   - Enumerating all available kernel tracepoints
 *   - Collecting statistics from tracepoint data
 *   - Exposing collected data via /proc/tracepoint_demo
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod tracepoint_demo.ko
 *   sudo insmod tracepoint_demo.ko target_pid=1234
 *   cat /proc/tracepoint_demo
 *   sudo rmmod tracepoint_demo
 *   dmesg | tail -20
 *
 * Note: This module requires CONFIG_TRACEPOINTS=y in the kernel config
 *       (enabled by default on most distributions).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

/*
 * Include the tracepoint headers for the events we want to probe.
 * These are in include/trace/events/.
 */
#include <trace/events/sched.h>

/* ========================================================================
 * Module Parameters
 * ======================================================================== */

static int target_pid = -1;  /* -1 = trace all processes */
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid,
		 "PID to trace specifically (-1 for all, default: -1)");

static int max_log_entries = 20;
module_param(max_log_entries, int, 0444);
MODULE_PARM_DESC(max_log_entries,
		 "Maximum number of switch events to log (default: 20)");

/* ========================================================================
 * Statistics
 * ======================================================================== */

static atomic_t total_switches = ATOMIC_INIT(0);
static atomic_t total_forks = ATOMIC_INIT(0);
static atomic_t voluntary_switches = ATOMIC_INIT(0);
static atomic_t involuntary_switches = ATOMIC_INIT(0);
static unsigned long start_jiffies;

/* Recent switch log */
struct switch_entry {
	pid_t prev_pid;
	pid_t next_pid;
	char prev_comm[TASK_COMM_LEN];
	char next_comm[TASK_COMM_LEN];
	unsigned long timestamp;
	bool preempt;
};

#define MAX_LOG  64
static struct switch_entry switch_log[MAX_LOG];
static int log_index = 0;
static DEFINE_SPINLOCK(log_lock);

/* Tracepoint pointers (found dynamically) */
static struct tracepoint *tp_sched_switch = NULL;
static struct tracepoint *tp_sched_process_fork = NULL;
static int tp_count = 0;

/* ========================================================================
 * Tracepoint Probes
 * ======================================================================== */

/*
 * sched_switch probe
 *
 * Called every time the scheduler switches from one task to another.
 * The first argument is always 'void *data' (the private data passed
 * during registration), followed by the tracepoint-specific arguments.
 *
 * Note: The exact signature depends on the kernel version. The format
 * below matches kernels >= 5.x. Check the tracepoint format in
 * /sys/kernel/debug/tracing/events/sched/sched_switch/format
 */
static void probe_sched_switch(void *data, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next,
			       unsigned int prev_state)
{
	int count;

	/* Increment counters */
	count = atomic_inc_return(&total_switches);

	if (preempt)
		atomic_inc(&involuntary_switches);
	else
		atomic_inc(&voluntary_switches);

	/* Filter by target PID if specified */
	if (target_pid >= 0 &&
	    prev->pid != target_pid &&
	    next->pid != target_pid)
		return;

	/* Log recent entries (circular buffer) */
	if (count <= max_log_entries ||
	    (target_pid >= 0 &&
	     (prev->pid == target_pid || next->pid == target_pid))) {

		unsigned long flags;
		int idx;

		spin_lock_irqsave(&log_lock, flags);
		idx = log_index % MAX_LOG;
		switch_log[idx].prev_pid = prev->pid;
		switch_log[idx].next_pid = next->pid;
		strscpy(switch_log[idx].prev_comm, prev->comm,
			TASK_COMM_LEN);
		strscpy(switch_log[idx].next_comm, next->comm,
			TASK_COMM_LEN);
		switch_log[idx].timestamp = jiffies;
		switch_log[idx].preempt = preempt;
		log_index++;
		spin_unlock_irqrestore(&log_lock, flags);
	}
}

/*
 * sched_process_fork probe
 *
 * Called when a new process is forked.
 */
static void probe_sched_fork(void *data,
			     struct task_struct *parent,
			     struct task_struct *child)
{
	atomic_inc(&total_forks);

	if (target_pid >= 0 && parent->pid != target_pid)
		return;

	pr_info("fork: %s[%d] -> %s[%d]\n",
		parent->comm, parent->pid,
		child->comm, child->pid);
}

/* ========================================================================
 * Tracepoint Discovery
 *
 * We use for_each_kernel_tracepoint to find the tracepoints by name.
 * This is more robust than using the register_trace_* macros directly,
 * as it works even when the tracepoint header's API changes.
 * ======================================================================== */

static void find_tracepoint(struct tracepoint *tp, void *priv)
{
	tp_count++;

	if (strcmp(tp->name, "sched_switch") == 0)
		tp_sched_switch = tp;
	else if (strcmp(tp->name, "sched_process_fork") == 0)
		tp_sched_process_fork = tp;
}

/* ========================================================================
 * /proc/tracepoint_demo
 * ======================================================================== */

static int tp_proc_show(struct seq_file *s, void *v)
{
	unsigned long elapsed_sec;
	int entries, i, start;
	unsigned long flags;

	elapsed_sec = (jiffies - start_jiffies) / HZ;

	seq_puts(s, "=== Tracepoint Demo Statistics ===\n\n");
	seq_printf(s, "Monitoring duration: %lu seconds\n", elapsed_sec);
	seq_printf(s, "Target PID:         %d (%s)\n",
		   target_pid,
		   target_pid < 0 ? "all processes" : "filtered");
	seq_printf(s, "Available tracepoints: %d\n\n", tp_count);

	seq_puts(s, "--- Scheduler Statistics ---\n");
	seq_printf(s, "Total context switches:    %d\n",
		   atomic_read(&total_switches));
	seq_printf(s, "Voluntary switches:        %d\n",
		   atomic_read(&voluntary_switches));
	seq_printf(s, "Involuntary (preemption):  %d\n",
		   atomic_read(&involuntary_switches));
	seq_printf(s, "Process forks:             %d\n",
		   atomic_read(&total_forks));

	if (elapsed_sec > 0) {
		seq_printf(s, "Switches/second:           %d\n",
			   atomic_read(&total_switches) /
			   (int)elapsed_sec);
	}

	/* Display recent switch log */
	seq_puts(s, "\n--- Recent Context Switches ---\n");
	seq_printf(s, "%-8s %-16s %5s -> %-16s %5s %s\n",
		   "Age(ms)", "Prev", "PID", "Next", "PID", "Type");
	seq_puts(s, "----------------------------------------------"
		    "-----------------------------\n");

	spin_lock_irqsave(&log_lock, flags);
	entries = min(log_index, MAX_LOG);
	start = (log_index > MAX_LOG) ? log_index % MAX_LOG : 0;

	for (i = 0; i < entries; i++) {
		int idx = (start + i) % MAX_LOG;
		struct switch_entry *e = &switch_log[idx];
		unsigned long age_ms;

		age_ms = jiffies_to_msecs(jiffies - e->timestamp);

		seq_printf(s, "%7lu  %-16s %5d -> %-16s %5d %s\n",
			   age_ms,
			   e->prev_comm, e->prev_pid,
			   e->next_comm, e->next_pid,
			   e->preempt ? "preempt" : "voluntary");
	}
	spin_unlock_irqrestore(&log_lock, flags);

	return 0;
}

static int tp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tp_proc_show, NULL);
}

static const struct proc_ops tp_proc_ops = {
	.proc_open    = tp_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init tracepoint_demo_init(void)
{
	int ret;

	start_jiffies = jiffies;

	/* Discover tracepoints */
	for_each_kernel_tracepoint(find_tracepoint, NULL);
	pr_info("found %d kernel tracepoints\n", tp_count);

	if (!tp_sched_switch) {
		pr_err("sched_switch tracepoint not found\n");
		return -ENOENT;
	}

	if (!tp_sched_process_fork) {
		pr_err("sched_process_fork tracepoint not found\n");
		return -ENOENT;
	}

	/* Register probes */
	ret = tracepoint_probe_register(tp_sched_switch,
					probe_sched_switch, NULL);
	if (ret) {
		pr_err("failed to register sched_switch probe: %d\n", ret);
		return ret;
	}
	pr_info("registered sched_switch probe\n");

	ret = tracepoint_probe_register(tp_sched_process_fork,
					probe_sched_fork, NULL);
	if (ret) {
		pr_err("failed to register sched_process_fork probe: %d\n",
		       ret);
		tracepoint_probe_unregister(tp_sched_switch,
					    probe_sched_switch, NULL);
		tracepoint_synchronize_unregister();
		return ret;
	}
	pr_info("registered sched_process_fork probe\n");

	/* Create proc entry */
	if (!proc_create("tracepoint_demo", 0444, NULL, &tp_proc_ops)) {
		pr_err("failed to create /proc/tracepoint_demo\n");
		tracepoint_probe_unregister(tp_sched_process_fork,
					    probe_sched_fork, NULL);
		tracepoint_probe_unregister(tp_sched_switch,
					    probe_sched_switch, NULL);
		tracepoint_synchronize_unregister();
		return -ENOMEM;
	}

	pr_info("module loaded (target_pid=%d)\n", target_pid);
	pr_info("status: cat /proc/tracepoint_demo\n");
	return 0;
}

static void __exit tracepoint_demo_exit(void)
{
	/* Remove proc entry first to prevent new readers */
	remove_proc_entry("tracepoint_demo", NULL);

	/* Unregister probes */
	tracepoint_probe_unregister(tp_sched_process_fork,
				    probe_sched_fork, NULL);
	tracepoint_probe_unregister(tp_sched_switch,
				    probe_sched_switch, NULL);

	/*
	 * Wait for any in-flight probe callbacks to complete.
	 * This is CRITICAL -- without this, the module's code could be
	 * freed while a CPU is still executing the probe function.
	 */
	tracepoint_synchronize_unregister();

	pr_info("module unloaded\n");
	pr_info("final: switches=%d forks=%d\n",
		atomic_read(&total_switches),
		atomic_read(&total_forks));
}

module_init(tracepoint_demo_init);
module_exit(tracepoint_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Tracepoint probe registration demonstration");
MODULE_VERSION("1.0.0");

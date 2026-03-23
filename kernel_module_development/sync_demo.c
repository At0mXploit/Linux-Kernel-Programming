// SPDX-License-Identifier: GPL-2.0
/*
 * sync_demo.c - Kernel module demonstrating synchronization primitives:
 *   - spinlock_t with spin_lock/spin_unlock
 *   - struct mutex with mutex_lock/mutex_unlock
 *   - RCU with rcu_read_lock, rcu_assign_pointer, call_rcu
 *   - atomic_t operations
 *   - Per-CPU variables
 *
 * Creates worker threads that demonstrate each synchronization mechanism.
 * Results are visible via printk/dmesg and a /proc entry.
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod sync_demo.ko
 *   cat /proc/sync_demo
 *   sleep 5
 *   cat /proc/sync_demo
 *   sudo rmmod sync_demo
 *   dmesg | tail -40
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/jiffies.h>

/* ========================================================================
 * 1. Spinlock-Protected Shared Data
 * ======================================================================== */

static DEFINE_SPINLOCK(spin_data_lock);
static int spin_counter = 0;
static unsigned long spin_total_hold_ns = 0;

/* ========================================================================
 * 2. Mutex-Protected Shared Buffer
 * ======================================================================== */

static DEFINE_MUTEX(buf_mutex);
static char shared_buffer[128] = "(empty)";
static int buf_update_count = 0;

/* ========================================================================
 * 3. RCU-Protected Data Structure
 * ======================================================================== */

struct rcu_config {
	int version;
	int value_a;
	int value_b;
	unsigned long timestamp;
	struct rcu_head rcu;
};

static struct rcu_config __rcu *current_config;
static DEFINE_SPINLOCK(config_update_lock);
static int rcu_read_count = 0;
static int rcu_update_count = 0;

/* ========================================================================
 * 4. Atomic Counter
 * ======================================================================== */

static atomic_t atomic_counter = ATOMIC_INIT(0);
static atomic64_t atomic_total_ops = ATOMIC64_INIT(0);

/* ========================================================================
 * 5. Per-CPU Counter
 * ======================================================================== */

static DEFINE_PER_CPU(unsigned long, percpu_ops);

/* ========================================================================
 * Worker Threads
 * ======================================================================== */

static struct task_struct *spin_thread;
static struct task_struct *mutex_thread;
static struct task_struct *rcu_writer_thread;
static struct task_struct *rcu_reader_thread;
static struct task_struct *atomic_thread;

/* ---------- Spinlock Worker ---------- */

static int spinlock_worker(void *data)
{
	int i = 0;
	ktime_t start, end;

	pr_info("[spinlock] worker started on CPU %d\n", smp_processor_id());

	while (!kthread_should_stop()) {
		start = ktime_get();

		spin_lock(&spin_data_lock);
		spin_counter++;
		/* Simulate brief critical section work */
		spin_total_hold_ns += ktime_to_ns(ktime_sub(ktime_get(), start));
		spin_unlock(&spin_data_lock);

		end = ktime_get();

		if (++i % 100 == 0)
			pr_info("[spinlock] counter=%d hold_ns_avg=%lu\n",
				spin_counter,
				spin_total_hold_ns / spin_counter);

		/* Per-CPU operation (no lock needed, just disable preemption) */
		this_cpu_inc(percpu_ops);

		msleep(50);
	}

	pr_info("[spinlock] worker stopped, final counter=%d\n", spin_counter);
	return 0;
}

/* ---------- Mutex Worker ---------- */

static int mutex_worker(void *data)
{
	int i = 0;

	pr_info("[mutex] worker started on CPU %d\n", smp_processor_id());

	while (!kthread_should_stop()) {
		mutex_lock(&buf_mutex);

		/*
		 * We can sleep while holding a mutex (unlike a spinlock).
		 * This simulates a longer critical section, e.g., I/O.
		 */
		scnprintf(shared_buffer, sizeof(shared_buffer),
			  "update #%d from CPU %d at jiffies %lu",
			  ++buf_update_count, smp_processor_id(), jiffies);

		mutex_unlock(&buf_mutex);

		if (++i % 20 == 0)
			pr_info("[mutex] buffer: '%s'\n", shared_buffer);

		msleep(200);
	}

	pr_info("[mutex] worker stopped, updates=%d\n", buf_update_count);
	return 0;
}

/* ---------- RCU Callback for Deferred Free ---------- */

static void config_free_rcu(struct rcu_head *head)
{
	struct rcu_config *old = container_of(head, struct rcu_config, rcu);

	pr_info("[rcu] deferred free: version=%d\n", old->version);
	kfree(old);
}

/* ---------- RCU Writer ---------- */

static int rcu_writer_worker(void *data)
{
	int version = 0;

	pr_info("[rcu-writer] started on CPU %d\n", smp_processor_id());

	while (!kthread_should_stop()) {
		struct rcu_config *new_cfg, *old_cfg;

		new_cfg = kmalloc(sizeof(*new_cfg), GFP_KERNEL);
		if (!new_cfg) {
			msleep(1000);
			continue;
		}

		version++;
		new_cfg->version = version;
		new_cfg->value_a = version * 10;
		new_cfg->value_b = version * 100;
		new_cfg->timestamp = jiffies;

		/*
		 * Writers must serialize among themselves.
		 * RCU only protects readers from writers, not writers from
		 * each other.
		 */
		spin_lock(&config_update_lock);
		old_cfg = rcu_dereference_protected(current_config,
			lockdep_is_held(&config_update_lock));
		rcu_assign_pointer(current_config, new_cfg);
		rcu_update_count++;
		spin_unlock(&config_update_lock);

		/*
		 * Schedule deferred free. The old config will be freed
		 * after all current RCU readers finish their critical
		 * sections (grace period).
		 */
		if (old_cfg)
			call_rcu(&old_cfg->rcu, config_free_rcu);

		pr_info("[rcu-writer] published version %d (a=%d b=%d)\n",
			version, new_cfg->value_a, new_cfg->value_b);

		msleep(1000);
	}

	pr_info("[rcu-writer] stopped, total updates=%d\n", rcu_update_count);
	return 0;
}

/* ---------- RCU Reader ---------- */

static int rcu_reader_worker(void *data)
{
	pr_info("[rcu-reader] started on CPU %d\n", smp_processor_id());

	while (!kthread_should_stop()) {
		struct rcu_config *cfg;

		/*
		 * rcu_read_lock: extremely lightweight (disables preemption).
		 * No spinning, no sleeping, no atomic operations.
		 */
		rcu_read_lock();
		cfg = rcu_dereference(current_config);
		if (cfg) {
			/* Safe to read cfg within this section */
			rcu_read_count++;
			if (rcu_read_count % 50 == 0)
				pr_info("[rcu-reader] read v%d: a=%d b=%d\n",
					cfg->version, cfg->value_a,
					cfg->value_b);
		}
		rcu_read_unlock();

		/* Per-CPU operation */
		this_cpu_inc(percpu_ops);

		msleep(100);
	}

	pr_info("[rcu-reader] stopped, total reads=%d\n", rcu_read_count);
	return 0;
}

/* ---------- Atomic Worker ---------- */

static int atomic_worker(void *data)
{
	pr_info("[atomic] worker started on CPU %d\n", smp_processor_id());

	while (!kthread_should_stop()) {
		/* Atomic increment: no lock needed */
		atomic_inc(&atomic_counter);
		atomic64_inc(&atomic_total_ops);

		/* Demonstrate atomic compare-and-exchange */
		if (atomic_read(&atomic_counter) >= 1000) {
			int old = atomic_cmpxchg(&atomic_counter, 1000, 0);
			if (old == 1000)
				pr_info("[atomic] counter reset at 1000\n");
		}

		/* Per-CPU operation */
		this_cpu_inc(percpu_ops);

		msleep(10);
	}

	pr_info("[atomic] worker stopped, counter=%d total_ops=%lld\n",
		atomic_read(&atomic_counter),
		atomic64_read(&atomic_total_ops));
	return 0;
}

/* ========================================================================
 * /proc/sync_demo - Status Overview
 * ======================================================================== */

static int sync_proc_show(struct seq_file *s, void *v)
{
	struct rcu_config *cfg;
	unsigned long total_percpu = 0;
	int cpu;

	seq_puts(s, "=== Synchronization Demo Status ===\n\n");

	/* Spinlock data */
	spin_lock(&spin_data_lock);
	seq_printf(s, "[Spinlock]\n");
	seq_printf(s, "  counter:       %d\n", spin_counter);
	seq_printf(s, "  total_hold_ns: %lu\n", spin_total_hold_ns);
	if (spin_counter > 0)
		seq_printf(s, "  avg_hold_ns:   %lu\n",
			   spin_total_hold_ns / spin_counter);
	spin_unlock(&spin_data_lock);

	/* Mutex data */
	seq_printf(s, "\n[Mutex]\n");
	mutex_lock(&buf_mutex);
	seq_printf(s, "  buffer:        '%s'\n", shared_buffer);
	seq_printf(s, "  update_count:  %d\n", buf_update_count);
	mutex_unlock(&buf_mutex);

	/* RCU data */
	seq_printf(s, "\n[RCU]\n");
	rcu_read_lock();
	cfg = rcu_dereference(current_config);
	if (cfg) {
		seq_printf(s, "  version:       %d\n", cfg->version);
		seq_printf(s, "  value_a:       %d\n", cfg->value_a);
		seq_printf(s, "  value_b:       %d\n", cfg->value_b);
		seq_printf(s, "  age_ms:        %u\n",
			   jiffies_to_msecs(jiffies - cfg->timestamp));
	} else {
		seq_puts(s, "  (no config)\n");
	}
	rcu_read_unlock();
	seq_printf(s, "  read_count:    %d\n", rcu_read_count);
	seq_printf(s, "  update_count:  %d\n", rcu_update_count);

	/* Atomic data */
	seq_printf(s, "\n[Atomic]\n");
	seq_printf(s, "  counter:       %d\n", atomic_read(&atomic_counter));
	seq_printf(s, "  total_ops:     %lld\n",
		   atomic64_read(&atomic_total_ops));

	/* Per-CPU data */
	seq_printf(s, "\n[Per-CPU Operations]\n");
	for_each_online_cpu(cpu) {
		unsigned long val = per_cpu(percpu_ops, cpu);

		seq_printf(s, "  CPU%d:          %lu\n", cpu, val);
		total_percpu += val;
	}
	seq_printf(s, "  total:         %lu\n", total_percpu);

	return 0;
}

static int sync_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sync_proc_show, NULL);
}

static const struct proc_ops sync_proc_ops = {
	.proc_open    = sync_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init sync_demo_init(void)
{
	struct rcu_config *initial;
	int cpu;

	/* Initialize per-CPU counters */
	for_each_possible_cpu(cpu)
		per_cpu(percpu_ops, cpu) = 0;

	/* Initialize RCU-protected config */
	initial = kzalloc(sizeof(*initial), GFP_KERNEL);
	if (!initial)
		return -ENOMEM;
	initial->version = 0;
	initial->value_a = 0;
	initial->value_b = 0;
	initial->timestamp = jiffies;
	rcu_assign_pointer(current_config, initial);

	/* Create proc entry */
	if (!proc_create("sync_demo", 0444, NULL, &sync_proc_ops)) {
		kfree(initial);
		return -ENOMEM;
	}

	/* Start worker threads */
	spin_thread = kthread_run(spinlock_worker, NULL, "sync_spin");
	if (IS_ERR(spin_thread)) {
		proc_remove(proc_create("sync_demo", 0, NULL, NULL));
		kfree(initial);
		return PTR_ERR(spin_thread);
	}

	mutex_thread = kthread_run(mutex_worker, NULL, "sync_mutex");
	if (IS_ERR(mutex_thread)) {
		kthread_stop(spin_thread);
		goto err_cleanup;
	}

	rcu_writer_thread = kthread_run(rcu_writer_worker, NULL, "sync_rcu_w");
	if (IS_ERR(rcu_writer_thread)) {
		kthread_stop(mutex_thread);
		kthread_stop(spin_thread);
		goto err_cleanup;
	}

	rcu_reader_thread = kthread_run(rcu_reader_worker, NULL, "sync_rcu_r");
	if (IS_ERR(rcu_reader_thread)) {
		kthread_stop(rcu_writer_thread);
		kthread_stop(mutex_thread);
		kthread_stop(spin_thread);
		goto err_cleanup;
	}

	atomic_thread = kthread_run(atomic_worker, NULL, "sync_atomic");
	if (IS_ERR(atomic_thread)) {
		kthread_stop(rcu_reader_thread);
		kthread_stop(rcu_writer_thread);
		kthread_stop(mutex_thread);
		kthread_stop(spin_thread);
		goto err_cleanup;
	}

	pr_info("module loaded -- 5 worker threads started\n");
	pr_info("status: cat /proc/sync_demo\n");
	return 0;

err_cleanup:
	remove_proc_entry("sync_demo", NULL);
	rcu_assign_pointer(current_config, NULL);
	synchronize_rcu();
	kfree(initial);
	return -ENOMEM;
}

static void __exit sync_demo_exit(void)
{
	struct rcu_config *cfg;

	/* Stop all worker threads */
	kthread_stop(atomic_thread);
	kthread_stop(rcu_reader_thread);
	kthread_stop(rcu_writer_thread);
	kthread_stop(mutex_thread);
	kthread_stop(spin_thread);

	/* Remove proc entry */
	remove_proc_entry("sync_demo", NULL);

	/* Free RCU-protected data */
	cfg = rcu_dereference_protected(current_config, 1);
	if (cfg) {
		rcu_assign_pointer(current_config, NULL);
		synchronize_rcu();
		kfree(cfg);
	}

	pr_info("module unloaded\n");
	pr_info("final: spin=%d mutex_updates=%d atomic=%d rcu_reads=%d\n",
		spin_counter, buf_update_count,
		atomic_read(&atomic_counter), rcu_read_count);
}

module_init(sync_demo_init);
module_exit(sync_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Spinlock, mutex, RCU, atomic, and per-CPU demonstration");
MODULE_VERSION("1.0.0");

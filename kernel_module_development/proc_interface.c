// SPDX-License-Identifier: GPL-2.0
/*
 * proc_interface.c - Kernel module creating /proc entries with read/write
 *                    support using both simple and seq_file interfaces.
 *
 * Creates:
 *   /proc/mod2_demo/status   - seq_file based, shows module status info
 *   /proc/mod2_demo/config   - read/write entry for user configuration
 *   /proc/mod2_demo/items    - seq_file iterating over a linked list
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod proc_interface.ko
 *   cat /proc/mod2_demo/status
 *   echo "hello" > /proc/mod2_demo/config
 *   cat /proc/mod2_demo/config
 *   cat /proc/mod2_demo/items
 *   sudo rmmod proc_interface
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>

/* ========================================================================
 * Data Structures
 * ======================================================================== */

/* Configuration buffer */
#define CONFIG_BUF_SIZE 256
static char config_buffer[CONFIG_BUF_SIZE] = "default_value";
static DEFINE_MUTEX(config_mutex);

/* Linked list for the items proc entry */
struct demo_item {
	int id;
	char name[32];
	unsigned long timestamp;
	struct list_head list;
};

static LIST_HEAD(items_list);
static DEFINE_MUTEX(items_mutex);
static int next_id = 1;
static atomic_t read_count = ATOMIC_INIT(0);

/* Proc directory entry */
static struct proc_dir_entry *proc_dir;

/* ========================================================================
 * /proc/mod2_demo/status -- Single seq_file showing module status
 * ======================================================================== */

static int status_show(struct seq_file *s, void *v)
{
	int count, item_count = 0;
	struct demo_item *item;

	count = atomic_inc_return(&read_count);

	mutex_lock(&items_mutex);
	list_for_each_entry(item, &items_list, list)
		item_count++;
	mutex_unlock(&items_mutex);

	seq_puts(s, "=== Module Status ===\n");
	seq_printf(s, "Module name:    %s\n", KBUILD_MODNAME);
	seq_printf(s, "Read count:     %d\n", count);
	seq_printf(s, "Item count:     %d\n", item_count);
	seq_printf(s, "Next ID:        %d\n", next_id);
	seq_printf(s, "Jiffies:        %lu\n", jiffies);
	seq_printf(s, "HZ:             %d\n", HZ);
	seq_printf(s, "Uptime (sec):   %lu\n", jiffies / HZ);

	mutex_lock(&config_mutex);
	seq_printf(s, "Config value:   %s\n", config_buffer);
	mutex_unlock(&config_mutex);

	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, status_show, NULL);
}

static const struct proc_ops status_proc_ops = {
	.proc_open    = status_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ========================================================================
 * /proc/mod2_demo/config -- Simple read/write proc entry
 * ======================================================================== */

static ssize_t config_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	char buf[CONFIG_BUF_SIZE + 1];
	int len;

	mutex_lock(&config_mutex);
	len = snprintf(buf, sizeof(buf), "%s\n", config_buffer);
	mutex_unlock(&config_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static ssize_t config_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	size_t len;

	if (count >= CONFIG_BUF_SIZE)
		return -EINVAL;

	len = count;

	mutex_lock(&config_mutex);
	if (copy_from_user(config_buffer, ubuf, len)) {
		mutex_unlock(&config_mutex);
		return -EFAULT;
	}

	/* Remove trailing newline if present */
	if (len > 0 && config_buffer[len - 1] == '\n')
		len--;
	config_buffer[len] = '\0';

	pr_info("config updated: '%s'\n", config_buffer);
	mutex_unlock(&config_mutex);

	return count;
}

static const struct proc_ops config_proc_ops = {
	.proc_read  = config_read,
	.proc_write = config_write,
};

/* ========================================================================
 * /proc/mod2_demo/items -- seq_file iterating over a linked list
 *
 * Demonstrates the full seq_operations interface:
 *   start -> show -> next -> show -> ... -> stop
 * ======================================================================== */

static void *items_seq_start(struct seq_file *s, loff_t *pos)
{
	mutex_lock(&items_mutex);
	return seq_list_start(&items_list, *pos);
}

static void *items_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &items_list, pos);
}

static void items_seq_stop(struct seq_file *s, void *v)
{
	mutex_unlock(&items_mutex);
}

static int items_seq_show(struct seq_file *s, void *v)
{
	struct demo_item *item = list_entry(v, struct demo_item, list);
	unsigned long age_sec;

	age_sec = (jiffies - item->timestamp) / HZ;

	seq_printf(s, "[%03d] %-20s (age: %lu sec)\n",
		   item->id, item->name, age_sec);
	return 0;
}

static const struct seq_operations items_seq_ops = {
	.start = items_seq_start,
	.next  = items_seq_next,
	.stop  = items_seq_stop,
	.show  = items_seq_show,
};

static int items_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &items_seq_ops);
}

/*
 * Write to /proc/mod2_demo/items to add a new item.
 * Write "delete <id>" to remove an item.
 * Write any other string to add it as a new item name.
 */
static ssize_t items_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	char kbuf[64];
	size_t len = min(count, sizeof(kbuf) - 1);
	int del_id;

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	/* Strip trailing newline */
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[--len] = '\0';

	/* Check for delete command */
	if (sscanf(kbuf, "delete %d", &del_id) == 1) {
		struct demo_item *item, *tmp;

		mutex_lock(&items_mutex);
		list_for_each_entry_safe(item, tmp, &items_list, list) {
			if (item->id == del_id) {
				pr_info("deleting item %d (%s)\n",
					item->id, item->name);
				list_del(&item->list);
				kfree(item);
				mutex_unlock(&items_mutex);
				return count;
			}
		}
		mutex_unlock(&items_mutex);
		pr_warn("item %d not found\n", del_id);
		return -ENOENT;
	}

	/* Otherwise, add a new item */
	{
		struct demo_item *new_item;

		new_item = kzalloc(sizeof(*new_item), GFP_KERNEL);
		if (!new_item)
			return -ENOMEM;

		new_item->id = next_id++;
		strscpy(new_item->name, kbuf, sizeof(new_item->name));
		new_item->timestamp = jiffies;

		mutex_lock(&items_mutex);
		list_add_tail(&new_item->list, &items_list);
		mutex_unlock(&items_mutex);

		pr_info("added item %d: '%s'\n", new_item->id, new_item->name);
	}

	return count;
}

static const struct proc_ops items_proc_ops = {
	.proc_open    = items_open,
	.proc_read    = seq_read,
	.proc_write   = items_write,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release,
};

/* ========================================================================
 * Populate initial items
 * ======================================================================== */

static void __init populate_initial_items(void)
{
	static const char * const names[] = {
		"alpha", "beta", "gamma", "delta", "epsilon"
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		struct demo_item *item;

		item = kzalloc(sizeof(*item), GFP_KERNEL);
		if (!item)
			return;

		item->id = next_id++;
		strscpy(item->name, names[i], sizeof(item->name));
		item->timestamp = jiffies;
		list_add_tail(&item->list, &items_list);
	}
}

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init proc_demo_init(void)
{
	/* Create /proc/mod2_demo/ directory */
	proc_dir = proc_mkdir("mod2_demo", NULL);
	if (!proc_dir) {
		pr_err("failed to create /proc/mod2_demo\n");
		return -ENOMEM;
	}

	/* Create /proc/mod2_demo/status */
	if (!proc_create("status", 0444, proc_dir, &status_proc_ops)) {
		pr_err("failed to create /proc/mod2_demo/status\n");
		goto err_remove_dir;
	}

	/* Create /proc/mod2_demo/config */
	if (!proc_create("config", 0666, proc_dir, &config_proc_ops)) {
		pr_err("failed to create /proc/mod2_demo/config\n");
		goto err_remove_dir;
	}

	/* Create /proc/mod2_demo/items */
	if (!proc_create("items", 0666, proc_dir, &items_proc_ops)) {
		pr_err("failed to create /proc/mod2_demo/items\n");
		goto err_remove_dir;
	}

	/* Populate initial data */
	populate_initial_items();

	pr_info("module loaded\n");
	pr_info("  /proc/mod2_demo/status  - module status (read-only)\n");
	pr_info("  /proc/mod2_demo/config  - configuration (read-write)\n");
	pr_info("  /proc/mod2_demo/items   - item list (read-write)\n");
	return 0;

err_remove_dir:
	proc_remove(proc_dir);
	return -ENOMEM;
}

static void __exit proc_demo_exit(void)
{
	struct demo_item *item, *tmp;

	/* Remove all proc entries (recursive) */
	proc_remove(proc_dir);

	/* Free all list items */
	mutex_lock(&items_mutex);
	list_for_each_entry_safe(item, tmp, &items_list, list) {
		list_del(&item->list);
		kfree(item);
	}
	mutex_unlock(&items_mutex);

	pr_info("module unloaded (total reads: %d)\n",
		atomic_read(&read_count));
}

module_init(proc_demo_init);
module_exit(proc_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("procfs interface with seq_file and read/write support");
MODULE_VERSION("1.0.0");

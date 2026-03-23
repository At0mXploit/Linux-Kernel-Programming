// SPDX-License-Identifier: GPL-2.0
/*
 * sysfs_interface.c - Kernel module creating sysfs attributes under a kobject.
 *
 * Creates:
 *   /sys/kernel/mod2_sysfs/
 *     +-- device_name     (read-only string attribute)
 *     +-- counter         (read-write integer attribute)
 *     +-- enabled         (read-write boolean attribute)
 *     +-- stats           (read-only multi-value status)
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod sysfs_interface.ko
 *   cat /sys/kernel/mod2_sysfs/device_name
 *   echo 42 > /sys/kernel/mod2_sysfs/counter
 *   cat /sys/kernel/mod2_sysfs/counter
 *   echo 1 > /sys/kernel/mod2_sysfs/enabled
 *   cat /sys/kernel/mod2_sysfs/stats
 *   sudo rmmod sysfs_interface
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

/* ========================================================================
 * Module Data
 * ======================================================================== */

static struct kobject *mod2_kobj;

/* device_name: a read-only string attribute */
static char device_name[64] = "mod2_device";

/* counter: a read-write integer */
static atomic_t counter = ATOMIC_INIT(0);

/* enabled: a boolean flag */
static bool enabled = false;
static DEFINE_MUTEX(enabled_mutex);

/* statistics tracking */
static atomic_t read_ops = ATOMIC_INIT(0);
static atomic_t write_ops = ATOMIC_INIT(0);
static unsigned long load_time;

/* ========================================================================
 * Attribute: device_name (read-only)
 * ======================================================================== */

static ssize_t device_name_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	atomic_inc(&read_ops);
	return sysfs_emit(buf, "%s\n", device_name);
}

/* Note: Using __ATTR_RO makes this read-only (permission 0444) */
static struct kobj_attribute device_name_attr =
	__ATTR_RO(device_name);

/* ========================================================================
 * Attribute: counter (read-write)
 * ======================================================================== */

static ssize_t counter_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	atomic_inc(&read_ops);
	return sysfs_emit(buf, "%d\n", atomic_read(&counter));
}

static ssize_t counter_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;

	if (val < 0) {
		pr_warn("counter cannot be negative: %d\n", val);
		return -EINVAL;
	}

	atomic_set(&counter, val);
	atomic_inc(&write_ops);

	pr_info("counter set to %d\n", val);
	return count;
}

static struct kobj_attribute counter_attr =
	__ATTR(counter, 0644, counter_show, counter_store);

/* ========================================================================
 * Attribute: enabled (read-write boolean)
 * ======================================================================== */

static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	bool val;

	atomic_inc(&read_ops);

	mutex_lock(&enabled_mutex);
	val = enabled;
	mutex_unlock(&enabled_mutex);

	return sysfs_emit(buf, "%d\n", val ? 1 : 0);
}

static ssize_t enabled_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	bool val;
	int ret;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	mutex_lock(&enabled_mutex);
	if (enabled != val) {
		enabled = val;
		pr_info("module %s\n", enabled ? "enabled" : "disabled");
	}
	mutex_unlock(&enabled_mutex);

	atomic_inc(&write_ops);
	return count;
}

static struct kobj_attribute enabled_attr =
	__ATTR(enabled, 0644, enabled_show, enabled_store);

/* ========================================================================
 * Attribute: stats (read-only composite)
 *
 * Note: sysfs convention says "one value per file." This is a deliberate
 * exception for demonstration. In production, these would be separate files.
 * ======================================================================== */

static ssize_t stats_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	unsigned long uptime_sec;

	atomic_inc(&read_ops);
	uptime_sec = (jiffies - load_time) / HZ;

	return sysfs_emit(buf,
		"read_operations: %d\n"
		"write_operations: %d\n"
		"uptime_seconds: %lu\n"
		"counter_value: %d\n"
		"enabled: %d\n",
		atomic_read(&read_ops),
		atomic_read(&write_ops),
		uptime_sec,
		atomic_read(&counter),
		enabled ? 1 : 0);
}

static struct kobj_attribute stats_attr =
	__ATTR_RO(stats);

/* ========================================================================
 * Attribute Group
 *
 * Grouping attributes allows creating/removing them atomically.
 * ======================================================================== */

static struct attribute *mod2_attrs[] = {
	&device_name_attr.attr,
	&counter_attr.attr,
	&enabled_attr.attr,
	&stats_attr.attr,
	NULL,   /* Sentinel -- must be NULL-terminated */
};

/*
 * ATTRIBUTE_GROUPS generates:
 *   static const struct attribute_group mod2_group = {
 *       .attrs = mod2_attrs,
 *   };
 *   static const struct attribute_group *mod2_groups[] = {
 *       &mod2_group,
 *       NULL,
 *   };
 */
ATTRIBUTE_GROUPS(mod2);

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init sysfs_demo_init(void)
{
	int ret;

	load_time = jiffies;

	/*
	 * Create a kobject under /sys/kernel/
	 * Other parent options:
	 *   firmware_kobj  -> /sys/firmware/
	 *   NULL           -> /sys/  (top level, rarely appropriate)
	 *   &pdev->dev.kobj -> under a device
	 */
	mod2_kobj = kobject_create_and_add("mod2_sysfs", kernel_kobj);
	if (!mod2_kobj) {
		pr_err("failed to create kobject\n");
		return -ENOMEM;
	}

	/*
	 * Create all sysfs files defined in the attribute group.
	 * If any file creation fails, already-created files are removed.
	 */
	ret = sysfs_create_group(mod2_kobj, &mod2_group);
	if (ret) {
		pr_err("failed to create sysfs group: %d\n", ret);
		kobject_put(mod2_kobj);
		return ret;
	}

	pr_info("module loaded\n");
	pr_info("sysfs directory: /sys/kernel/mod2_sysfs/\n");
	pr_info("attributes: device_name, counter, enabled, stats\n");
	return 0;
}

static void __exit sysfs_demo_exit(void)
{
	pr_info("final stats: reads=%d writes=%d counter=%d enabled=%d\n",
		atomic_read(&read_ops), atomic_read(&write_ops),
		atomic_read(&counter), enabled ? 1 : 0);

	/*
	 * kobject_put() decrements the reference count. When it reaches 0,
	 * the kobject and all its sysfs entries are removed.
	 * No need to call sysfs_remove_group explicitly.
	 */
	kobject_put(mod2_kobj);

	pr_info("module unloaded\n");
}

module_init(sysfs_demo_init);
module_exit(sysfs_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("sysfs interface with kobject and attribute groups");
MODULE_VERSION("1.0.0");

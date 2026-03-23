// SPDX-License-Identifier: GPL-2.0
/*
 * hello_module.c - Complete kernel module demonstrating:
 *   - module_init / module_exit
 *   - MODULE_LICENSE, MODULE_AUTHOR, MODULE_DESCRIPTION, MODULE_VERSION
 *   - module_param with various types
 *   - module_param_array
 *   - Custom parameter validation via kernel_param_ops
 *   - __init / __exit section annotations
 *   - __initdata for init-only data
 *   - printk log levels and pr_* wrappers
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod hello_module.ko
 *   sudo insmod hello_module.ko buffer_size=8192 device_name="mydev" debug_mode=1
 *   sudo insmod hello_module.ko values=10,20,30
 *   dmesg | tail -20
 *   cat /sys/module/hello_module/parameters/buffer_size
 *   echo 2048 > /sys/module/hello_module/parameters/buffer_size
 *   sudo rmmod hello_module
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>

/* ========================================================================
 * Module Parameters
 * ======================================================================== */

/* Integer parameter: buffer size with read-write sysfs access */
static int buffer_size = 4096;
module_param(buffer_size, int, 0644);
MODULE_PARM_DESC(buffer_size, "Size of internal buffer in bytes (default: 4096)");

/* String parameter: device name with read-only sysfs access */
static char *device_name = "hello";
module_param(device_name, charp, 0444);
MODULE_PARM_DESC(device_name, "Logical device name string (default: hello)");

/* Boolean parameter: debug mode toggle */
static bool debug_mode = false;
module_param(debug_mode, bool, 0644);
MODULE_PARM_DESC(debug_mode, "Enable verbose debug output (default: false)");

/* Short parameter: log level override */
static short log_level = 6;
module_param(log_level, short, 0644);
MODULE_PARM_DESC(log_level, "Log verbosity level 0-7 (default: 6)");

/* Array parameter: up to 4 integer values */
static int values[4] = {0, 0, 0, 0};
static int num_values;
module_param_array(values, int, &num_values, 0644);
MODULE_PARM_DESC(values, "Array of up to 4 integer values");

/* ========================================================================
 * Custom Parameter Validation
 * ======================================================================== */

static int max_connections = 100;

/*
 * Custom setter that validates the range [1, 10000].
 * Rejects values outside this range with -EINVAL.
 */
static int max_conn_set(const char *val, const struct kernel_param *kp)
{
	int n;
	int ret;

	ret = kstrtoint(val, 10, &n);
	if (ret)
		return ret;

	if (n < 1 || n > 10000) {
		pr_err("max_connections must be in range [1, 10000], got %d\n", n);
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops max_conn_ops = {
	.set = max_conn_set,
	.get = param_get_int,
};

module_param_cb(max_connections, &max_conn_ops, &max_connections, 0644);
MODULE_PARM_DESC(max_connections,
		 "Maximum number of connections [1-10000] (default: 100)");

/* ========================================================================
 * Init-only data (freed after init completes)
 * ======================================================================== */

static const char __initdata banner[] =
	"=== Hello Module v1.0.0 - Advanced Kernel Module Demo ===";

static int __initdata init_run_count = 0;

/* ========================================================================
 * Demonstrating all printk log levels
 * ======================================================================== */

static void __init demonstrate_log_levels(void)
{
	pr_info("--- Demonstrating printk log levels ---\n");

	/*
	 * In production, you would only use the appropriate level.
	 * Here we demonstrate all levels for educational purposes.
	 * Note: KERN_EMERG and KERN_ALERT would be inappropriate for
	 * a demo module in production.
	 */
	pr_debug("KERN_DEBUG (7): Debug-level message\n");
	pr_info("KERN_INFO (6): Informational message\n");
	pr_notice("KERN_NOTICE (5): Normal but significant condition\n");
	pr_warn("KERN_WARNING (4): Warning condition\n");
	pr_err("KERN_ERR (3): Error condition (demo only)\n");

	/* Direct printk with explicit level */
	printk(KERN_INFO "hello_module: Direct printk with KERN_INFO\n");

	/*
	 * pr_debug() compiles to nothing unless:
	 *   - DEBUG is defined (-DDEBUG in CFLAGS)
	 *   - CONFIG_DYNAMIC_DEBUG is enabled (controllable at runtime)
	 *
	 * With dynamic debug enabled:
	 *   echo 'module hello_module +p' > \
	 *     /sys/kernel/debug/dynamic_debug/control
	 */
}

/* ========================================================================
 * Module Init Function
 * ======================================================================== */

static int __init hello_init(void)
{
	int i;

	init_run_count++;

	pr_info("%s\n", banner);
	pr_info("initialization started (run count: %d)\n", init_run_count);

	/* Display all parameter values */
	pr_info("parameters:\n");
	pr_info("  buffer_size     = %d\n", buffer_size);
	pr_info("  device_name     = %s\n", device_name);
	pr_info("  debug_mode      = %s\n", debug_mode ? "true" : "false");
	pr_info("  log_level       = %d\n", log_level);
	pr_info("  max_connections = %d\n", max_connections);

	/* Display array parameter */
	pr_info("  values[%d]       =", num_values);
	for (i = 0; i < num_values; i++)
		pr_cont(" %d", values[i]);
	pr_cont("\n");

	/* Validate buffer_size */
	if (buffer_size <= 0) {
		pr_err("invalid buffer_size: %d (must be > 0)\n", buffer_size);
		return -EINVAL;
	}

	if (buffer_size > (1 << 20)) {
		pr_warn("buffer_size %d is very large (> 1MB)\n", buffer_size);
		/* Warning only, don't fail */
	}

	/* Demonstrate log levels */
	demonstrate_log_levels();

	/* Debug-only output */
	if (debug_mode) {
		pr_debug("debug: THIS_MODULE = %px\n", THIS_MODULE);
		pr_debug("debug: module state = LIVE after init returns 0\n");
	}

	pr_info("initialization complete\n");
	pr_info("check parameters at: /sys/module/%s/parameters/\n",
		KBUILD_MODNAME);

	return 0;
}

/* ========================================================================
 * Module Exit Function
 * ======================================================================== */

static void __exit hello_exit(void)
{
	pr_info("cleanup started\n");
	pr_info("final parameter values:\n");
	pr_info("  buffer_size     = %d\n", buffer_size);
	pr_info("  device_name     = %s\n", device_name);
	pr_info("  debug_mode      = %s\n", debug_mode ? "true" : "false");
	pr_info("  max_connections = %d\n", max_connections);
	pr_info("module unloaded successfully\n");
}

/* ========================================================================
 * Module Registration
 * ======================================================================== */

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Comprehensive kernel module structure demonstration");
MODULE_VERSION("1.0.0");
MODULE_INFO(intree, "N");

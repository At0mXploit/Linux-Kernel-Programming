// SPDX-License-Identifier: GPL-2.0
/*
 * list_demo.c - Kernel module demonstrating kernel linked list operations:
 *   - LIST_HEAD declaration and initialization
 *   - list_add / list_add_tail
 *   - list_del / list_del_init
 *   - list_for_each_entry / list_for_each_entry_safe
 *   - list_move / list_splice
 *   - list_first_entry / list_last_entry
 *   - list_empty / list_is_singular
 *   - container_of macro
 *   - hlist for hash table usage
 *
 * Creates /proc/list_demo to display the current list contents.
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod list_demo.ko
 *   dmesg | tail -50
 *   cat /proc/list_demo
 *   sudo rmmod list_demo
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hash.h>
#include <linux/string.h>

/* ========================================================================
 * Data Structures
 * ======================================================================== */

struct city {
	int id;
	char name[32];
	char country[32];
	int population;         /* in thousands */
	struct list_head list;  /* node in the main list */
	struct hlist_node hnode; /* node in the hash table */
};

/* Main linked list */
static LIST_HEAD(city_list);
static int city_count = 0;

/* Secondary list for demonstration */
static LIST_HEAD(large_cities);

/* Hash table (by name) */
#define HASH_BITS  4
#define HASH_SIZE  (1 << HASH_BITS)
static struct hlist_head city_hash[HASH_SIZE];

/* ========================================================================
 * Helper Functions
 * ======================================================================== */

static unsigned int city_hash_fn(const char *name)
{
	unsigned int hash = 0;
	while (*name)
		hash = hash * 31 + *name++;
	return hash_32(hash, HASH_BITS);
}

static struct city *create_city(int id, const char *name,
				const char *country, int population)
{
	struct city *c;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return NULL;

	c->id = id;
	strscpy(c->name, name, sizeof(c->name));
	strscpy(c->country, country, sizeof(c->country));
	c->population = population;
	INIT_LIST_HEAD(&c->list);
	INIT_HLIST_NODE(&c->hnode);

	return c;
}

static void add_city(struct city *c)
{
	unsigned int bucket;

	/* Add to the main list (at tail = FIFO order) */
	list_add_tail(&c->list, &city_list);
	city_count++;

	/* Add to hash table */
	bucket = city_hash_fn(c->name);
	hlist_add_head(&c->hnode, &city_hash[bucket]);
}

static struct city *find_city_by_name(const char *name)
{
	unsigned int bucket = city_hash_fn(name);
	struct city *c;

	hlist_for_each_entry(c, &city_hash[bucket], hnode) {
		if (strcmp(c->name, name) == 0)
			return c;
	}
	return NULL;
}

static void remove_city(struct city *c)
{
	list_del(&c->list);
	hlist_del(&c->hnode);
	city_count--;
}

/* ========================================================================
 * Demonstration Functions
 * ======================================================================== */

static void demo_basic_operations(void)
{
	struct city *c;

	pr_info("=== 1. Basic List Operations ===\n");

	/* Add cities */
	add_city(create_city(1, "Tokyo",     "Japan",   13960));
	add_city(create_city(2, "Delhi",     "India",   32941));
	add_city(create_city(3, "Shanghai",  "China",   28517));
	add_city(create_city(4, "Sao Paulo", "Brazil",  22430));
	add_city(create_city(5, "Mexico City","Mexico",  21919));
	add_city(create_city(6, "Cairo",     "Egypt",   21750));
	add_city(create_city(7, "Mumbai",    "India",   21297));
	add_city(create_city(8, "Beijing",   "China",   20896));
	add_city(create_city(9, "Dhaka",     "Bangladesh",23210));
	add_city(create_city(10,"Osaka",     "Japan",   19165));

	pr_info("added %d cities\n", city_count);
	pr_info("list empty? %s\n", list_empty(&city_list) ? "yes" : "no");
	pr_info("is singular? %s\n",
		list_is_singular(&city_list) ? "yes" : "no");
}

static void demo_iteration(void)
{
	struct city *c;
	int count = 0;

	pr_info("\n=== 2. Iteration (list_for_each_entry) ===\n");

	/* Forward iteration */
	list_for_each_entry(c, &city_list, list) {
		pr_info("  [%d] %-15s %-12s pop=%dk\n",
			c->id, c->name, c->country, c->population);
		count++;
	}
	pr_info("iterated over %d cities\n", count);

	/* Access first and last */
	c = list_first_entry(&city_list, struct city, list);
	pr_info("first city: %s\n", c->name);

	c = list_last_entry(&city_list, struct city, list);
	pr_info("last city: %s\n", c->name);
}

static void demo_safe_deletion(void)
{
	struct city *c, *tmp;
	int removed = 0;

	pr_info("\n=== 3. Safe Deletion (list_for_each_entry_safe) ===\n");
	pr_info("removing cities with population < 21000k...\n");

	/*
	 * MUST use _safe variant when deleting during iteration.
	 * The 'tmp' variable holds the next entry before we potentially
	 * delete the current one.
	 */
	list_for_each_entry_safe(c, tmp, &city_list, list) {
		if (c->population < 21000) {
			pr_info("  removing: %s (pop=%dk)\n",
				c->name, c->population);
			remove_city(c);
			kfree(c);
			removed++;
		}
	}

	pr_info("removed %d cities, %d remaining\n", removed, city_count);
}

static void demo_list_move_splice(void)
{
	struct city *c, *tmp;

	pr_info("\n=== 4. Move and Splice ===\n");

	/* Move cities with population > 25000 to the large_cities list */
	list_for_each_entry_safe(c, tmp, &city_list, list) {
		if (c->population > 25000) {
			pr_info("  moving %s to large_cities list\n", c->name);
			list_move_tail(&c->list, &large_cities);
		}
	}

	pr_info("main list:\n");
	list_for_each_entry(c, &city_list, list)
		pr_info("  %s\n", c->name);

	pr_info("large_cities list:\n");
	list_for_each_entry(c, &large_cities, list)
		pr_info("  %s\n", c->name);

	/* Splice large_cities back into city_list */
	pr_info("splicing large_cities back into main list...\n");
	list_splice_init(&large_cities, &city_list);

	pr_info("large_cities empty? %s\n",
		list_empty(&large_cities) ? "yes" : "no");
}

static void demo_hash_lookup(void)
{
	struct city *c;
	const char *search_names[] = {"Tokyo", "Delhi", "Paris", "Shanghai"};
	int i;

	pr_info("\n=== 5. Hash Table Lookup ===\n");

	for (i = 0; i < ARRAY_SIZE(search_names); i++) {
		c = find_city_by_name(search_names[i]);
		if (c)
			pr_info("  found: %s in %s (pop=%dk)\n",
				c->name, c->country, c->population);
		else
			pr_info("  not found: %s\n", search_names[i]);
	}

	/* Dump hash table bucket distribution */
	pr_info("hash bucket distribution:\n");
	for (i = 0; i < HASH_SIZE; i++) {
		int count = 0;
		struct city *cur;

		hlist_for_each_entry(cur, &city_hash[i], hnode)
			count++;
		if (count > 0)
			pr_info("  bucket[%2d]: %d entries\n", i, count);
	}
}

static void demo_container_of(void)
{
	struct city *c;
	struct list_head *ptr;

	pr_info("\n=== 6. container_of Macro ===\n");

	/* Get the raw list_head pointer */
	ptr = city_list.next;  /* First element's list node */

	/*
	 * container_of recovers the struct city* from the list_head*.
	 * This is the fundamental mechanism that makes intrusive lists work.
	 *
	 * Equivalent to:
	 *   (struct city *)((char *)ptr - offsetof(struct city, list))
	 */
	c = container_of(ptr, struct city, list);
	pr_info("container_of demo: ptr=%px -> city '%s' at %px\n",
		ptr, c->name, c);
	pr_info("  offsetof(struct city, list) = %zu\n",
		offsetof(struct city, list));

	/* list_entry is just an alias for container_of */
	c = list_entry(ptr, struct city, list);
	pr_info("list_entry gives same result: '%s'\n", c->name);
}

static void demo_reverse_iteration(void)
{
	struct city *c;

	pr_info("\n=== 7. Reverse Iteration ===\n");

	list_for_each_entry_reverse(c, &city_list, list)
		pr_info("  %s\n", c->name);
}

/* ========================================================================
 * /proc/list_demo - Display current list state
 * ======================================================================== */

static int list_proc_show(struct seq_file *s, void *v)
{
	struct city *c;
	int i = 0;

	seq_printf(s, "City List (%d entries):\n", city_count);
	seq_puts(s, "-------------------------------------------"
		    "-----------------------\n");
	seq_printf(s, "%-4s %-15s %-12s %s\n",
		   "#", "City", "Country", "Population(k)");
	seq_puts(s, "-------------------------------------------"
		    "-----------------------\n");

	list_for_each_entry(c, &city_list, list) {
		seq_printf(s, "%-4d %-15s %-12s %d\n",
			   ++i, c->name, c->country, c->population);
	}

	seq_puts(s, "-------------------------------------------"
		    "-----------------------\n");

	/* Show large_cities list if non-empty */
	if (!list_empty(&large_cities)) {
		seq_puts(s, "\nLarge Cities (>25000k):\n");
		list_for_each_entry(c, &large_cities, list)
			seq_printf(s, "  %s (%dk)\n", c->name, c->population);
	}

	return 0;
}

static int list_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static const struct proc_ops list_proc_ops = {
	.proc_open    = list_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init list_demo_init(void)
{
	int i;

	/* Initialize hash table */
	for (i = 0; i < HASH_SIZE; i++)
		INIT_HLIST_HEAD(&city_hash[i]);

	/* Run demonstrations */
	demo_basic_operations();
	demo_iteration();
	demo_container_of();
	demo_hash_lookup();
	demo_safe_deletion();
	demo_list_move_splice();
	demo_reverse_iteration();

	/* Create proc entry */
	if (!proc_create("list_demo", 0444, NULL, &list_proc_ops)) {
		pr_err("failed to create /proc/list_demo\n");
		/* Continue without proc -- not fatal */
	}

	pr_info("module loaded -- check dmesg for demo output\n");
	pr_info("current list: cat /proc/list_demo\n");
	return 0;
}

static void __exit list_demo_exit(void)
{
	struct city *c, *tmp;

	remove_proc_entry("list_demo", NULL);

	/* Free all cities in main list */
	list_for_each_entry_safe(c, tmp, &city_list, list) {
		list_del(&c->list);
		hlist_del(&c->hnode);
		kfree(c);
	}

	/* Free any cities in large_cities list */
	list_for_each_entry_safe(c, tmp, &large_cities, list) {
		list_del(&c->list);
		kfree(c);
	}

	pr_info("module unloaded, all memory freed\n");
}

module_init(list_demo_init);
module_exit(list_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Kernel linked list and hash list demonstration");
MODULE_VERSION("1.0.0");

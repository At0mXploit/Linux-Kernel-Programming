// SPDX-License-Identifier: GPL-2.0
/*
 * char_device.c - Complete character device driver with ioctl support.
 *
 * Creates /dev/mod2_chardev with:
 *   - open / release (reference counting)
 *   - read / write (circular buffer)
 *   - ioctl (get/set buffer size, get stats, reset)
 *   - Automatic device node creation via udev
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod char_device.ko
 *   echo "hello" > /dev/mod2_chardev
 *   cat /dev/mod2_chardev
 *   sudo rmmod char_device
 *
 * Ioctl usage from C:
 *   #include "char_device_ioctl.h"
 *   int fd = open("/dev/mod2_chardev", O_RDWR);
 *   struct chardev_stats stats;
 *   ioctl(fd, CHARDEV_IOC_GET_STATS, &stats);
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/ioctl.h>

/* ========================================================================
 * Ioctl Definitions
 *
 * In a real driver, these would be in a shared header file included by
 * both the kernel module and userspace programs.
 * ======================================================================== */

#define CHARDEV_IOC_MAGIC   'C'

/* Reset the buffer */
#define CHARDEV_IOC_RESET       _IO(CHARDEV_IOC_MAGIC, 0)

/* Get current buffer size */
#define CHARDEV_IOC_GET_BUFSIZE _IOR(CHARDEV_IOC_MAGIC, 1, int)

/* Set buffer size (reallocates) */
#define CHARDEV_IOC_SET_BUFSIZE _IOW(CHARDEV_IOC_MAGIC, 2, int)

/* Get statistics */
struct chardev_stats {
	int buffer_size;
	int data_len;
	int open_count;
	unsigned long total_reads;
	unsigned long total_writes;
	unsigned long total_bytes_read;
	unsigned long total_bytes_written;
};

#define CHARDEV_IOC_GET_STATS   _IOR(CHARDEV_IOC_MAGIC, 3, struct chardev_stats)

/* Get/set a string message */
#define CHARDEV_IOC_GET_MSG     _IOR(CHARDEV_IOC_MAGIC, 4, char[64])
#define CHARDEV_IOC_SET_MSG     _IOW(CHARDEV_IOC_MAGIC, 5, char[64])

#define CHARDEV_IOC_MAXNR  5

/* ========================================================================
 * Device State
 * ======================================================================== */

#define DEVICE_NAME     "mod2_chardev"
#define CLASS_NAME      "mod2_class"
#define DEFAULT_BUF_SIZE 4096

struct chardev_data {
	dev_t devno;
	struct cdev cdev;
	struct class *cls;
	struct device *dev;

	/* Buffer for read/write */
	char *buffer;
	int buf_size;
	int data_len;
	struct mutex buf_mutex;

	/* Statistics */
	atomic_t open_count;
	unsigned long total_reads;
	unsigned long total_writes;
	unsigned long total_bytes_read;
	unsigned long total_bytes_written;

	/* Custom message for ioctl demo */
	char message[64];
	struct mutex msg_mutex;
};

static struct chardev_data *chardev;

/* ========================================================================
 * File Operations: open / release
 * ======================================================================== */

static int chardev_open(struct inode *inode, struct file *file)
{
	int count;

	/*
	 * Store device data in file->private_data for use in other fops.
	 * This pattern allows multiple device instances with the same driver.
	 */
	file->private_data = chardev;

	count = atomic_inc_return(&chardev->open_count);
	pr_info("device opened (open_count=%d)\n", count);

	return 0;
}

static int chardev_release(struct inode *inode, struct file *file)
{
	int count;

	count = atomic_dec_return(&chardev->open_count);
	pr_info("device closed (open_count=%d)\n", count);

	return 0;
}

/* ========================================================================
 * File Operations: read
 * ======================================================================== */

static ssize_t chardev_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct chardev_data *dev = file->private_data;
	ssize_t bytes_read;

	mutex_lock(&dev->buf_mutex);

	if (*ppos >= dev->data_len) {
		mutex_unlock(&dev->buf_mutex);
		return 0;  /* EOF */
	}

	/* Clamp count to available data */
	if (count > dev->data_len - *ppos)
		count = dev->data_len - *ppos;

	if (copy_to_user(ubuf, dev->buffer + *ppos, count)) {
		mutex_unlock(&dev->buf_mutex);
		return -EFAULT;
	}

	*ppos += count;
	bytes_read = count;

	dev->total_reads++;
	dev->total_bytes_read += bytes_read;

	pr_info("read %zd bytes (pos=%lld, data_len=%d)\n",
		bytes_read, *ppos, dev->data_len);

	mutex_unlock(&dev->buf_mutex);
	return bytes_read;
}

/* ========================================================================
 * File Operations: write
 * ======================================================================== */

static ssize_t chardev_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct chardev_data *dev = file->private_data;

	mutex_lock(&dev->buf_mutex);

	/* Clamp to buffer size */
	if (count > dev->buf_size - 1)
		count = dev->buf_size - 1;

	if (count == 0) {
		mutex_unlock(&dev->buf_mutex);
		return 0;
	}

	if (copy_from_user(dev->buffer, ubuf, count)) {
		mutex_unlock(&dev->buf_mutex);
		return -EFAULT;
	}

	dev->data_len = count;
	dev->buffer[count] = '\0';
	*ppos = count;

	dev->total_writes++;
	dev->total_bytes_written += count;

	pr_info("wrote %zd bytes: '%.32s%s'\n",
		count, dev->buffer, count > 32 ? "..." : "");

	mutex_unlock(&dev->buf_mutex);
	return count;
}

/* ========================================================================
 * File Operations: ioctl
 * ======================================================================== */

static long chardev_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct chardev_data *dev = file->private_data;
	int val;
	struct chardev_stats stats;
	char msg_buf[64];

	/* Validate command */
	if (_IOC_TYPE(cmd) != CHARDEV_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > CHARDEV_IOC_MAXNR)
		return -ENOTTY;

	switch (cmd) {
	case CHARDEV_IOC_RESET:
		pr_info("ioctl: RESET\n");
		mutex_lock(&dev->buf_mutex);
		memset(dev->buffer, 0, dev->buf_size);
		dev->data_len = 0;
		mutex_unlock(&dev->buf_mutex);
		break;

	case CHARDEV_IOC_GET_BUFSIZE:
		pr_info("ioctl: GET_BUFSIZE\n");
		val = dev->buf_size;
		if (copy_to_user((int __user *)arg, &val, sizeof(val)))
			return -EFAULT;
		break;

	case CHARDEV_IOC_SET_BUFSIZE:
		if (copy_from_user(&val, (int __user *)arg, sizeof(val)))
			return -EFAULT;

		pr_info("ioctl: SET_BUFSIZE to %d\n", val);

		if (val < 64 || val > (1 << 20)) {
			pr_err("buffer size must be in [64, 1048576]\n");
			return -EINVAL;
		}

		mutex_lock(&dev->buf_mutex);
		{
			char *new_buf = kzalloc(val, GFP_KERNEL);
			if (!new_buf) {
				mutex_unlock(&dev->buf_mutex);
				return -ENOMEM;
			}

			/* Copy existing data (up to new size) */
			if (dev->data_len > 0) {
				int copy_len = min(dev->data_len, val - 1);

				memcpy(new_buf, dev->buffer, copy_len);
				dev->data_len = copy_len;
			}

			kfree(dev->buffer);
			dev->buffer = new_buf;
			dev->buf_size = val;
		}
		mutex_unlock(&dev->buf_mutex);
		break;

	case CHARDEV_IOC_GET_STATS:
		pr_info("ioctl: GET_STATS\n");
		mutex_lock(&dev->buf_mutex);
		stats.buffer_size = dev->buf_size;
		stats.data_len = dev->data_len;
		stats.open_count = atomic_read(&dev->open_count);
		stats.total_reads = dev->total_reads;
		stats.total_writes = dev->total_writes;
		stats.total_bytes_read = dev->total_bytes_read;
		stats.total_bytes_written = dev->total_bytes_written;
		mutex_unlock(&dev->buf_mutex);

		if (copy_to_user((struct chardev_stats __user *)arg,
				 &stats, sizeof(stats)))
			return -EFAULT;
		break;

	case CHARDEV_IOC_GET_MSG:
		pr_info("ioctl: GET_MSG\n");
		mutex_lock(&dev->msg_mutex);
		if (copy_to_user((char __user *)arg, dev->message,
				 sizeof(dev->message))) {
			mutex_unlock(&dev->msg_mutex);
			return -EFAULT;
		}
		mutex_unlock(&dev->msg_mutex);
		break;

	case CHARDEV_IOC_SET_MSG:
		pr_info("ioctl: SET_MSG\n");
		if (copy_from_user(msg_buf, (char __user *)arg,
				   sizeof(msg_buf)))
			return -EFAULT;
		msg_buf[sizeof(msg_buf) - 1] = '\0';

		mutex_lock(&dev->msg_mutex);
		strscpy(dev->message, msg_buf, sizeof(dev->message));
		mutex_unlock(&dev->msg_mutex);
		pr_info("message set to: '%s'\n", dev->message);
		break;

	default:
		return -ENOTTY;
	}

	return 0;
}

/* ========================================================================
 * File Operations Structure
 * ======================================================================== */

static const struct file_operations chardev_fops = {
	.owner          = THIS_MODULE,
	.open           = chardev_open,
	.release        = chardev_release,
	.read           = chardev_read,
	.write          = chardev_write,
	.unlocked_ioctl = chardev_ioctl,
};

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init chardev_init(void)
{
	int ret;

	/* Allocate device data */
	chardev = kzalloc(sizeof(*chardev), GFP_KERNEL);
	if (!chardev)
		return -ENOMEM;

	/* Allocate data buffer */
	chardev->buf_size = DEFAULT_BUF_SIZE;
	chardev->buffer = kzalloc(chardev->buf_size, GFP_KERNEL);
	if (!chardev->buffer) {
		ret = -ENOMEM;
		goto err_free_dev;
	}

	mutex_init(&chardev->buf_mutex);
	mutex_init(&chardev->msg_mutex);
	strscpy(chardev->message, "(no message)", sizeof(chardev->message));

	/* Allocate device number (dynamic major) */
	ret = alloc_chrdev_region(&chardev->devno, 0, 1, DEVICE_NAME);
	if (ret) {
		pr_err("failed to allocate chrdev region: %d\n", ret);
		goto err_free_buf;
	}
	pr_info("device number: major=%d minor=%d\n",
		MAJOR(chardev->devno), MINOR(chardev->devno));

	/* Initialize and add cdev */
	cdev_init(&chardev->cdev, &chardev_fops);
	chardev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&chardev->cdev, chardev->devno, 1);
	if (ret) {
		pr_err("failed to add cdev: %d\n", ret);
		goto err_unregister;
	}

	/* Create device class (visible in /sys/class/) */
	chardev->cls = class_create(CLASS_NAME);
	if (IS_ERR(chardev->cls)) {
		ret = PTR_ERR(chardev->cls);
		pr_err("failed to create class: %d\n", ret);
		goto err_cdev_del;
	}

	/* Create device node (triggers udev, creates /dev/mod2_chardev) */
	chardev->dev = device_create(chardev->cls, NULL, chardev->devno,
				     NULL, DEVICE_NAME);
	if (IS_ERR(chardev->dev)) {
		ret = PTR_ERR(chardev->dev);
		pr_err("failed to create device: %d\n", ret);
		goto err_class_destroy;
	}

	pr_info("module loaded\n");
	pr_info("device: /dev/%s (major=%d)\n",
		DEVICE_NAME, MAJOR(chardev->devno));
	pr_info("usage:\n");
	pr_info("  echo 'data' > /dev/%s\n", DEVICE_NAME);
	pr_info("  cat /dev/%s\n", DEVICE_NAME);
	return 0;

err_class_destroy:
	class_destroy(chardev->cls);
err_cdev_del:
	cdev_del(&chardev->cdev);
err_unregister:
	unregister_chrdev_region(chardev->devno, 1);
err_free_buf:
	kfree(chardev->buffer);
err_free_dev:
	kfree(chardev);
	return ret;
}

static void __exit chardev_exit(void)
{
	if (!chardev)
		return;

	pr_info("stats: reads=%lu writes=%lu bytes_r=%lu bytes_w=%lu\n",
		chardev->total_reads, chardev->total_writes,
		chardev->total_bytes_read, chardev->total_bytes_written);

	device_destroy(chardev->cls, chardev->devno);
	class_destroy(chardev->cls);
	cdev_del(&chardev->cdev);
	unregister_chrdev_region(chardev->devno, 1);

	kfree(chardev->buffer);
	kfree(chardev);

	pr_info("module unloaded\n");
}

module_init(chardev_init);
module_exit(chardev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Complete character device driver with ioctl");
MODULE_VERSION("1.0.0");

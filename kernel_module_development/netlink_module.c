// SPDX-License-Identifier: GPL-2.0
/*
 * netlink_module.c - Kernel module communicating with userspace via netlink.
 *
 * Receives messages from userspace, processes them, and sends replies.
 * Supports two message types:
 *   - ECHO: echoes the message back with a kernel-side timestamp
 *   - INFO: returns kernel information (uptime, jiffies, etc.)
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Usage:
 *   sudo insmod netlink_module.ko
 *   ./netlink_user          # run the userspace companion
 *   sudo rmmod netlink_module
 *
 * See netlink_user.c for the userspace companion program.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/jiffies.h>
#include <linux/utsname.h>

/* ========================================================================
 * Protocol Definition
 *
 * Use protocol number 31 (NETLINK_USERSOCK=2 is for userspace-only,
 * numbers 17-31 are available for custom protocols).
 * In production, use Generic Netlink (NETLINK_GENERIC) instead.
 * ======================================================================== */

#define NETLINK_MOD2_PROTO  31

/* Message types */
#define MSG_TYPE_ECHO    1
#define MSG_TYPE_INFO    2
#define MSG_TYPE_ACK     3
#define MSG_TYPE_ERROR   4

/* Maximum payload size */
#define MAX_PAYLOAD      1024

/* ========================================================================
 * Module State
 * ======================================================================== */

static struct sock *nl_sock;
static atomic_t msg_count = ATOMIC_INIT(0);

/* ========================================================================
 * Send a reply to userspace
 * ======================================================================== */

static int send_reply(int pid, int msg_type, const char *data, int len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
	int res;

	skb_out = nlmsg_new(len, GFP_KERNEL);
	if (!skb_out) {
		pr_err("failed to allocate skb for reply\n");
		return -ENOMEM;
	}

	nlh = nlmsg_put(skb_out, 0, 0, msg_type, len, 0);
	if (!nlh) {
		kfree_skb(skb_out);
		return -EMSGSIZE;
	}

	NETLINK_CB(skb_out).dst_group = 0;  /* Unicast */
	memcpy(nlmsg_data(nlh), data, len);

	res = nlmsg_unicast(nl_sock, skb_out, pid);
	if (res < 0) {
		pr_err("failed to send reply to pid %d: %d\n", pid, res);
		return res;
	}

	return 0;
}

/* ========================================================================
 * Handle incoming messages from userspace
 * ======================================================================== */

static void handle_echo(int pid, const char *payload, int len)
{
	char reply[MAX_PAYLOAD];
	int reply_len;
	unsigned long sec;

	sec = jiffies / HZ;

	reply_len = scnprintf(reply, sizeof(reply),
			      "[%lu.%03lu] ECHO: %.*s",
			      sec, (jiffies % HZ) * 1000 / HZ,
			      len, payload);

	pr_info("echo request from pid %d: '%.*s'\n", pid, len, payload);
	send_reply(pid, MSG_TYPE_ACK, reply, reply_len);
}

static void handle_info(int pid)
{
	char reply[MAX_PAYLOAD];
	int reply_len;

	reply_len = scnprintf(reply, sizeof(reply),
		"kernel: %s %s\n"
		"jiffies: %lu\n"
		"HZ: %d\n"
		"uptime: %lu sec\n"
		"messages_received: %d\n",
		utsname()->sysname,
		utsname()->release,
		jiffies,
		HZ,
		jiffies / HZ,
		atomic_read(&msg_count));

	pr_info("info request from pid %d\n", pid);
	send_reply(pid, MSG_TYPE_ACK, reply, reply_len);
}

static void nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	char *payload;
	int pid, msg_type, payload_len;

	nlh = nlmsg_hdr(skb);
	pid = nlh->nlmsg_pid;
	msg_type = nlh->nlmsg_type;
	payload = nlmsg_data(nlh);
	payload_len = nlmsg_len(nlh);

	atomic_inc(&msg_count);

	pr_info("received message: type=%d pid=%d len=%d\n",
		msg_type, pid, payload_len);

	switch (msg_type) {
	case MSG_TYPE_ECHO:
		handle_echo(pid, payload, payload_len);
		break;

	case MSG_TYPE_INFO:
		handle_info(pid);
		break;

	default:
		pr_warn("unknown message type %d from pid %d\n",
			msg_type, pid);
		send_reply(pid, MSG_TYPE_ERROR, "unknown command",
			   strlen("unknown command"));
		break;
	}
}

/* ========================================================================
 * Module Init / Exit
 * ======================================================================== */

static int __init netlink_demo_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = nl_recv_msg,   /* Callback for incoming messages */
		.groups = 0,            /* No multicast groups */
		.flags = 0,
	};

	nl_sock = netlink_kernel_create(&init_net, NETLINK_MOD2_PROTO, &cfg);
	if (!nl_sock) {
		pr_err("failed to create netlink socket\n");
		return -ENOMEM;
	}

	pr_info("module loaded (protocol=%d)\n", NETLINK_MOD2_PROTO);
	pr_info("run the userspace companion: ./netlink_user\n");
	return 0;
}

static void __exit netlink_demo_exit(void)
{
	if (nl_sock) {
		netlink_kernel_release(nl_sock);
		nl_sock = NULL;
	}

	pr_info("module unloaded (total messages: %d)\n",
		atomic_read(&msg_count));
}

module_init(netlink_demo_init);
module_exit(netlink_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Linux Programming Course");
MODULE_DESCRIPTION("Netlink kernel-userspace communication module");
MODULE_VERSION("1.0.0");

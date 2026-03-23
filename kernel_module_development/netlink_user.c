/*
 * netlink_user.c - Userspace companion for netlink_module.ko
 *
 * Communicates with the kernel netlink module using protocol 31.
 * Sends ECHO and INFO commands and displays kernel responses.
 *
 * Build (userspace, not a kernel module):
 *   gcc -Wall -o netlink_user netlink_user.c
 *
 * Usage:
 *   sudo insmod netlink_module.ko    # Load the kernel module first
 *   sudo ./netlink_user              # Must run as root for raw netlink
 *
 * Message types:
 *   1 (ECHO) - Send a string, get it echoed back with timestamp
 *   2 (INFO) - Request kernel information
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* Must match the kernel module definitions */
#define NETLINK_MOD2_PROTO  31
#define MSG_TYPE_ECHO       1
#define MSG_TYPE_INFO       2
#define MSG_TYPE_ACK        3
#define MSG_TYPE_ERROR      4
#define MAX_PAYLOAD         1024

/* ========================================================================
 * Netlink Helpers
 * ======================================================================== */

struct netlink_ctx {
	int sock_fd;
	struct sockaddr_nl src_addr;
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
};

static int netlink_init(struct netlink_ctx *ctx)
{
	ctx->sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MOD2_PROTO);
	if (ctx->sock_fd < 0) {
		perror("socket(PF_NETLINK)");
		fprintf(stderr,
			"Hint: Make sure netlink_module.ko is loaded and "
			"you are running as root.\n");
		return -1;
	}

	/* Bind to our PID */
	memset(&ctx->src_addr, 0, sizeof(ctx->src_addr));
	ctx->src_addr.nl_family = AF_NETLINK;
	ctx->src_addr.nl_pid = getpid();
	ctx->src_addr.nl_groups = 0;

	if (bind(ctx->sock_fd, (struct sockaddr *)&ctx->src_addr,
		 sizeof(ctx->src_addr)) < 0) {
		perror("bind");
		close(ctx->sock_fd);
		return -1;
	}

	/* Destination: kernel (pid 0) */
	memset(&ctx->dest_addr, 0, sizeof(ctx->dest_addr));
	ctx->dest_addr.nl_family = AF_NETLINK;
	ctx->dest_addr.nl_pid = 0;      /* Kernel */
	ctx->dest_addr.nl_groups = 0;

	/* Allocate netlink message buffer */
	ctx->nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!ctx->nlh) {
		perror("malloc");
		close(ctx->sock_fd);
		return -1;
	}

	return 0;
}

static void netlink_cleanup(struct netlink_ctx *ctx)
{
	if (ctx->nlh)
		free(ctx->nlh);
	if (ctx->sock_fd >= 0)
		close(ctx->sock_fd);
}

static int netlink_send(struct netlink_ctx *ctx, int msg_type,
			const char *data, int data_len)
{
	memset(ctx->nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	ctx->nlh->nlmsg_len = NLMSG_LENGTH(data_len);
	ctx->nlh->nlmsg_pid = getpid();
	ctx->nlh->nlmsg_flags = 0;
	ctx->nlh->nlmsg_type = msg_type;

	if (data && data_len > 0)
		memcpy(NLMSG_DATA(ctx->nlh), data, data_len);

	ctx->iov.iov_base = ctx->nlh;
	ctx->iov.iov_len = ctx->nlh->nlmsg_len;

	memset(&ctx->msg, 0, sizeof(ctx->msg));
	ctx->msg.msg_name = &ctx->dest_addr;
	ctx->msg.msg_namelen = sizeof(ctx->dest_addr);
	ctx->msg.msg_iov = &ctx->iov;
	ctx->msg.msg_iovlen = 1;

	if (sendmsg(ctx->sock_fd, &ctx->msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}

	return 0;
}

static int netlink_recv(struct netlink_ctx *ctx, char *buf, int buf_size,
			int *msg_type)
{
	int len;

	memset(ctx->nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	ctx->nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);

	ctx->iov.iov_base = ctx->nlh;
	ctx->iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&ctx->msg, 0, sizeof(ctx->msg));
	ctx->msg.msg_name = &ctx->dest_addr;
	ctx->msg.msg_namelen = sizeof(ctx->dest_addr);
	ctx->msg.msg_iov = &ctx->iov;
	ctx->msg.msg_iovlen = 1;

	len = recvmsg(ctx->sock_fd, &ctx->msg, 0);
	if (len < 0) {
		perror("recvmsg");
		return -1;
	}

	if (msg_type)
		*msg_type = ctx->nlh->nlmsg_type;

	len = NLMSG_PAYLOAD(ctx->nlh, 0);
	if (len > buf_size - 1)
		len = buf_size - 1;

	memcpy(buf, NLMSG_DATA(ctx->nlh), len);
	buf[len] = '\0';

	return len;
}

/* ========================================================================
 * Main Program
 * ======================================================================== */

int main(int argc, char *argv[])
{
	struct netlink_ctx ctx;
	char recv_buf[MAX_PAYLOAD];
	int msg_type;
	const char *echo_messages[] = {
		"Hello from userspace!",
		"Testing netlink communication",
		"Message number three",
	};
	int i;

	printf("=== Netlink Userspace Client ===\n");
	printf("PID: %d\n", getpid());
	printf("Protocol: %d\n\n", NETLINK_MOD2_PROTO);

	/* Initialize netlink context */
	if (netlink_init(&ctx) < 0) {
		fprintf(stderr, "Failed to initialize netlink\n");
		return EXIT_FAILURE;
	}

	/* ---- Test 1: Echo messages ---- */
	printf("--- Test 1: Echo Messages ---\n");
	for (i = 0; i < 3; i++) {
		const char *msg = echo_messages[i];

		printf("\n[SEND] type=ECHO payload='%s'\n", msg);

		if (netlink_send(&ctx, MSG_TYPE_ECHO, msg,
				 strlen(msg)) < 0) {
			fprintf(stderr, "Failed to send echo message\n");
			goto cleanup;
		}

		if (netlink_recv(&ctx, recv_buf, sizeof(recv_buf),
				 &msg_type) < 0) {
			fprintf(stderr, "Failed to receive reply\n");
			goto cleanup;
		}

		printf("[RECV] type=%d payload='%s'\n", msg_type, recv_buf);
	}

	/* ---- Test 2: Info request ---- */
	printf("\n--- Test 2: Kernel Info Request ---\n");
	printf("\n[SEND] type=INFO\n");

	if (netlink_send(&ctx, MSG_TYPE_INFO, "", 0) < 0) {
		fprintf(stderr, "Failed to send info request\n");
		goto cleanup;
	}

	if (netlink_recv(&ctx, recv_buf, sizeof(recv_buf), &msg_type) < 0) {
		fprintf(stderr, "Failed to receive info reply\n");
		goto cleanup;
	}

	printf("[RECV] type=%d payload:\n%s\n", msg_type, recv_buf);

	/* ---- Test 3: Interactive mode (if requested) ---- */
	if (argc > 1 && strcmp(argv[1], "-i") == 0) {
		char input[MAX_PAYLOAD];

		printf("\n--- Interactive Mode (type 'quit' to exit) ---\n");
		while (1) {
			printf("\nEnter message: ");
			fflush(stdout);

			if (!fgets(input, sizeof(input), stdin))
				break;

			/* Remove newline */
			input[strcspn(input, "\n")] = '\0';

			if (strcmp(input, "quit") == 0)
				break;

			if (strcmp(input, "info") == 0) {
				netlink_send(&ctx, MSG_TYPE_INFO, "", 0);
			} else {
				netlink_send(&ctx, MSG_TYPE_ECHO,
					     input, strlen(input));
			}

			if (netlink_recv(&ctx, recv_buf, sizeof(recv_buf),
					 &msg_type) < 0) {
				fprintf(stderr, "Receive failed\n");
				break;
			}

			printf("[RECV] type=%d: %s\n", msg_type, recv_buf);
		}
	}

	printf("\n=== Done ===\n");

cleanup:
	netlink_cleanup(&ctx);
	return EXIT_SUCCESS;
}

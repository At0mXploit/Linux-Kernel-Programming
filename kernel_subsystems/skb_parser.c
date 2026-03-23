/*
 * skb_parser.c - Kernel module demonstrating sk_buff inspection
 *
 * Demonstrates how to inspect sk_buff structures
 * by registering a netfilter hook on the loopback interface and
 * parsing packet headers at various layers.
 *
 * This module intercepts packets on the loopback interface and logs
 * detailed information about the sk_buff metadata, IP header, and
 * transport header fields.
 *
 * Usage:
 *   insmod skb_parser.ko
 *   ping -c 3 127.0.0.1            # generate ICMP traffic
 *   curl http://127.0.0.1:8080/    # generate TCP traffic (if server running)
 *   nc -u 127.0.0.1 9999 <<< "hello"  # generate UDP traffic
 *   dmesg | grep skb_parser
 *   rmmod skb_parser
 *
 * Build: Part of the kernel_subsystems Makefile
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Subsystems Lab");
MODULE_DESCRIPTION("sk_buff parser demonstrating network packet inspection");

/* Maximum number of packets to log (to prevent log flooding) */
static int max_packets = 50;
module_param(max_packets, int, 0644);
MODULE_PARM_DESC(max_packets, "Maximum number of packets to log (default: 50)");

static atomic_t packet_count = ATOMIC_INIT(0);

/*
 * log_skb_metadata - Log sk_buff structure metadata
 *
 * This function demonstrates accessing various fields of the sk_buff
 * structure that are relevant to understanding packet processing.
 */
static void log_skb_metadata(const struct sk_buff *skb, int pkt_num)
{
    pr_info("skb_parser: === Packet #%d sk_buff metadata ===\n", pkt_num);

    /* ── Buffer geometry ── */
    pr_info("skb_parser:   head=%px data=%px tail=%u end=%u\n",
            skb->head, skb->data, skb->tail, skb->end);
    pr_info("skb_parser:   len=%u data_len=%u (linear=%u)\n",
            skb->len, skb->data_len, skb_headlen(skb));

    /*
     * headroom: space before data pointer (for prepending headers)
     * tailroom: space after tail pointer (for appending data)
     */
    pr_info("skb_parser:   headroom=%u tailroom=%u\n",
            skb_headroom(skb), skb_tailroom(skb));

    /* ── Protocol and type ── */
    pr_info("skb_parser:   protocol=0x%04x pkt_type=%d\n",
            ntohs(skb->protocol), skb->pkt_type);

    /* ── Header offsets ── */
    pr_info("skb_parser:   mac_header=%u network_header=%u "
            "transport_header=%u\n",
            skb->mac_header, skb->network_header,
            skb->transport_header);

    /* ── Device info ── */
    if (skb->dev)
        pr_info("skb_parser:   dev=%s ifindex=%d\n",
                skb->dev->name, skb->dev->ifindex);

    /* ── Checksum info ── */
    pr_info("skb_parser:   ip_summed=%d (0=NONE, 1=UNNECESSARY, "
            "2=COMPLETE, 3=PARTIAL)\n",
            skb->ip_summed);

    /* ── Mark and hash ── */
    pr_info("skb_parser:   mark=0x%x hash=0x%x\n",
            skb->mark, skb->hash);

    /* ── Clone and shared info ── */
    pr_info("skb_parser:   cloned=%d users=%d\n",
            skb->cloned, refcount_read(&skb->users));
}

/*
 * log_ip_header - Parse and log the IPv4 header
 */
static void log_ip_header(const struct iphdr *iph)
{
    pr_info("skb_parser:   [IPv4] version=%u ihl=%u tos=0x%02x "
            "tot_len=%u\n",
            iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len));
    pr_info("skb_parser:   [IPv4] id=%u frag_off=0x%04x ttl=%u "
            "protocol=%u\n",
            ntohs(iph->id), ntohs(iph->frag_off),
            iph->ttl, iph->protocol);
    pr_info("skb_parser:   [IPv4] saddr=%pI4 daddr=%pI4 "
            "check=0x%04x\n",
            &iph->saddr, &iph->daddr, ntohs(iph->check));
}

/*
 * log_tcp_header - Parse and log the TCP header
 */
static void log_tcp_header(const struct tcphdr *tcph)
{
    pr_info("skb_parser:   [TCP] sport=%u dport=%u\n",
            ntohs(tcph->source), ntohs(tcph->dest));
    pr_info("skb_parser:   [TCP] seq=%u ack_seq=%u\n",
            ntohl(tcph->seq), ntohl(tcph->ack_seq));
    pr_info("skb_parser:   [TCP] doff=%u window=%u check=0x%04x\n",
            tcph->doff, ntohs(tcph->window), ntohs(tcph->check));
    pr_info("skb_parser:   [TCP] flags: %s%s%s%s%s%s%s%s\n",
            tcph->fin ? "FIN " : "",
            tcph->syn ? "SYN " : "",
            tcph->rst ? "RST " : "",
            tcph->psh ? "PSH " : "",
            tcph->ack ? "ACK " : "",
            tcph->urg ? "URG " : "",
            tcph->ece ? "ECE " : "",
            tcph->cwr ? "CWR " : "");
}

/*
 * log_udp_header - Parse and log the UDP header
 */
static void log_udp_header(const struct udphdr *udph)
{
    pr_info("skb_parser:   [UDP] sport=%u dport=%u len=%u check=0x%04x\n",
            ntohs(udph->source), ntohs(udph->dest),
            ntohs(udph->len), ntohs(udph->check));
}

/*
 * log_icmp_header - Parse and log the ICMP header
 */
static void log_icmp_header(const struct icmphdr *icmph)
{
    const char *type_str;

    switch (icmph->type) {
    case ICMP_ECHOREPLY:     type_str = "Echo Reply"; break;
    case ICMP_DEST_UNREACH:  type_str = "Destination Unreachable"; break;
    case ICMP_REDIRECT:      type_str = "Redirect"; break;
    case ICMP_ECHO:          type_str = "Echo Request"; break;
    case ICMP_TIME_EXCEEDED: type_str = "Time Exceeded"; break;
    default:                 type_str = "Other"; break;
    }

    pr_info("skb_parser:   [ICMP] type=%u (%s) code=%u "
            "checksum=0x%04x\n",
            icmph->type, type_str, icmph->code,
            ntohs(icmph->checksum));

    if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
        pr_info("skb_parser:   [ICMP] id=%u seq=%u\n",
                ntohs(icmph->un.echo.id),
                ntohs(icmph->un.echo.sequence));
    }
}

/*
 * nf_hook_func - Netfilter hook callback for packet inspection
 *
 * We hook at LOCAL_OUT to catch packets generated locally
 * (which includes loopback traffic).
 */
static unsigned int nf_hook_func(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    int pkt_num;

    if (!skb || !skb->dev)
        return NF_ACCEPT;

    /* Only inspect loopback packets */
    if (!(skb->dev->flags & IFF_LOOPBACK))
        return NF_ACCEPT;

    /* Check packet limit */
    pkt_num = atomic_inc_return(&packet_count);
    if (pkt_num > max_packets) {
        if (pkt_num == max_packets + 1)
            pr_info("skb_parser: reached max_packets=%d, stopping logs\n",
                    max_packets);
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return NF_ACCEPT;

    /* ── Log sk_buff metadata ── */
    log_skb_metadata(skb, pkt_num);

    /* ── Log IP header ── */
    log_ip_header(iph);

    /* ── Log transport header based on protocol ── */
    switch (iph->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcph;
        tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));
        log_tcp_header(tcph);
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udph;
        udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));
        log_udp_header(udph);
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmph;
        icmph = (struct icmphdr *)((unsigned char *)iph + (iph->ihl * 4));
        log_icmp_header(icmph);
        break;
    }
    default:
        pr_info("skb_parser:   [Proto %u] (no detailed parser)\n",
                iph->protocol);
        break;
    }

    pr_info("skb_parser: ─────────────────────────────────────\n");

    return NF_ACCEPT;
}

/* ──────────────── Hook registration ──────────────── */

static struct nf_hook_ops nf_skb_hook = {
    .hook     = nf_hook_func,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

static int __init skb_parser_init(void)
{
    int ret;

    ret = nf_register_net_hook(&init_net, &nf_skb_hook);
    if (ret) {
        pr_err("skb_parser: failed to register hook: %d\n", ret);
        return ret;
    }

    pr_info("skb_parser: module loaded, inspecting loopback packets\n");
    pr_info("skb_parser: will log up to %d packets\n", max_packets);
    pr_info("skb_parser: try: ping -c 3 127.0.0.1\n");
    return 0;
}

static void __exit skb_parser_exit(void)
{
    nf_unregister_net_hook(&init_net, &nf_skb_hook);
    pr_info("skb_parser: module unloaded (inspected %d packets)\n",
            atomic_read(&packet_count));
}

module_init(skb_parser_init);
module_exit(skb_parser_exit);

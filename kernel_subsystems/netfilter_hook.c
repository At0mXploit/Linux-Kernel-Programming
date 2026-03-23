/*
 * netfilter_hook.c - Educational netfilter hook module
 *
 * Demonstrates netfilter hook registration by
 * installing a hook at NF_INET_PRE_ROUTING that logs packet information.
 *
 * This module is purely observational (defensive/educational):
 * it logs packet metadata and always returns NF_ACCEPT.
 *
 * Usage:
 *   insmod netfilter_hook.ko
 *   # Generate traffic: ping localhost, curl http://example.com, etc.
 *   dmesg | grep nf_hook
 *   rmmod netfilter_hook
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
#include <linux/inet.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Subsystems Lab");
MODULE_DESCRIPTION("Educational netfilter hook that logs packet metadata");

/* Rate limit logging to avoid flooding the kernel log */
static unsigned long last_log_jiffies;
static int pkt_count;

/*
 * get_protocol_name - Convert IP protocol number to human-readable name
 */
static const char *get_protocol_name(u8 protocol)
{
    switch (protocol) {
    case IPPROTO_TCP:   return "TCP";
    case IPPROTO_UDP:   return "UDP";
    case IPPROTO_ICMP:  return "ICMP";
    case IPPROTO_IGMP:  return "IGMP";
    case IPPROTO_GRE:   return "GRE";
    case IPPROTO_ESP:   return "ESP";
    case IPPROTO_AH:    return "AH";
    case IPPROTO_SCTP:  return "SCTP";
    default:            return "OTHER";
    }
}

/*
 * nf_hook_func - The netfilter hook callback
 *
 * This function is called for every IPv4 packet at the PRE_ROUTING hook.
 * We inspect the IP header and optionally the transport header to log
 * useful packet information.
 *
 * @priv:  Private data (unused)
 * @skb:   The socket buffer containing the packet
 * @state: Hook state (input/output device, hook number, etc.)
 *
 * Returns: NF_ACCEPT (always -- this is an observational module)
 */
static unsigned int nf_hook_func(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    unsigned int data_len;

    if (!skb)
        return NF_ACCEPT;

    /* Ensure we have access to the IP header */
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    /* Count packets */
    pkt_count++;

    /*
     * Rate-limit logging: log at most every 100ms or every 100th packet.
     * In a real module, you would use a more sophisticated approach
     * (e.g., per-flow counters, BPF maps, etc.).
     */
    if (time_before(jiffies, last_log_jiffies + msecs_to_jiffies(100))
        && (pkt_count % 100 != 0))
        return NF_ACCEPT;

    last_log_jiffies = jiffies;
    data_len = ntohs(iph->tot_len) - (iph->ihl * 4);

    /* Log based on protocol */
    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));

        /*
         * Log TCP packet details:
         * - Source and destination IP (%pI4 is the kernel's IP format specifier)
         * - Source and destination ports
         * - TCP flags (SYN, ACK, FIN, RST, PSH)
         * - Data length
         */
        pr_info("nf_hook [TCP]: %pI4:%u -> %pI4:%u "
                "flags=[%s%s%s%s%s] len=%u dev=%s\n",
                &iph->saddr, ntohs(tcph->source),
                &iph->daddr, ntohs(tcph->dest),
                tcph->syn ? "SYN " : "",
                tcph->ack ? "ACK " : "",
                tcph->fin ? "FIN " : "",
                tcph->rst ? "RST " : "",
                tcph->psh ? "PSH " : "",
                data_len,
                state->in ? state->in->name : "?");
        break;

    case IPPROTO_UDP:
        udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));

        pr_info("nf_hook [UDP]: %pI4:%u -> %pI4:%u len=%u dev=%s\n",
                &iph->saddr, ntohs(udph->source),
                &iph->daddr, ntohs(udph->dest),
                data_len,
                state->in ? state->in->name : "?");
        break;

    case IPPROTO_ICMP:
        icmph = (struct icmphdr *)((unsigned char *)iph + (iph->ihl * 4));

        pr_info("nf_hook [ICMP]: %pI4 -> %pI4 type=%u code=%u dev=%s\n",
                &iph->saddr, &iph->daddr,
                icmph->type, icmph->code,
                state->in ? state->in->name : "?");
        break;

    default:
        pr_info("nf_hook [%s/%u]: %pI4 -> %pI4 len=%u dev=%s\n",
                get_protocol_name(iph->protocol),
                iph->protocol,
                &iph->saddr, &iph->daddr,
                data_len,
                state->in ? state->in->name : "?");
        break;
    }

    /*
     * IMPORTANT: Always return NF_ACCEPT.
     * This module is observational only; it never drops packets.
     * In a real firewall module, you would return NF_DROP for
     * packets that should be blocked.
     */
    return NF_ACCEPT;
}

/* ──────────────── Hook registration ──────────────── */

/*
 * Define the netfilter hook operations structure.
 * We hook at NF_INET_PRE_ROUTING with the highest priority
 * (NF_IP_PRI_FIRST) to see packets before any other hooks.
 */
static struct nf_hook_ops nf_hook_ops_struct = {
    .hook     = nf_hook_func,
    .pf       = NFPROTO_IPV4,           /* IPv4 protocol family     */
    .hooknum  = NF_INET_PRE_ROUTING,    /* Before routing decision  */
    .priority = NF_IP_PRI_FIRST,        /* Highest priority         */
};

static int __init nf_hook_init(void)
{
    int ret;

    /*
     * Register the hook with the init_net namespace.
     * For a production module, you might want to register for
     * all namespaces using register_pernet_subsys().
     */
    ret = nf_register_net_hook(&init_net, &nf_hook_ops_struct);
    if (ret) {
        pr_err("nf_hook: failed to register hook: %d\n", ret);
        return ret;
    }

    pkt_count = 0;
    last_log_jiffies = jiffies;

    pr_info("nf_hook: netfilter hook registered at PRE_ROUTING\n");
    pr_info("nf_hook: monitoring IPv4 packets (TCP/UDP/ICMP)\n");
    return 0;
}

static void __exit nf_hook_exit(void)
{
    nf_unregister_net_hook(&init_net, &nf_hook_ops_struct);
    pr_info("nf_hook: netfilter hook unregistered (processed %d packets)\n",
            pkt_count);
}

module_init(nf_hook_init);
module_exit(nf_hook_exit);

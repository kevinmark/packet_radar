//#define _IPV4_

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

MODULE_LICENSE("GPL");

#ifdef _IPV4_
inline void dumpIpHdr(const char *fn, const struct sk_buff *skb)
{
	const struct iphdr *ip = ip_hdr(skb);

	const struct tcphdr *tcp = tcp_hdr(skb);
	//unsigned char *target_port = "\x00\x50";    // port：80

	//if( (tcp->source == *(unsigned short *)target_port)||(tcp->dest == *(unsigned short *)target_port) )
	//{
		printk(KERN_ALERT "%s, saddr:%u.%u.%u.%u:%hu, daddr:%u.%u.%u.%u:%hu\n", fn, NIPQUAD(ip->saddr), ntohs(tcp->source), NIPQUAD(ip->daddr), ntohs(tcp->dest));

	if(!strcmp(fn, "postrouting"))
		printk(KERN_ALERT "---------------------------------\n");
	//}

	// ref:
	//if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP))
	//
	// ref: sort by ICMP	
	//if(iph->protocol == IPPROTO_ICMP)
	//{
	//	printk(KERN_INFO"hook_icmp::icmp_srv: receive ICMP packet\n");
	//	printk(KERN_INFO"src: ");
	//}	
}

static unsigned int
prerouting(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIpHdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
localin(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIpHdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
localout(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIpHdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
postrouting(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIpHdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
fwding(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIpHdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}
#endif

inline void dumpIp6Hdr(const char *fn, const struct sk_buff *skb)
{
	const struct ipv6hdr *ipv6 = ipv6_hdr(skb);
	const struct tcphdr *tcp = tcp_hdr(skb);

	printk(KERN_ALERT "%s, saddr:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%hu, daddr:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%hu\n", fn, NIP6(ipv6->saddr), ntohs(tcp->source), NIP6(ipv6->daddr), ntohs(tcp->dest));

	if(!strcmp(fn, "postrouting6"))
	printk(KERN_ALERT "---------------------------------\n");
}

static unsigned int
prerouting6(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIp6Hdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
localin6(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIp6Hdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
localout6(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIp6Hdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
postrouting6(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIp6Hdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static unsigned int
fwding6(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	dumpIp6Hdr(__FUNCTION__, skb);
	return NF_ACCEPT;
}

static struct nf_hook_ops brook_ops[] __read_mostly = {
#ifdef _IPV4_
	{
		.hook = prerouting,
		.pf = PF_INET,
		.hooknum = NF_IP_PRE_ROUTING,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = localin,
		.pf = PF_INET,
		.hooknum = NF_IP_LOCAL_IN,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = fwding,
		.pf = PF_INET,
		.hooknum = NF_IP_FORWARD,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = localout,
		.pf = PF_INET,
		.hooknum = NF_IP_LOCAL_OUT,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = postrouting,
		.pf = PF_INET,
		.hooknum = NF_IP_POST_ROUTING,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, 
#endif
	{
		.hook = prerouting6,
		.pf = PF_INET6,
		.hooknum = NF_IP6_PRE_ROUTING,
		.priority = NF_IP6_PRI_FIRST,
		.owner = THIS_MODULE,
	}, {
		.hook = localin6,
		.pf = PF_INET6,
		.hooknum = NF_IP6_LOCAL_IN,
		.priority = NF_IP6_PRI_FIRST,
		.owner = THIS_MODULE,
	}, {
		.hook = fwding6,
		.pf = PF_INET6,
		.hooknum = NF_IP6_FORWARD,
		.priority = NF_IP6_PRI_FIRST,
		.owner = THIS_MODULE,
	}, {
		.hook = localout6,
		.pf = PF_INET6,
		.hooknum = NF_IP6_LOCAL_OUT,
		.priority = NF_IP6_PRI_FIRST,
		.owner = THIS_MODULE,
	}, {
		.hook = postrouting6,
		.pf = PF_INET6,
		.hooknum = NF_IP6_POST_ROUTING,
		.priority = NF_IP6_PRI_FIRST,
		.owner = THIS_MODULE,
	},

};

static int __init init_modules(void)
{
	if (nf_register_hooks(brook_ops, ARRAY_SIZE(brook_ops)) < 0) {
		printk("nf_register_hook failed\n");
	}
	return 0;
}

static void __exit exit_modules(void)
{
	nf_unregister_hooks(brook_ops, ARRAY_SIZE(brook_ops));
}

module_init(init_modules);
module_exit(exit_modules);



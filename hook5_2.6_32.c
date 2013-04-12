#include <linux/init.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");

inline void dumpIpHdr(const char *fn, const struct sk_buff *skb)
{
	const struct iphdr *ip = ip_hdr(skb);

	const struct tcphdr *tcp = tcp_hdr(skb);
//	unsigned char *target_port = "\x00\x50";    // port：80

//	if( (tcp->source == *(unsigned short *)target_port)||(tcp->dest == *(unsigned short *)target_port) )
//	{
		printk(KERN_ALERT "%s, saddr:%pI4:%hu, daddr:%pI4:%hu\n", fn, &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

	if(!strcmp(fn, "postrouting"))
		printk(KERN_ALERT "---------------------------------\n");
//	}

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

static struct nf_hook_ops brook_ops[] __read_mostly = {
	{
		.hook = prerouting,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = localin,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = fwding,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = localout,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_RAW,
		.owner = THIS_MODULE,
	}, {
		.hook = postrouting,
			.pf = PF_INET,
			.hooknum = NF_INET_POST_ROUTING,
			.priority = NF_IP_PRI_RAW,
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



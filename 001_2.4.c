#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>                  /* For IP header */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* 用于注册我们的函数的数据结构 */
static struct nf_hook_ops nfho;

/* 我们要丢弃的数据包来自的地址，网络字节序 */
static unsigned char *drop_ip = "\x7f\x00\x00\x01";

/* 注册的hook函数的实现 */
unsigned int hook_func(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = skb;
	struct iphdr *ip_head;

	ip_head = ip_hdr(sb);
//	if (sb->nh.iph->saddr == *(unsigned int *)drop_ip) {
	if (ip_head->saddr == *(unsigned int *)drop_ip)
	{
		// if (sb->nh.iph->saddr == drop_ip) {
		printk("Dropped packet from... %d.%d.%d.%d\n",
				*drop_ip, *(drop_ip + 1),
				*(drop_ip + 2), *(drop_ip + 3));
//		return NF_DROP;
		return NF_ACCEPT;
	} 
	else 
	{
		return NF_ACCEPT;
	}
}

	/* 初始化程序 */
	int init_module()
	{
		/* 填充我们的hook数据结构 */
		nfho.hook     = hook_func;         /* 处理函数 */
//		nfho.hooknum  = NF_IP_LOCAL_IN; /* 使用IPv4的第一个hook */
		nfho.hooknum  = NF_INET_LOCAL_IN; /* 使用IPv4的第一个hook */
		nfho.pf       = PF_INET;
		nfho.priority = NF_IP_PRI_FIRST;   /* 让我们的函数首先执行 */

		nf_register_hook(&nfho);

		return 0;
	}

	/* 清除程序 */
	void cleanup_module()
	{
		nf_unregister_hook(&nfho);
	}



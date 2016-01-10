/*
 *
 * netfilter : hang up ACK and modify advertise window (works on linux)
 * ref : https://github.com/rops/netfilter-stringscleaner/blob/master/xt_POLIMI.c
 *
 * v1.0  kernel module setup
 * v1.1  ssh          compatibility
 * v1.2  ftp          compatibility
 * v1.3  wget         compatibility
 * v1.4  scp upload   compatibility
 * v1.5  scp download compatibility
 *
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPLv3");

static inline __sum16 tcp_v4_check(int len, __be32 saddr, __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}

inline unsigned int modifyIpHdr(const char *fn, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	//struct tcphdr *tcph = tcp_hdr(skb);  // not valid
	//http://www.linuxquestions.org/questions/programming-9/tcp-checksum-calculation-4175416394/
	struct tcphdr *tcph = (void *)(skb_network_header(skb) + iph->ihl * 4); // Gets the TCP header
	int tcplen;
	static int tcpwin_old=0;


	//(1) list the origin content of skb
	//printk(KERN_ALERT "%s, saddr:%pI4:%hu, daddr:%pI4:%hu\n", fn, &iph->saddr, ntohs(tcph->source), &iph->daddr, ntohs(tcph->dest));

	//(2) filter 'ACK' package
	//tcp_header :
	//http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html
	//printk(KERN_ALERT "ACK:%d\n", tcph->ack);
	//printk(KERN_ALERT "SYN:%d\n", tcph->syn);
	//printk(KERN_ALERT "FIN:%d\n", tcph->fin);
	//printk(KERN_ALERT "PSH:%d\n", tcph->psh);

	//(2a) skip syn+ack or fin+ack
	// ack+psh : TLSv1.2 (SSL) data transfer
	//if (tcph->syn || tcph->fin || tcph->psh )
	if (tcph->syn || tcph->fin )
		return NF_ACCEPT;

	//(2b) skip https service (443)

	//(2c) skip continuous data-transfer
	//printk(KERN_ALERT "[tcp_win]:%d\n", ntohs(tcph->window));
	//printk(KERN_ALERT "[tcp_win_old]:%d\n", tcpwin_old);
	if( tcpwin_old <= ntohs(tcph->window) )
	{
		tcpwin_old= ntohs(tcph->window);
		return NF_ACCEPT;
	}
	tcpwin_old= ntohs(tcph->window);

	//(2d) small(cnotrol) packets doesn't need to be modified
	//printk(KERN_ALERT "[tcp_win]:%d\n", ntohs(tcph->window));
	//tcplen = (skb->len - (iph->ihl << 2));
	//printk(KERN_ALERT "[tcp_len]:%d\n", tcplen);
	//printk(KERN_ALERT "[skb_len]:%d\n", skb->len);
	//if( ntohs(tcph->window) < 10240 )
	//	return NF_ACCEPT;

	//(3) modify package
	// http://stackoverflow.com/questions/8237983/packet-processing-in-netfilter-hooks
	//printk(KERN_ALERT "[advertise win_old]:%hu\n", ntohs(tcph->window));
	//printk(KERN_ALERT "[tcp_win]:edit 0x??ff\n");
	tcph->window = htons(0xffff);
	//tcph->window = htons(0x8fff);
	//printk(KERN_ALERT "[advertise win_new]:%hu\n", ntohs(tcph->window));

	//(4) calculate new checksum
	// http://www.spinics.net/lists/newbies/msg49938.html

	// after linearize, obtain new pointer position
	// http://stackoverflow.com/questions/16610989/calculating-tcp-checksum-in-a-netfilter-module
	if( skb_linearize(skb)<0 ){
		//printk("[POLIMI] Not Linearizable \n");
		return NF_DROP;
	}
	tcph = (void *)(skb_network_header(skb) + iph->ihl * 4);
	iph = ip_hdr(skb);	

	/* tcp checksum */
	//printk(KERN_ALERT "[tcp_check_old]:%d\n", tcph->check);
	tcplen = (skb->len - (iph->ihl << 2)); //tcplen is the length of the skb - the ip-header length 
	tcph->check = 0; //This must be zero to be able to calculate it with csum above.
	tcph->check = tcp_v4_check(tcplen,
                                iph->saddr,
                                iph->daddr,
                                csum_partial((char*) tcph, tcplen, 0));
	//printk(KERN_ALERT "[tcp_check_new]:%d\n", tcph->check);
	/* IP Checksum */
	iph->check = htons(0);
	iph->check = ip_fast_csum((unsigned char *) iph,iph->ihl);

	return NF_ACCEPT;
}

static unsigned int
postrouting(unsigned int hook, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	return modifyIpHdr(__FUNCTION__, skb);
}

static struct nf_hook_ops brook_ops[] __read_mostly = {
	{
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



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/protocol.h>

#include <linux/string.h>

#include "nc_kernel_module.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uncerso");
MODULE_DESCRIPTION("NC kernel");
MODULE_VERSION("1");

#define PF_NC 41
#define IPPROTO_NC 200

struct sk_buff * (*ip_make_skb_nc)(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags) = NULL;

int (*ip_send_skb_nc)(struct net *net, struct sk_buff *skb) = NULL;

static inline struct nchdr *nc_hdr(const struct sk_buff *skb) {
	return (struct nchdr *)skb_transport_header(skb);
}

struct handlers * handlers_head = NULL;
struct states * find_state_record(__u32 prog_id, int state) {
	struct handlers * hptr = handlers_head;
	struct states * sptr = NULL;
	while (hptr) {
		if (prog_id == hptr->prog_id) {
			sptr = hptr->state;
			break;
		}
		hptr = hptr->next;
	}
	while (sptr) {
		if (state == sptr->state)
			break;
		sptr = sptr->next;
	}
	return sptr;
}

int nc_sock_release(struct socket *sock) {
	struct sock *sk = sock->sk;
	printk(KERN_DEBUG "nc_kernel: nc_sock_release: start\n");
	
	if (!sk) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_release: sk is nullptr\n");
		return 0;
	}
	lock_sock(sk);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	release_sock(sk);
	sock_put(sk);
	printk(KERN_DEBUG "nc_kernel: nc_sock_release: ok\n\n");
	return 0;
}

char * last_str;
size_t last_str_size;

void set_hdrs(struct sk_buff *skb, size_t size) {
	struct nchdr *nch = nc_hdr(skb);
	__u64 random_number;
	get_random_bytes_arch(&random_number, sizeof(random_number));
	skb->ip_summed = CHECKSUM_NONE;
	nch->total_len = htonl(sizeof(struct nchdr) + size);
	nch->id = htonl(random_number);
}

int nc_send(struct socket *sock, struct msghdr *msg, size_t size) {
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = NULL;
	struct flowi4 fl4_stack;
	struct flowi4 *fl4 = &fl4_stack;
	struct inet_cork cork;
	struct ipcm_cookie ipc;
	struct sk_buff *skb;
	__be32 daddr = inet->inet_daddr;
	__be32 saddr = inet->inet_saddr;
	__be32 faddr;
	int err;
	u8 tos;
	int connected = 1;
	printk(KERN_DEBUG "nc_kernel: nc_send: start\n");
	
	ipcm_init_sk(&ipc, inet);
	ipc.addr = faddr = daddr;
	tos = get_rttos(&ipc, inet);

	printk(KERN_DEBUG "nc_kernel: nc_send: daddr %u\n", ntohl(daddr));
	printk(KERN_DEBUG "nc_kernel: nc_send: saddr %u\n", ntohl(saddr));

	if (sock_flag(sk, SOCK_LOCALROUTE)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (!ipc.oif)
		ipc.oif = inet->uc_index;

	if (connected) {
		printk(KERN_DEBUG "nc_kernel: nc_send: connected\n");
		rt = (struct rtable *)sk_dst_check(sk, 0);
	}
	
	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);
		printk(KERN_DEBUG "nc_kernel: nc_send: rt is NULL\n");

		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
					RT_SCOPE_UNIVERSE, sk->sk_protocol,
					flow_flags,
					faddr, saddr, 0, inet->inet_sport,
					sk->sk_uid);
		
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			printk(KERN_DEBUG "nc_kernel: nc_send: rt error\n");
			err = PTR_ERR(rt);
			rt = NULL;
			return -1;
		}
		sk_dst_set(sk, dst_clone(&rt->dst));
	}
	skb = ip_make_skb_nc(sk, fl4, ip_generic_getfrag, msg, sizeof(struct nchdr)+size,
				sizeof(struct nchdr), &ipc, &rt,
				&cork, msg->msg_flags);
	err = PTR_ERR(skb);
	printk(KERN_DEBUG "nc_kernel: nc_send: PTR_ERR = %d\n", err);

	set_hdrs(skb, size);

	if (!IS_ERR_OR_NULL(skb)) {
		err = ip_send_skb_nc(sock_net(sk), skb);
		printk(KERN_DEBUG "nc_kernel: nc_send: return value of ip_send_skb is %d\n", err);
	}
	if (rt) {
		printk(KERN_DEBUG "nc_kernel: nc_send: rt free\n");
		ip_rt_put(rt);
	}
	printk(KERN_DEBUG "nc_kernel: nc_send: ok\n");
	return 0;
}

int nc_sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	struct iovec data;
	struct inet_sock *inet = inet_sk(sock->sk);
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: start\n");

	inet->inet_daddr = htonl(3232235625u); // 192.168.0.105

	nc_send(sock, msg, size);

	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: ok\n\n");
	return 0;	
}

int nc_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct iovec data;
	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: start\n");
	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: msg is not an iovec\n");
		return 0;
	}
	data = iov_iter_iovec(&msg->msg_iter);
	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: size = %lu, buf_len = %lu\n", size, data.iov_len);
	
	copy_to_user(data.iov_base, last_str, min(last_str_size, data.iov_len-1));

	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: ok\n\n");
	return 0;
}

struct proto_ops nc_proto_ops = {
	.family		= PF_NC,
	.owner		= THIS_MODULE,
	.release	= nc_sock_release,
	.sendmsg	= nc_sock_sendmsg,
	.recvmsg	= nc_sock_recvmsg,
};

struct nc_sock {
	//inet_sock should be first
	struct inet_sock   inet;
//	int		   field;
};

static struct proto nc_prot = {
	.name		= "NC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct nc_sock),
};

int nc_sock_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk;

	printk(KERN_DEBUG "nc_kernel: nc_sock_create: start\n");

	if (!net_eq(net, &init_net)) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_create: Not eq!\n");
		return -1;
	}

	sk = sk_alloc(net, PF_NC, GFP_KERNEL, &nc_prot, kern);
	if (!sk) {
		printk(KERN_DEBUG "ERROR sk don't allocated");
		return -1;
	}

	sock->state = SS_UNCONNECTED;
	sock->ops = &nc_proto_ops;
	sock->type = 2;
	sock_init_data(sock, sk);
	sk->sk_protocol = IPPROTO_NC;

	printk(KERN_DEBUG "nc_kernel: nc_sock_create: ok\n\n");
	return 0;
}

static const struct net_proto_family nc_proto_family = {
	.family		= PF_NC,
	.create		= nc_sock_create,
	.owner		= THIS_MODULE,
};

void update_str(char const * str, size_t size) {
	void * kdata = kmalloc(size, GFP_KERNEL);
	if (!kdata) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: kdata = 0\n");
		return;
	}
	memcpy(kdata, str, size);
	swap(last_str, kdata);
	last_str_size = size;
	if (kdata)
		kfree(kdata);
}

int nc_rcv(struct sk_buff *skb) {
	printk(KERN_DEBUG "nc_kernel: nc_rcv: data received!\n\n");
	while(skb) {
		struct sk_buff * next = skb->next;
		struct nchdr * nch = nc_hdr(skb);
		printk(KERN_DEBUG "nc_kernel: nc_rcv: %d\n", skb->len);
		printk(KERN_DEBUG "nc_kernel: nc_rcv: %d\n", ntohl(nch->total_len));
		printk(KERN_DEBUG "nc_kernel: nc_rcv: %lu\n", ntohl(nch->id));
		
		update_str(skb->data + sizeof(struct nchdr), skb->len - sizeof(struct nchdr));

		kfree_skb(skb);
		skb = next;
	}
	return 0;
}

int nc_err(struct sk_buff *skb, u32 info) {
	printk(KERN_DEBUG "nc_kernel: nc_err: Oops! Error info = %u\n\n", info);
	return 0;
}

static struct net_protocol nc_protocol = {
	.handler		= nc_rcv,
	.err_handler	= nc_err,
	.no_policy		= 1,
	.netns_ok		= 1,
};

static struct inet_protosw inet_protosw_nc = {
	.type		= 2,
	.protocol	= IPPROTO_NC,
	.prot		= &nc_prot,
	.ops		= &nc_proto_ops,
	.flags		= INET_PROTOSW_REUSE,
};

static int __init nc_kernel_init(void) {
	int err;
	char init_str[] = "init_str";
	printk(KERN_DEBUG "nc_kernel: init: start\n");

	err = sock_register(&nc_proto_family);
	printk(KERN_DEBUG "nc_kernel: init: return value of sock_register is %d\n", err);
	if (err) {
		sock_unregister(PF_NC);
		err = sock_register(&nc_proto_family);
		printk(KERN_DEBUG "nc_kernel: init: return value of sock_register (attemption 2) is %d\n", err);
		if (err)
			return err;
	}	
	err = proto_register(&nc_prot, 1);
	printk(KERN_DEBUG "nc_kernel: init: return value of proto_register is %d\n", err);
	if (err) return err;

	err = inet_add_protocol(&nc_protocol, IPPROTO_NC);
	printk(KERN_DEBUG "nc_kernel: init: return value of inet_add_protocol is %d\n", err);
	if (err) return err;

	inet_register_protosw(&inet_protosw_nc);

	ip_make_skb_nc = kallsyms_lookup_name("ip_make_skb");
	ip_send_skb_nc = kallsyms_lookup_name("ip_send_skb");

	last_str_size = sizeof(init_str);
	last_str = kmalloc(last_str_size, GFP_KERNEL);
	memcpy(last_str, init_str, last_str_size);

	printk(KERN_DEBUG "nc_kernel: init: ok\n\n");
	return 0;
}

static void __exit nc_kernel_exit(void) {
	int err;
	printk(KERN_DEBUG "nc_kernel: exit: start\n");
	
	inet_unregister_protosw(&inet_protosw_nc);

	err = inet_del_protocol(&nc_protocol, IPPROTO_NC);
	printk(KERN_DEBUG "nc_kernel: init: return value of inet_del_protocol is %d\n", err);
	
	proto_unregister(&nc_prot);
	sock_unregister(PF_NC);
	
	if (last_str)
		kfree(last_str);
	printk(KERN_DEBUG "nc_kernel: exit: ok\n\n");
}

module_init(nc_kernel_init);
module_exit(nc_kernel_exit);
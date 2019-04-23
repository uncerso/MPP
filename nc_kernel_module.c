#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/protocol.h>
#include <linux/mutex.h>

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

struct id_ip idip = {
	.ips = {3232235624u, 3232235624u, 3232235624u},
};

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

DEFINE_MUTEX(str_lock);
char * last_str = NULL;
char * out_str = NULL;
int last_str_size = 0;

void set_hdrs(struct sk_buff *skb, size_t size, char const * str_with_hdr) {
	struct nchdr *nch = nc_hdr(skb);
	__u64 random_number;
	printk(KERN_DEBUG "nc_kernel: set_hdrs: start\n");
	if (str_with_hdr) {
		memcpy(nch, str_with_hdr, sizeof(struct nchdr));
		nch->state = htons(ntohs(nch->state)+1);
	} else {
		get_random_bytes_arch(&random_number, sizeof(random_number));
		skb->ip_summed = CHECKSUM_NONE;
		nch->total_len = htonl(sizeof(struct nchdr) + size);
		nch->id = htonl(random_number);
		nch->state = htons(1);
		nch->prog_id = htonl(1);
	}

}

int nc_send(struct socket *sock, struct msghdr *msg, size_t size, char const * str_with_hdr) {
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

	if (sock_flag(sk, SOCK_LOCALROUTE)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (!ipc.oif)
		ipc.oif = inet->uc_index;

	// if (connected) {
	// 	printk(KERN_DEBUG "nc_kernel: nc_send: connected\n");
	// 	rt = (struct rtable *)sk_dst_check(sk, 0);
	// }
	
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

	set_hdrs(skb, size, str_with_hdr);

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
	struct inet_sock *inet = inet_sk(sock->sk);
//	char * kdata;
	struct iovec data;
	char * out_str_local = NULL;
	struct nchdr * nch;
	int cur_state = 0;
	struct states * st;
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: start\n");

	if (size < 2) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: msg too small\n");
		goto out;
	}

	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: msg is not an iovec\n");
		goto out;
	}

	// data = iov_iter_iovec(&msg->msg_iter);
	// kdata = kmalloc(size, GFP_KERNEL);
	// if (!kdata) {
	// 	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: kdata = 0\n");
	// 	goto out;
	// }

//	mutex_lock_interruptible(&str_lock);
	out_str_local = out_str;
	out_str = NULL;
//	mutex_unlock(&str_lock);
	
	// copy_from_user(kdata, data.iov_base, size);
	// printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: size = %d, str = %s\n", size, kdata);

	// if (kdata[size-2] == '!') {
	// 	inet->inet_daddr = htonl(idip.ips[0]);
	// } else if ('0' <= kdata[size-2] && kdata[size-2] <= '2') {
	// 	inet->inet_daddr = htonl(idip.ips[kdata[size-2]-'0']);
	// } else {
	// 	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: invalid data\n");
	// 	goto out;
	// }

	if (out_str_local) {
		nch = (struct nchdr *)out_str_local;
		cur_state = ntohs(nch->state);
	}
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: state = %d\n", cur_state);
	st = find_state_record(1, cur_state);
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: st = %x\n", st);
	if (!st)
		goto out;
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: st->state = %d\n", st->state);
	inet->inet_daddr = htonl(idip.ips[st->state]);
	nc_send(sock, msg, size, out_str_local);

out:
	if (out_str_local)
		kfree(out_str_local);
	printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: ok\n\n");
	return 0;	
}

int nc_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct iovec data;
	int out_size;
	// mutex_lock_interruptible(&str_lock);
	if (!last_str) {
		goto out_err;
	}
	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: start\n");
	
	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: msg is not an iovec\n");
		goto out_ok;
	}
	data = iov_iter_iovec(&msg->msg_iter);
//	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: size = %lu, buf_len = %lu\n", size, data.iov_len);

	if (out_str)
		kfree(out_str);
	out_str = last_str;
	last_str = NULL;
	out_size = last_str_size;
	last_str_size = 0;

	if (out_size < sizeof(struct nchdr) + 2) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: BUG detected\n");
		printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: size = %d\n", last_str_size);
		goto out_err;
	}

	copy_to_user(data.iov_base, out_str+sizeof(struct nchdr), min(out_size-sizeof(struct nchdr), size));

out_ok:
	// mutex_unlock(&str_lock);
	printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: ok\n\n");
	return 0;
out_err:
	// mutex_unlock(&str_lock);
	return -1;
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
	char * kdata = kmalloc(size, GFP_KERNEL);
	printk(KERN_DEBUG "nc_kernel: update_str: updating str...\n");
	if (!kdata) {
		printk(KERN_DEBUG "nc_kernel: update_str: kdata = 0\n");
		return;
	}
	memcpy(kdata, str, size);

	// mutex_lock_interruptible(&str_lock);
	swap(last_str, kdata);
	last_str_size = size;
	// mutex_unlock(&str_lock);

	if (kdata)
		kfree(kdata);
	printk(KERN_DEBUG "nc_kernel: update_str: ok\n\n");
}

int nc_rcv(struct sk_buff *skb) {
	printk(KERN_DEBUG "nc_kernel: nc_rcv: data received!\n\n");
	while(skb) {
		struct sk_buff * next = skb->next;
		update_str(skb->data, skb->len);
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

struct handlers * make_prog(void) {
	struct handlers * tmp  = kmalloc(sizeof(struct handlers), GFP_KERNEL);
	if (!tmp) return NULL;
	tmp->next = NULL;
	tmp->prog_id = 1;
	tmp->state = NULL;
	return tmp;
}

struct states * make_state(int num) {
	struct states * tmp = kmalloc(sizeof(struct states), GFP_KERNEL);
	if (!tmp) return NULL;
	tmp->next = NULL;
	tmp->state = num;
	return tmp;
}

static int __init nc_kernel_init(void) {
	int const sz = 10;
	int const sts[] = {0, 2, 1, 1, 2, 0, 1, 2, 0, 1};
	struct states * sptr = NULL;
	int err;
	int i;
	printk(KERN_DEBUG "nc_kernel: init: start\n");

	handlers_head = make_prog();
	if (!handlers_head) {
		printk(KERN_DEBUG "nc_kernel: init: wtf1\n");
		return -1;
	}
	handlers_head->state = make_state(sts[0]);
	sptr = handlers_head->state;
	for (i = 1; i < sz; ++i) {
		sptr->next = make_state(sts[i]);
		if (!sptr->next) {
			printk(KERN_DEBUG "nc_kernel: init: wtf2\n");
			return -1;
		}
		sptr = sptr->next;
	}

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

	printk(KERN_DEBUG "nc_kernel: init: ok\n\n");
	return 0;
}

static void __exit nc_kernel_exit(void) {
	int err;
	struct states * sptr = NULL;
	printk(KERN_DEBUG "nc_kernel: exit: start\n");
	
	inet_unregister_protosw(&inet_protosw_nc);

	err = inet_del_protocol(&nc_protocol, IPPROTO_NC);
	printk(KERN_DEBUG "nc_kernel: init: return value of inet_del_protocol is %d\n", err);
	
	proto_unregister(&nc_prot);
	sock_unregister(PF_NC);
	
	if (handlers_head) {
		sptr = handlers_head->state;
		kfree(handlers_head);
	}
	while(sptr){
		struct states * next = sptr->next;
		kfree(sptr);
		sptr = next;
	}

	if (last_str)
		kfree(last_str);
	if (out_str)
		kfree(out_str);
	mutex_destroy(&str_lock);
	printk(KERN_DEBUG "nc_kernel: exit: ok\n\n");
}

module_init(nc_kernel_init);
module_exit(nc_kernel_exit);
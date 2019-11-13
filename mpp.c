#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/protocol.h>

#include <linux/string.h>

#include "mpp.h"
#include "mpp_queues.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uncerso");
MODULE_VERSION("1");

#define PF_MPP 41
#define IPPROTO_MPP 200

struct sk_buff * (*ip_make_skb_mpp)(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags) = NULL;

int (*ip_send_skb_mpp)(struct net *net, struct sk_buff *skb) = NULL;

static inline struct mpphdr *mpp_hdr(const struct sk_buff *skb) {
	return (struct mpphdr *)skb_transport_header(skb);
}

struct id_ip idip = {
//	.ips = {2130706433u, 2130706433u, 2130706433u},
	// .ips = {3232235625u, 3232235625u, 3232235625u},
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

//struct tasks_queue recv_queue;
struct msg_queue control_msg_queue;
//==============================================
void handler_data_init(struct handler_data * hd) {
	atomic_set(&hd->cnt, 0);
	tasks_queue_init(&hd->q);
}

void handler_data_destroy(struct handler_data * hd) {
	tasks_queue_destroy(&hd->q);
}

void mpphdr_dump(struct mpphdr *mpph) {
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: type = %u\n", mpph->type);
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: code = %u\n", mpph->code);
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: loop_cnt = %u\n", ntohs(mpph->loop_cnt));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: prog_id = %u\n", ntohl(mpph->prog_id));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: state = %u\n", ntohs(mpph->state));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: flags = %u\n", ntohs(mpph->flags));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: id = %d\n", ntohl(mpph->id));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: total_len = %u\n", ntohl(mpph->total_len));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: csum = %d\n", ntohl(mpph->csum));
	printk(KERN_DEBUG "mpp_kernel: mpphdr_dump: last_cpoint_id = %u\n", ntohl(mpph->last_cpoint_id));
}

void wake_up_handler(int handler_type) {
	struct msg_node * node;
	node = kmalloc(sizeof(struct msg_node), GFP_KERNEL);
	if (!node) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_create: msg_node don't allocated");
		return;
	}

	node->data.code = 1;
	node->data.value = handler_type;
	msg_queue_push(&control_msg_queue, node);
}

#define handler_id_size 15
struct handler_data handlers_storage[handler_id_size];

//==============================================
// handlers
void default_handler(struct sk_buff * skb, struct states * st) {
	if (unlikely(st->handler_type < 0 || st->handler_type >= handler_id_size)) {
		printk(KERN_WARNING "mpp_kernel: default_handler: incorrect handler type: %d\n", st->handler_type);
		mpphdr_dump(mpp_hdr(skb));
		kfree_skb(skb);
	}
	tasks_queue_push(&handlers_storage[st->handler_type].q, skb);
	if (!atomic_read(&handlers_storage[st->handler_type].cnt))
		wake_up_handler(st->handler_type);
}
//==============================================

inline struct mpp_sock * cast_to_mpp_sock(struct sock * sk) {
	return (struct mpp_sock *)inet_sk(sk);
}

int mpp_sock_release(struct socket *sock) {
	struct sock *sk = sock->sk;
	struct mpp_sock *mppsk = cast_to_mpp_sock(sk);
	int handler_type;
	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_release: start\n");
	
	if (!sk) 
		goto out;
	
	lock_sock(sk);
	handler_type = cast_to_mpp_sock(sk)->handler_type;
	if (mppsk->node_to_send)
		kfree_skb(mppsk->node_to_send);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	release_sock(sk);
	sock_put(sk);
	if (unlikely(handler_type < 0 || handler_type >= handler_id_size)) {
		printk(KERN_ERR "mpp_kernel: mpp_sock_release: taint was detected! Socket was released with protocol = %d\n", handler_type);
		goto out;
	}
	
	if (!atomic_dec_and_test(&handlers_storage[handler_type].cnt) && handlers_storage[handler_type].q.head) 
		wake_up_handler(handler_type);
	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_release: ok\n\n");
out:
	return 0;
}

struct sk_buff * node_to_send = NULL;

void set_hdrs(struct sk_buff *skb, size_t size, char const * str_with_hdr) {
	struct mpphdr *mpph = mpp_hdr(skb);
	__u64 random_number;
	// printk(KERN_DEBUG "mpp_kernel: set_hdrs: start\n");
	if (str_with_hdr) {
		memcpy(mpph, str_with_hdr, sizeof(struct mpphdr));
		mpph->state = htons((ntohs(mpph->state)+1)&1);
	} else {
		// printk(KERN_DEBUG "mpp_kernel: set_hdrs: new prog\n");
		get_random_bytes_arch(&random_number, sizeof(random_number));
		skb->ip_summed = CHECKSUM_NONE;
		mpph->total_len = htonl(sizeof(struct mpphdr) + size);
		mpph->id = htonl(random_number);
		mpph->state = htons(1);
		mpph->prog_id = htonl(1);

		mpph->type = 0;
		mpph->code = 0;
		mpph->csum = 0;
		mpph->flags = 0;
		mpph->loop_cnt = 0;
		mpph->last_cpoint_id = 0;
	}
	// mpphdr_dump(mpph);
}

int mpp_send(struct socket *sock, struct msghdr *msg, size_t size, char const * str_with_hdr) {
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
	// printk(KERN_DEBUG "mpp_kernel: mpp_send: start\n");
	
	ipcm_init_sk(&ipc, inet);
	ipc.addr = faddr = daddr;
	tos = get_rttos(&ipc, inet);

	if (sock_flag(sk, SOCK_LOCALROUTE)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (!ipc.oif)
		ipc.oif = inet->uc_index;

	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
					RT_SCOPE_UNIVERSE, sk->sk_protocol,
					flow_flags,
					faddr, saddr, 0, inet->inet_sport,
					sk->sk_uid);
		
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			printk(KERN_DEBUG "mpp_kernel: mpp_send: rt error\n");
			err = PTR_ERR(rt);
			rt = NULL;
			return -1;
		}
		sk_dst_set(sk, dst_clone(&rt->dst));
	}
	skb = ip_make_skb_mpp(sk, fl4, ip_generic_getfrag, msg, sizeof(struct mpphdr)+size,
				sizeof(struct mpphdr), &ipc, &rt,
				&cork, msg->msg_flags);
	err = PTR_ERR(skb);
	// printk(KERN_DEBUG "mpp_kernel: mpp_send: PTR_ERR = %d\n", err);

	if (!IS_ERR_OR_NULL(skb)) {
		set_hdrs(skb, size, str_with_hdr);
		err = ip_send_skb_mpp(sock_net(sk), skb);
		// printk(KERN_DEBUG "mpp_kernel: mpp_send: return value of ip_send_skb is %d\n", err);
	}
	if (likely(rt))
		ip_rt_put(rt);
	// printk(KERN_DEBUG "mpp_kernel: mpp_send: ok\n");
	return 0;
}

int mpp_sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	struct inet_sock *inet = inet_sk(sock->sk);
	struct iovec data;
	struct mpphdr * mpph;
	struct states * st;
	int cur_state = 0;
	char const * str = NULL;
	struct mpp_sock * mppsk = cast_to_mpp_sock(sock->sk);
	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_sendmsg: start\n");

	if (size < 1) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_sendmsg: msg too small\n");
		goto out;
	}

	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_sendmsg: msg is not an iovec\n");
		goto out;
	}

	data = iov_iter_iovec(&msg->msg_iter);
	
	if (mppsk->node_to_send) {
		mpph = (struct mpphdr *)mppsk->node_to_send->data;
		cur_state = ntohs(mpph->state);
		str = mppsk->node_to_send->data;
	}
	st = find_state_record(1, cur_state);
	if (!st) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_sendmsg: the end of the path was reached\n");
		goto out;
	}
	inet->inet_daddr = htonl(idip.ips[st->next_dev]);
	mpp_send(sock, msg, size, str);

out:
	if (mppsk->node_to_send) {
		kfree_skb(mppsk->node_to_send);
		mppsk->node_to_send = NULL;
	}
	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_sendmsg: ok\n\n");
	return 0;	
}

int common_rcv(struct mpp_sock * mppsk, struct msghdr *msg, size_t size) {
	struct iovec data;
	struct sk_buff * node = NULL;

	node = tasks_queue_pop(&handlers_storage[mppsk->handler_type].q);
	if (!node)
		return -1;
	
	data = iov_iter_iovec(&msg->msg_iter);

	copy_to_user(data.iov_base, node->data+sizeof(struct mpphdr), min(node->len-sizeof(struct mpphdr), size));

	mppsk->node_to_send = node;
	return 0;
}

int get_control_msg(struct msghdr *msg, size_t size) {
	struct iovec data;
	struct msg_node * node = NULL;

	node = msg_queue_pop(&control_msg_queue);
	if (!node)
		return -1;
	
	data = iov_iter_iovec(&msg->msg_iter);

	copy_to_user(data.iov_base, &node->data, min(sizeof(node->data), size));
	kfree(node);

	return 0;
}

int mpp_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct mpp_sock * mppsk = cast_to_mpp_sock(sock->sk);
	if (unlikely(!iter_is_iovec(&msg->msg_iter))) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_recvmsg: msg is not an iovec\n");
		return -2;
	}
	if (unlikely(mppsk->handler_type < 0 || mppsk->handler_type >= handler_id_size))
		return -3;

	if (likely(mppsk->handler_type)) 
		return common_rcv(mppsk, msg, size);
	
	return get_control_msg(msg, size);
}

struct proto_ops mpp_proto_ops = {
	.family		= PF_MPP,
	.owner		= THIS_MODULE,
	.release	= mpp_sock_release,
	.sendmsg	= mpp_sock_sendmsg,
	.recvmsg	= mpp_sock_recvmsg,
};

static struct proto mpp_prot = {
	.name		= "MPP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct mpp_sock),
};

int mpp_sock_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk = NULL;
	struct mpp_sock * mppsk;
	struct msg_node * node = NULL;

	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_create: start\n");

	if (protocol < 0 || protocol >= handler_id_size)
		goto err_out;

	if (!net_eq(net, &init_net))
		goto err_out;

	if (likely(protocol != 0)) {
		node = kmalloc(sizeof(struct msg_node), GFP_KERNEL);
		if (!node) {
			printk(KERN_DEBUG "mpp_kernel: mpp_sock_create: sk don't allocated");
			goto err_out;
		}
	}

	sk = sk_alloc(net, PF_MPP, GFP_KERNEL, &mpp_prot, kern);
	if (!sk) {
		printk(KERN_DEBUG "mpp_kernel: mpp_sock_create: sk don't allocated");
		goto err_out;
	}

	atomic_inc(&handlers_storage[protocol].cnt);

	sock->state = SS_UNCONNECTED;
	sock->ops = &mpp_proto_ops;
	sock->type = 2;
	sock_init_data(sock, sk);
	sk->sk_protocol = IPPROTO_MPP;
	mppsk = (struct mpp_sock *)inet_sk(sk);
	mppsk->handler_type = protocol;
	// printk(KERN_DEBUG "mpp_kernel: mpp_sock_create: ok\n\n");
	return 0;
err_out:
	if (node)
		kfree(node);
	if (sk)
		sock_put(sk);
	return -1;
}

static const struct net_proto_family mpp_proto_family = {
	.family		= PF_MPP,
	.create		= mpp_sock_create,
	.owner		= THIS_MODULE,
};

int mpp_rcv(struct sk_buff *skb) {
	struct mpphdr * hdr;
	struct states * st;
	// printk(KERN_DEBUG "mpp_kernel: mpp_rcv: data received!\n");
	while(skb) {
		struct sk_buff * next = skb->next;
		// printk("%d\n", skb->len);
		if (unlikely(
				skb->len < sizeof(struct mpphdr) || 
				skb->len != ntohl(((struct mpphdr *)skb->data)->total_len)
				)
			) {
				printk(KERN_DEBUG "mpp_kernel: mpp_rcv: wtf\n");
				mpphdr_dump((struct mpphdr *)skb->data);
				kfree_skb(skb);
				skb = next;
			}

		hdr = (struct mpphdr *)skb->data;
		st = find_state_record(ntohl(hdr->prog_id), ntohs(hdr->state));
		if (likely(st))
			st->handler(skb, st);
		else {
			printk(KERN_DEBUG "mpp_kernel: mpp_rcv: unknown program with (prog_id, state) = (%d, %d)\n", ntohl(hdr->prog_id), ntohs(hdr->state));
			mpphdr_dump(hdr);
			kfree_skb(skb);
		}
		skb = next;
	}
	// printk(KERN_DEBUG "mpp_kernel: mpp_rcv: ok\n\n");
	return 0;
}

int mpp_err(struct sk_buff *skb, u32 info) {
	printk(KERN_DEBUG "mpp_kernel: mpp_err: Oops! Error info = %u\n\n", info);
	return 0;
}

static struct net_protocol mpp_protocol = {
	.handler		= mpp_rcv,
	.err_handler	= mpp_err,
	.no_policy		= 1,
	.netns_ok		= 1,
};

static struct inet_protosw inet_protosw_mpp = {
	.type		= 2,
	.protocol	= IPPROTO_MPP,
	.prot		= &mpp_prot,
	.ops		= &mpp_proto_ops,
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

struct states * make_state(int num, int i, int handler_type) {
	struct states * tmp = kmalloc(sizeof(struct states), GFP_KERNEL);
	if (!tmp) return NULL;
	tmp->next = NULL;
	tmp->state = i;
	tmp->handler = default_handler;
	tmp->next_dev = num;
	tmp->handler_type = handler_type;
	return tmp;
}

int fill_the_path(void) {
	struct states * sptr = NULL;
	int const sz = 2;
	int const sts[] = {0, 1};
	int const handlers_types[] = {3, 4};
	int i = 0;

	handlers_head = make_prog();
	if (!handlers_head) {
		printk(KERN_DEBUG "mpp_kernel: init: wtf1\n");
		return -1;
	}
	handlers_head->state = make_state(sts[0], 0, handlers_types[i]);
	sptr = handlers_head->state;
	for (i = 1; i < sz; ++i) {
		sptr->next = make_state(sts[i], i, handlers_types[i]);
		if (!sptr->next) {
			printk(KERN_DEBUG "mpp_kernel: init: wtf2\n");
			return -1;
		}
		sptr = sptr->next;
	}
	return 0;
}

static int __init mpp_kernel_init(void) {
	int err;
	int i;
	printk(KERN_DEBUG "mpp_kernel: init: start\n");

	err = fill_the_path();
	if (err) return err;

	err = sock_register(&mpp_proto_family);
	printk(KERN_DEBUG "mpp_kernel: init: return value of sock_register is %d\n", err);
	if (err) {
		sock_unregister(PF_MPP);
		err = sock_register(&mpp_proto_family);
		printk(KERN_DEBUG "mpp_kernel: init: return value of sock_register (attemption 2) is %d\n", err);
		if (err)
			return err;
	}	
	err = proto_register(&mpp_prot, 1);
	printk(KERN_DEBUG "mpp_kernel: init: return value of proto_register is %d\n", err);
	if (err) return err;

	err = inet_add_protocol(&mpp_protocol, IPPROTO_MPP);
	printk(KERN_DEBUG "mpp_kernel: init: return value of inet_add_protocol is %d\n", err);
	if (err) return err;

	inet_register_protosw(&inet_protosw_mpp);

	ip_make_skb_mpp = kallsyms_lookup_name("ip_make_skb");
	ip_send_skb_mpp = kallsyms_lookup_name("ip_send_skb");

	for (i = 0; i < handler_id_size; ++i)
		handler_data_init(&handlers_storage[i]);

	msg_queue_init(&control_msg_queue);
	
	printk(KERN_DEBUG "mpp_kernel: init: ok\n\n");
	return 0;
}

static void __exit mpp_kernel_exit(void) {
	int err;
	struct states * sptr = NULL;
	int i;
	printk(KERN_DEBUG "mpp_kernel: exit: start\n");
	
	inet_unregister_protosw(&inet_protosw_mpp);

	err = inet_del_protocol(&mpp_protocol, IPPROTO_MPP);
	printk(KERN_DEBUG "mpp_kernel: init: return value of inet_del_protocol is %d\n", err);
	
	proto_unregister(&mpp_prot);
	sock_unregister(PF_MPP);
	
	if (handlers_head) {
		sptr = handlers_head->state;
		kfree(handlers_head);
	}
	while(sptr){
		struct states * next = sptr->next;
		kfree(sptr);
		sptr = next;
	}

	for (i = 0; i < handler_id_size; ++i)
		handler_data_destroy(&handlers_storage[i]);

	msg_queue_destroy(&control_msg_queue);
	
	printk(KERN_DEBUG "mpp_kernel: exit: ok\n\n");
}

module_init(mpp_kernel_init);
module_exit(mpp_kernel_exit);

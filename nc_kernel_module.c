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
#include "nc_queues.h"

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
//	.ips = {2130706433u, 2130706433u, 2130706433u},
//	.ips = {3232235625u, 3232235625u, 3232235625u},
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
	hd->cnt = 0;
	tasks_queue_init(&hd->q);
}

void handler_data_destroy(struct handler_data * hd) {
	tasks_queue_destroy(&hd->q);
}

void nchdr_dump(struct nchdr *nch) {
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: type = %u\n", nch->type);
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: code = %u\n", nch->code);
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: loop_cnt = %u\n", ntohs(nch->loop_cnt));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: prog_id = %u\n", ntohl(nch->prog_id));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: state = %u\n", ntohs(nch->state));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: flags = %u\n", ntohs(nch->flags));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: id = %lu\n", ntohl(nch->id));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: total_len = %u\n", ntohl(nch->total_len));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: csum = %lu\n", ntohl(nch->csum));
	printk(KERN_DEBUG "nc_kernel: nchdr_dump: last_cpoint_id = %u\n", ntohl(nch->last_cpoint_id));
}

void wake_up_handler(int handler_type) {
	struct msg_node * node;
	node = kmalloc(sizeof(struct msg_node), GFP_KERNEL);
	if (!node) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_create: msg_node don't allocated");
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
		printk(KERN_WARNING "nc_kernel: default_handler: incorrect handler type: \n", st->handler_type);
		nchdr_dump(nc_hdr(skb));
		kfree_skb(skb);
	}
	tasks_queue_push(&handlers_storage[st->handler_type].q, skb);
	if (!handlers_storage[st->handler_type].cnt)
		wake_up_handler(st->handler_type);
}
//==============================================

inline struct nc_sock * cast_to_nc_sock(struct sock * sk) {
	return (struct nc_sock *)inet_sk(sk);
}

int nc_sock_release(struct socket *sock) {
	struct sock *sk = sock->sk;
	struct nc_sock *ncsk = cast_to_nc_sock(sk);
	int handler_type;
	// printk(KERN_DEBUG "nc_kernel: nc_sock_release: start\n");
	
	if (!sk) 
		goto out;
	
	lock_sock(sk);
	handler_type = cast_to_nc_sock(sk)->handler_type;
	if (ncsk->node_to_send)
		kfree_skb(ncsk->node_to_send);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	release_sock(sk);
	sock_put(sk);
	if (unlikely(handler_type < 0 || handler_type >= handler_id_size)) {
		printk(KERN_ERR "nc_kernel: nc_sock_release: taint was detected! Socket was released with protocol = %\n", handler_type);
		goto out;
	}
	
	--handlers_storage[handler_type].cnt;
	if (!handlers_storage[handler_type].cnt && handlers_storage[handler_type].q.head) 
		wake_up_handler(handler_type);
	// printk(KERN_DEBUG "nc_kernel: nc_sock_release: ok\n\n");
out:
	return 0;
}

struct sk_buff * node_to_send = NULL;

void set_hdrs(struct sk_buff *skb, size_t size, char const * str_with_hdr) {
	struct nchdr *nch = nc_hdr(skb);
	__u64 random_number;
	// printk(KERN_DEBUG "nc_kernel: set_hdrs: start\n");
	if (str_with_hdr) {
		memcpy(nch, str_with_hdr, sizeof(struct nchdr));
		nch->state = htons(ntohs(nch->state)+1);
	} else {
		// printk(KERN_DEBUG "nc_kernel: set_hdrs: new prog\n");
		get_random_bytes_arch(&random_number, sizeof(random_number));
		skb->ip_summed = CHECKSUM_NONE;
		nch->total_len = htonl(sizeof(struct nchdr) + size);
		nch->id = htonl(random_number);
		nch->state = htons(1);
		nch->prog_id = htonl(1);

		nch->type = 0;
		nch->code = 0;
		nch->csum = 0;
		nch->flags = 0;
		nch->loop_cnt = 0;
		nch->last_cpoint_id = 0;
	}
	// nchdr_dump(nch);
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
	// printk(KERN_DEBUG "nc_kernel: nc_send: start\n");
	
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
	// printk(KERN_DEBUG "nc_kernel: nc_send: PTR_ERR = %d\n", err);

	set_hdrs(skb, size, str_with_hdr);

	if (!IS_ERR_OR_NULL(skb)) {
		err = ip_send_skb_nc(sock_net(sk), skb);
		// printk(KERN_DEBUG "nc_kernel: nc_send: return value of ip_send_skb is %d\n", err);
	}
	if (likely(rt))
		ip_rt_put(rt);
	// printk(KERN_DEBUG "nc_kernel: nc_send: ok\n");
	return 0;
}

int nc_sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	struct inet_sock *inet = inet_sk(sock->sk);
	struct iovec data;
	struct nchdr * nch;
	struct states * st;
	int cur_state = 0;
	char const * str = NULL;
	struct nc_sock * ncsk = cast_to_nc_sock(sock->sk);
	// printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: start\n");

	if (size < 1) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: msg too small\n");
		goto out;
	}

	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: msg is not an iovec\n");
		goto out;
	}

	data = iov_iter_iovec(&msg->msg_iter);
	
	if (ncsk->node_to_send) {
		nch = (struct nchdr *)ncsk->node_to_send->data;
		cur_state = ntohs(nch->state);
		str = ncsk->node_to_send->data;
	}
	st = find_state_record(1, cur_state);
	if (!st) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: the end of the path was reached\n");
		goto out;
	}
	inet->inet_daddr = htonl(idip.ips[st->next_dev]);
	nc_send(sock, msg, size, str);

out:
	if (ncsk->node_to_send) {
		kfree_skb(ncsk->node_to_send);
		ncsk->node_to_send = NULL;
	}
	// printk(KERN_DEBUG "nc_kernel: nc_sock_sendmsg: ok\n\n");
	return 0;	
}

int common_rcv(struct nc_sock * ncsk, struct msghdr *msg, size_t size) {
	struct iovec data;
	struct sk_buff * node = NULL;

	node = tasks_queue_pop(&handlers_storage[ncsk->handler_type].q);
	if (!node)
		return -1;
	
	data = iov_iter_iovec(&msg->msg_iter);

	copy_to_user(data.iov_base, node->data+sizeof(struct nchdr), min(node->len-sizeof(struct nchdr), size));

	ncsk->node_to_send = node;
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

int nc_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct nc_sock * ncsk = cast_to_nc_sock(sock->sk);
	if (unlikely(!iter_is_iovec(&msg->msg_iter))) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_recvmsg: msg is not an iovec\n");
		return -2;
	}
	if (unlikely(ncsk->handler_type < 0 || ncsk->handler_type >= handler_id_size))
		return -3;

	if (likely(ncsk->handler_type)) 
		return common_rcv(ncsk, msg, size);
	
	return get_control_msg(msg, size);
}

struct proto_ops nc_proto_ops = {
	.family		= PF_NC,
	.owner		= THIS_MODULE,
	.release	= nc_sock_release,
	.sendmsg	= nc_sock_sendmsg,
	.recvmsg	= nc_sock_recvmsg,
};

static struct proto nc_prot = {
	.name		= "NC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct nc_sock),
};

int nc_sock_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk = NULL;
	struct nc_sock * ncsk;
	struct msg_node * node = NULL;

	// printk(KERN_DEBUG "nc_kernel: nc_sock_create: start\n");

	if (protocol < 0 || protocol >= handler_id_size)
		goto err_out;

	if (!net_eq(net, &init_net))
		goto err_out;

	if (likely(protocol != 0)) {
		node = kmalloc(sizeof(struct msg_node), GFP_KERNEL);
		if (!node) {
			printk(KERN_DEBUG "nc_kernel: nc_sock_create: sk don't allocated");
			goto err_out;
		}
	}

	sk = sk_alloc(net, PF_NC, GFP_KERNEL, &nc_prot, kern);
	if (!sk) {
		printk(KERN_DEBUG "nc_kernel: nc_sock_create: sk don't allocated");
		goto err_out;
	}

	++handlers_storage[protocol].cnt;

	sock->state = SS_UNCONNECTED;
	sock->ops = &nc_proto_ops;
	sock->type = 2;
	sock_init_data(sock, sk);
	sk->sk_protocol = IPPROTO_NC;
	ncsk = (struct nc_sock *)inet_sk(sk);
	ncsk->handler_type = protocol;
	// printk(KERN_DEBUG "nc_kernel: nc_sock_create: ok\n\n");
	return 0;
err_out:
	if (node)
		kfree(node);
	if (sk)
		sock_put(sk);
	return -1;
}

static const struct net_proto_family nc_proto_family = {
	.family		= PF_NC,
	.create		= nc_sock_create,
	.owner		= THIS_MODULE,
};

int nc_rcv(struct sk_buff *skb) {
	struct nchdr * hdr;
	struct states * st;
	// printk(KERN_DEBUG "nc_kernel: nc_rcv: data received!\n\n");
	while(skb) {
		struct sk_buff * next = skb->next;
		if (unlikely(
				skb->len < sizeof(struct nchdr) || 
				skb->len != ntohl(((struct nchdr *)skb->data)->total_len)
				)
			) return 0;

		// printk(KERN_DEBUG "nc_kernel: nc_rcv: str = %s\n", skb->data+sizeof(struct nchdr));
		hdr = (struct nchdr *)skb->data;
		st = find_state_record(ntohl(hdr->prog_id), ntohs(hdr->state));
		if (likely(st))
			st->handler(skb, st);
		else {
			printk(KERN_DEBUG "nc_kernel: nc_rcv: unknown program with (prog_id, state) = (%lu, %lu)\n", ntohl(hdr->prog_id), ntohs(hdr->state));
			nchdr_dump(hdr);
			kfree_skb(skb);
		}
		skb = next;
	}
	// printk(KERN_DEBUG "nc_kernel: nc_rcv: ok\n\n");
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
	int const sz = 19;
	int const sts[] = {0, 2, 1, 1, 2, 0, 1, 2, 0, 1, 1, 0, 2, 0, 2, 2, 1, 0, 1};
	int const handlers_types[] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
	int i;

	handlers_head = make_prog();
	if (!handlers_head) {
		printk(KERN_DEBUG "nc_kernel: init: wtf1\n");
		return -1;
	}
	handlers_head->state = make_state(sts[0], 0, handlers_types[i]);
	sptr = handlers_head->state;
	for (i = 1; i < sz; ++i) {
		sptr->next = make_state(sts[i], i, handlers_types[i]);
		if (!sptr->next) {
			printk(KERN_DEBUG "nc_kernel: init: wtf2\n");
			return -1;
		}
		sptr = sptr->next;
	}
	return 0;
}

static int __init nc_kernel_init(void) {
	int err;
	int i;
	printk(KERN_DEBUG "nc_kernel: init: start\n");

	err = fill_the_path();
	if (err) return err;

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

	for (i = 0; i < handler_id_size; ++i)
		handler_data_init(&handlers_storage[i]);

	msg_queue_init(&control_msg_queue);
	
	printk(KERN_DEBUG "nc_kernel: init: ok\n\n");
	return 0;
}

static void __exit nc_kernel_exit(void) {
	int err;
	struct states * sptr = NULL;
	int i;
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

	for (i = 0; i < handler_id_size; ++i)
		handler_data_destroy(&handlers_storage[i]);

	msg_queue_destroy(&control_msg_queue);
	
	printk(KERN_DEBUG "nc_kernel: exit: ok\n\n");
}

module_init(nc_kernel_init);
module_exit(nc_kernel_exit);
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uncerso");
MODULE_DESCRIPTION("NC kernel");
MODULE_VERSION("1");

#define NC_PROTO_FAMILY 41

int nc_sock_release(struct socket *sock) {
	struct sock *sk = sock->sk;
	printk(KERN_INFO "nc_kernel: nc_sock_release: start\n");
	
	if (!sk) {
		printk(KERN_INFO "nc_kernel: nc_sock_release: sk is nullptr\n");
		return 0;
	}
	lock_sock(sk);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	release_sock(sk);
	sock_put(sk);
	printk(KERN_INFO "nc_kernel: nc_sock_release: ok\n\n");
	return 0;
}

char * last_str;
size_t last_str_size;

int nc_sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	void * kdata;
	struct iovec data;
	printk(KERN_INFO "nc_kernel: nc_sock_sendmsg: start\n");

	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_INFO "nc_kernel: nc_sock_sendmsg: msg is not an iovec\n");
		return 0;
	}
	
	data = iov_iter_iovec(&msg->msg_iter);
	kdata = kmalloc(data.iov_len * sizeof(char), GFP_KERNEL);
	if (!kdata) {
		printk(KERN_INFO "nc_kernel: nc_sock_sendmsg: kdata = 0\n");
		return 0;
	}
	copy_from_user(kdata, data.iov_base, data.iov_len);
	printk(KERN_INFO "nc_kernel: nc_sock_sendmsg: size = %lu, msg = %s\n", size, (char*)kdata);
	swap(last_str, kdata);
	last_str_size = data.iov_len;
	if (kdata)
		kfree(kdata);
	printk(KERN_INFO "nc_kernel: nc_sock_sendmsg: ok\n\n");
	return 0;	
}

int nc_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct iovec data;
	printk(KERN_INFO "nc_kernel: nc_sock_recvmsg: start\n");
	if (!iter_is_iovec(&msg->msg_iter)) {
		printk(KERN_INFO "nc_kernel: nc_sock_recvmsg: msg is not an iovec\n");
		return 0;
	}
	data = iov_iter_iovec(&msg->msg_iter);
	printk(KERN_INFO "nc_kernel: nc_sock_recvmsg: size = %lu, buf_len = %lu\n", size, data.iov_len);
	
	copy_to_user(data.iov_base, last_str, min(last_str_size, data.iov_len-1));

	printk(KERN_INFO "nc_kernel: nc_sock_recvmsg: ok\n\n");
	return 0;
}

struct proto_ops nc_kernel_proto_ops = {
	.family		= NC_PROTO_FAMILY,
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
	.name		   = "NC",
	.owner		   = THIS_MODULE,
	.obj_size   = sizeof(struct nc_sock),
};

int nc_sock_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk;

	printk(KERN_INFO "nc_kernel: nc_sock_create: start\n");

	if (!net_eq(net, &init_net)) {
		printk(KERN_INFO "nc_kernel: nc_sock_create: Not eq!\n");
		return -1;
	}

	sk = sk_alloc(net, NC_PROTO_FAMILY, GFP_KERNEL, &nc_prot, kern);
	if (!sk) {
		printk(KERN_INFO "ERROR sk don't allocated");
		return -1;
	}

	sock_init_data(sock, sk);
	sock->state = SS_UNCONNECTED;
	sock->ops = &nc_kernel_proto_ops;
	sock->type = 2;

	printk(KERN_INFO "nc_kernel: nc_sock_create: ok\n\n");
	return 0;
}

static const struct net_proto_family nc_proto_family = {
	.family		= NC_PROTO_FAMILY,
	.create		= nc_sock_create,
	.owner		= THIS_MODULE,
};

static int __init nc_kernel_init(void) {
	int err;
	char init_str[] = "init_str";
	printk(KERN_INFO "nc_kernel: init: start\n");

	err = sock_register(&nc_proto_family);
	printk(KERN_INFO "nc_kernel: init: return value of sock_register is %d\n", err);
	if (err) return err;
	
	err = proto_register(&nc_prot, 1);
	printk(KERN_INFO "nc_kernel: init: return value of proto_register is %d\n", err);
	if (err) return err;

	last_str_size = sizeof(init_str);
	last_str = kmalloc(last_str_size, GFP_KERNEL);
	memcpy(last_str, init_str, last_str_size);

	printk(KERN_INFO "nc_kernel: init: ok\n\n");
	return 0;
}

static void __exit nc_kernel_exit(void) {
	printk(KERN_INFO "nc_kernel: exit: start\n");
	sock_unregister(NC_PROTO_FAMILY);
	proto_unregister(&nc_prot);
	if (last_str)
		kfree(last_str);
	printk(KERN_INFO "nc_kernel: exit: ok\n\n");
}

module_init(nc_kernel_init);
module_exit(nc_kernel_exit);
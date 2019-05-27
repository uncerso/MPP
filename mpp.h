#ifndef __mpp_kernel_module__
#define __mpp_kernel_module__
#include "mpp_queues.h"

struct mpphdr {
	__u8	type;
	__u8	code;
	__be16	loop_cnt;
	__be32	prog_id;
	__be16	state;
	__be16	flags;
	__be64	id;
//	__be32	seq_num;
//	__be32	ack_num;
	__be32	total_len;
//	__be64	security_info;
//	__be64	data_storage_info;
//	__be32	debug_server;
	__be32	csum;
	__be32	last_cpoint_id;
};

struct states {
	struct states * next;
	__u16	state;
	__u16	next_dev;
	__u32	handler_type;
	void	(*handler)(struct sk_buff * skb, struct states * st);
};

struct handlers {
	struct handlers * next;
	__u32	prog_id;
	struct states * state;
};

struct id_ip {
	__u32 ips[3];
};

struct handler_data {
	struct tasks_queue q;
	atomic_t cnt;
};

struct mpp_sock {
	//inet_sock should be first
	struct inet_sock   inet;
	int handler_type;
	struct sk_buff * node_to_send;
};

#endif
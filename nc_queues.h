#ifndef __nc_queues__
#define __nc_queues__
#include <linux/mutex.h>
#include <linux/wait.h>

#define CAT(X, Y) X##_##Y
// #define CAT(X, Y) Y

#define DEFINE_QUEUE(queue_pref, node_type)	\
struct CAT(queue_pref, queue) {				\
	struct node_type * head;				\
	struct node_type * back;				\
	struct mutex lock;						\
	struct wait_queue_head read_wait;		\
};

#define DECLARE_QUEUE_FUNCS(queue_pref, node_type) \
void CAT(queue_pref, queue_init)(struct CAT(queue_pref, queue) * q);	\
void CAT(queue_pref, queue_destroy)(struct CAT(queue_pref, queue) * q);		\
void CAT(queue_pref, queue_push)(struct CAT(queue_pref, queue) * q,			\
								 struct node_type * new_skb);				\
struct node_type * CAT(queue_pref, queue_pop)(struct CAT(queue_pref, queue) * q);


DEFINE_QUEUE(tasks, sk_buff)
DECLARE_QUEUE_FUNCS(tasks, sk_buff)

struct msg_type {
	int code;
	int value;
};

struct msg_node {
	struct msg_node * next;
	struct msg_type data;
};

DEFINE_QUEUE(msg, msg_node)
DECLARE_QUEUE_FUNCS(msg, msg_node)

#endif
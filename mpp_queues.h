#ifndef __mpp_queues__
#define __mpp_queues__
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/timer.h>

#include "mpp.h"

#define CAT(X, Y) X##_##Y
// #define CAT(X, Y) Y

#define DEFINE_QUEUE(queue_pref, node_type)	\
struct CAT(queue_pref, queue) {				\
	struct node_type * head;				\
	struct node_type * back;				\
	struct mutex lock;						\
	struct wait_queue_head read_wait;		\
};

#define DECLARE_BASE_QUEUE_FUNCS(queue_pref, node_type) 				\
void CAT(queue_pref, queue_init)(struct CAT(queue_pref, queue) * q);	\
void CAT(queue_pref, queue_destroy)(struct CAT(queue_pref, queue) * q);	\
void CAT(queue_pref, queue_push)(struct CAT(queue_pref, queue) * q,		\
								 struct node_type * new_node);				

#define DECLARE_QUEUE_FUNCS(queue_pref, node_type)	\
DECLARE_BASE_QUEUE_FUNCS(queue_pref, node_type)		\
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


struct req_node {
	struct req_node * next;
	struct req_node * prev;
	struct sk_buff * skb;
	struct timer_list timer;
	size_t id;
};

void req_node_free(struct req_node * node);

DEFINE_QUEUE(req, req_node)
DECLARE_BASE_QUEUE_FUNCS(req, req_node)

struct ack_node {
	struct ack_node * next;
	struct ack_node * prev;
	struct timer_list timer;
	struct mpphdr hdr;
};

void ack_node_free(struct ack_node * node);

DEFINE_QUEUE(ack, ack_node)
DECLARE_BASE_QUEUE_FUNCS(ack, ack_node)

#endif
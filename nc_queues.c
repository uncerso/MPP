#include "nc_queues.h"

#include <linux/skbuff.h>

#define DEFINE_QUEUE_INIT(queue_pref)									\
void CAT(queue_pref, queue_init)(struct CAT(queue_pref, queue) * q) {	\
	q->head = NULL;														\
	q->back = NULL;														\
																		\
	mutex_init(&q->lock);												\
	init_waitqueue_head(&q->read_wait);									\
}																		\
EXPORT_SYMBOL(CAT(queue_pref, queue_init));

#define DEFINE_QUEUE_DESTROY(queue_pref, free_func)						\
void CAT(queue_pref, queue_destroy)(struct CAT(queue_pref, queue) * q) {\
	mutex_lock(&q->lock);												\
																		\
	while(q->head) {													\
		q->back = q->head->next;										\
		free_func(q->head);												\
		q->head = q->back;												\
	}																	\
																		\
	mutex_unlock(&q->lock);												\
	mutex_destroy(&q->lock);											\
}																		\
EXPORT_SYMBOL(CAT(queue_pref, queue_destroy));

#define DEFINE_QUEUE_PUSH(queue_pref, node_type)						\
void CAT(queue_pref, queue_push)(struct CAT(queue_pref, queue) * q,		\
								 struct node_type * new_skb) {			\
	new_skb->next = NULL;												\
																		\
	mutex_lock(&q->lock);												\
	if (q->back)														\
		q->back->next = new_skb;										\
	else																\
		q->head = new_skb;												\
																		\
	q->back = new_skb;													\
																		\
	wake_up_interruptible(&q->read_wait);								\
	mutex_unlock(&q->lock);												\
}																		\
EXPORT_SYMBOL(CAT(queue_pref, queue_push));

#define DEFINE_LOCKER(queue_pref)										\
bool CAT(queue_pref, try_lock_if_not_empty)(struct CAT(queue_pref, queue) * q) { \
	mutex_lock_interruptible(&q->lock);												\
																		\
	if (q->head)														\
		return 1;														\
																		\
	mutex_unlock(&q->lock);												\
	return 0;															\
}


#define QUEUE_POP_LAST_PART(queue_pref, node_type)						\
	/*	printk(KERN_DEBUG "nc_kernel: queue_pop: interrupt\n");*/		\
		return NULL;													\
	}																	\
																		\
	if (!q->head) {														\
		mutex_unlock(&q->lock);											\
		return NULL;													\
	}																	\
																		\
	node = q->head;														\
	q->head = q->head->next;											\
	if (!q->head)														\
		q->back = NULL;													\
																		\
	mutex_unlock(&q->lock);												\
																		\
	node->next = NULL;													\
	return node;														\
}																		\
EXPORT_SYMBOL(CAT(queue_pref, queue_pop));

#define DEFINE_QUEUE_POP1(queue_pref, node_type)						\
struct node_type * CAT(queue_pref, queue_pop)(struct CAT(queue_pref, queue) * q) { \
	struct node_type * node = NULL;										\
																		\
	if (wait_event_interruptible(q->read_wait,							\
								 CAT(queue_pref, try_lock_if_not_empty)(q))) { \
QUEUE_POP_LAST_PART(queue_pref, node_type)

#define DEFINE_QUEUE_POP2(queue_pref, node_type, timeout)				\
struct node_type * CAT(queue_pref, queue_pop)(struct CAT(queue_pref, queue) * q) { \
	struct node_type * node = NULL;										\
																		\
	if (wait_event_interruptible_timeout(q->read_wait,					\
										 CAT(queue_pref, try_lock_if_not_empty)(q),\
										 timeout) <= 0) {				\
QUEUE_POP_LAST_PART(queue_pref, node_type)


#define DEFINE_QUEUE_FUNCS(queue_pref, node_type, free_func)\
DEFINE_QUEUE_INIT(queue_pref)								\
DEFINE_QUEUE_DESTROY(queue_pref, free_func)					\
DEFINE_QUEUE_PUSH(queue_pref, node_type)					\
DEFINE_LOCKER(queue_pref)									\
DEFINE_QUEUE_POP1(queue_pref, node_type)

#define DEFINE_QUEUE_FUNCS_TIMEOUT(queue_pref, node_type, free_func, timeout) \
DEFINE_QUEUE_INIT(queue_pref)								\
DEFINE_QUEUE_DESTROY(queue_pref, free_func)					\
DEFINE_QUEUE_PUSH(queue_pref, node_type)					\
DEFINE_LOCKER(queue_pref)									\
DEFINE_QUEUE_POP2(queue_pref, node_type, timeout)



// DEFINE_QUEUE_FUNCS(tasks, sk_buff, kfree_skb)
DEFINE_QUEUE_FUNCS_TIMEOUT(tasks, sk_buff, kfree_skb, 500);
DEFINE_QUEUE_FUNCS(msg, msg_node, kfree)
#include "mpp_send_ack.h"
#include <linux/time.h>

struct req_queue glob_req_queue;
struct ack_queue glob_ack_queue;

#define NONBLOCK_POP(q, vert) {				\
	if (vert) {								\
		if (vert->prev)						\
			vert->prev->next = vert->next;	\
		if (vert->next)						\
			vert->next->prev = vert->prev;	\
		if ((q)->head == vert)				\
			(q)->head = vert->next;			\
		if ((q)->back == vert)				\
			(q)->back = vert->prev;			\
	}										\
}

struct req_node * find_and_pop_req_id(struct req_queue * q, size_t id) {
	struct req_node * ans = NULL;
	mutex_lock(&q->lock);
	
	ans = q->head;
	while (ans) {
		if (ans->id == id)
			break;
		ans = ans->next;
	}

	NONBLOCK_POP(&glob_req_queue, ans);

	mutex_unlock(&q->lock);
	return ans;
}
EXPORT_SYMBOL(find_and_pop_req_id);

int __always_inline cmphdr(struct mpphdr * hdr1, struct mpphdr * hdr2) {
	return  hdr1->id 		== hdr2->id 		&&
			hdr1->prog_id	== hdr2->prog_id	&&
			hdr1->state		== hdr2->state		&& 
			hdr1->loop_cnt	== hdr2->loop_cnt;
}

struct req_node * find_and_pop_req_hdr(struct req_queue * q, struct mpphdr * hdr) {
	struct req_node * ans = NULL;
	mutex_lock(&q->lock);
	
	ans = q->head;
	while (ans) {
		if (cmphdr((struct mpphdr *)ans->skb->data, hdr))
			break;
		ans = ans->next;
	}
	
	NONBLOCK_POP(&glob_req_queue, ans);

	mutex_unlock(&q->lock);
	return ans;
}
EXPORT_SYMBOL(find_and_pop_req_hdr);

struct ack_node * find_and_pop_ack_hdr(struct ack_queue * q, struct mpphdr * hdr) {
	struct ack_node * ans = NULL;
	mutex_lock(&q->lock);
	
	ans = q->head;
	while (ans) {
		if (cmphdr(&ans->hdr, hdr))
			break;
		ans = ans->next;
	}
	
	NONBLOCK_POP(&glob_ack_queue, ans);

	mutex_unlock(&q->lock);
	return ans;
}
EXPORT_SYMBOL(find_and_pop_ack_hdr);

void req_timer_callback(struct timer_list * t) {
	struct req_node * node = NULL;
	
	mutex_lock(&glob_req_queue.lock);

	node = from_timer(node, t, timer);
	printk(KERN_DEBUG "mpp: req_timer_callback: %x\n", node);
	if (!node) return;
	NONBLOCK_POP(&glob_req_queue, node)
	printk(KERN_DEBUG "mpp: req_timer_callback: id = %d\n", node->id);
	printk(KERN_DEBUG "mpp: req_timer_callback: skb = %x\n", node->skb);

	mutex_unlock(&glob_req_queue.lock);

	req_node_free(node);
}

void ack_timer_callback(struct timer_list * t) {
	
}

atomic_t req_node_cnt = ATOMIC_INIT(0);
struct req_node * make_req_node(struct sk_buff * skb) {
	struct req_node * ans = kmalloc(sizeof(struct req_node), GFP_KERNEL);
	if (!ans)
		return ans;
	ans->skb = skb;
	timer_setup(&ans->timer, req_timer_callback, 0);
	ans->id = atomic_inc_return(&req_node_cnt);
	return ans;
}
EXPORT_SYMBOL(make_req_node);

void req_node_free(struct req_node * node) {
	del_timer_sync(&node->timer);
	if (likely(node->skb)) kfree_skb(node->skb);
	kfree(node);
}
EXPORT_SYMBOL(req_node_free);

struct ack_node * make_ack_node(void) {
	return kmalloc(sizeof(struct ack_node), GFP_KERNEL);
}
EXPORT_SYMBOL(make_ack_node);

void ack_node_free(struct ack_node * node) {
	kfree(node);
}
EXPORT_SYMBOL(ack_node_free);

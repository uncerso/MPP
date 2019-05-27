#ifndef __mpp_send_ack__
#define __mpp_send_ack__

#include "mpp_queues.h"

struct req_node * find_and_pop_req_id(struct req_queue * q, size_t id);
struct req_node * find_and_pop_req_hdr(struct req_queue * q, struct mpphdr * hdr);

struct ack_node * find_and_pop_ack_hdr(struct ack_queue * q, struct mpphdr * hdr);

void req_node_free(struct req_node * node);
void ack_node_free(struct ack_node * node);
struct req_node * make_req_node(struct sk_buff * skb);
struct ack_node * make_ack_node(void);

#endif
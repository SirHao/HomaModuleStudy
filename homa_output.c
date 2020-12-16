/* This file contains functions related to the sender side of message
 * transmission. */

#include "homa_impl.h"

/**
 * homa_message_out_init() - 初始化一个homa_message_out, 将user space 的数据copy到sk_buffer
 * @hmo:       需要初始化的HomaMessageOut; current contents are assumed to be garbage.
 * @sk:        发送数据需要的socket sk
 * @id:        crpc的ID
 * @direction: 来自客户端还是服务端；FROM_CLIENT or FROM_SERVER.
 * @msg:       用户空间的msg结构体
 * @len:       msg数据长度
 * @dst:       rt获取到的dst
 * 
 * Return:   0 :success;     a negative: errno value.
 */
int homa_message_out_init(struct homa_message_out *hmo, struct sock *sk,
		struct rpc_id id, __u8 direction, struct msghdr *msg,
		size_t len, struct dst_entry *dst)
{
	int bytes_left;
	struct sk_buff *skb;
	int err;
	
	hmo->length = len;                                      //初始化hmo的总长度为 msglen
	__skb_queue_head_init(&hmo->packets);                   //头结点初始化函数
	hmo->unscheduled_bytes = 7*HOMA_MAX_DATA_PER_PACKET;    //unscheduled_bytes初始化为7个数据包
	hmo->limit = hmo->unscheduled_bytes;                    //limit这个版本目前就是unscheduled_bytes
	hmo->priority = 0;                                      //优先级暂时设置为 0 
	
	//将msg中的data拷贝到socket buffer
	if (likely(len <= HOMA_MAX_DATA_PER_PACKET)) {  //当只用放在一个skb中
		struct full_message_header *h;                      //初始化一个full message类型的package
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);         //alloc_skb一个skb出来
		if (unlikely(!skb)) {
			return -ENOMEM;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);                 //skb_reserve头部空间用来给ipv4和以太网用
		skb_reset_transport_header(skb);                    //skb->transport_header = skb->data - skb->head     
		h = (struct full_message_header *) skb_put(skb, sizeof(*h)); //把传输层的头部full_message_header put进去
		h->common.rpc_id = id;                              //一系列的full_message_header初始化
		h->common.type = FULL_MESSAGE;
		h->common.direction = direction;
		h->message_length = htons(hmo->length);             //hmo->length刚被赋予成了msg总长度
		err = skb_add_data_nocache(sk, skb, &msg->msg_iter, //还是熟悉的skb_add_data_nocache直接把值给拷贝了
				hmo->length);
		if (err != 0) {
			return err;
		}
		skb_dst_set(skb, dst);                              //还是熟悉的设置路由
		__skb_queue_tail(&hmo->packets, skb);               //将这个skb放到homa message out这个结构的package队列尾部
	} else if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
		return -EINVAL;                                     //超过大小返回错误
	} else for (bytes_left = len; bytes_left > 0;
			bytes_left -= HOMA_MAX_DATA_PER_PACKET) {       //否则只是循环上述单个的动作而已，并没有因为unschedual影响
		struct message_frag_header *h;
		__u32 cur_size = HOMA_MAX_DATA_PER_PACKET;
		if (unlikely(cur_size > bytes_left)) {
			cur_size = bytes_left;
		}
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
		if (unlikely(!skb)) {
			return -ENOMEM;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);
		skb_reset_transport_header(skb);
		h = (struct message_frag_header *) skb_put(skb, sizeof(*h));
		h->common.rpc_id = id;
		h->common.type = MESSAGE_FRAG;
		h->common.direction = direction;
		h->message_length = htons(hmo->length);
		h->offset = hmo->length - bytes_left;
		h->unscheduled_bytes = hmo->unscheduled_bytes;
		h->retransmit = 0;
		err = skb_add_data_nocache(sk, skb, &msg->msg_iter, cur_size);
		if (unlikely(err != 0)) {
			return err;
		}
		skb_dst_set(skb, dst);
		__skb_queue_tail(&hmo->packets, skb);
	}
	return 0;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @hmo:       Structure to clean up.
 * @hsk:       Associated socket.
 */
void homa_message_out_destroy(struct homa_message_out *hmo)
{
	struct sk_buff *skb;
	skb_queue_walk(&hmo->packets, skb) {
		kfree_skb(skb);
	}
}
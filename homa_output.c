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
int homa_message_out_init(struct homa_message_out *msgout, struct sock *sk,
                          struct msghdr *msg, size_t len, struct homa_addr *dest,
                          __u16 sport, __u64 id)
{
    int bytes_left;
    struct sk_buff *skb;
    int err;
    struct sk_buff **last_link = &msgout->packets;
	
	msgout->length = len;                                        //初始化hmo的总长度为 msglen
    msgout->packets = NULL;                                      //头结点初始化函数
    msgout->next_packet = NULL;
    msgout->next_offset = 0;
    msgout->unscheduled = 7*HOMA_MAX_DATA_PER_PACKET;      //unscheduled_bytes初始化为7个数据包
    msgout->limit = msgout->unscheduled;                      //limit这个版本目前就是unscheduled_bytes
	msgout->priority = 0;                                        //优先级暂时设置为 0


    //将msg中的data拷贝到socket buffer
    if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
        return -EINVAL;
    }
    for (bytes_left = len, last_link = &msgout->packets; bytes_left > 0; bytes_left -= HOMA_MAX_DATA_PER_PACKET) {
        struct data_header *h;
        __u32 cur_size = HOMA_MAX_DATA_PER_PACKET;
        if (likely(cur_size > bytes_left)) {
            cur_size = bytes_left;
        }
        skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
        if (unlikely(!skb)) {
            return -ENOMEM;
        }
        skb_reserve(skb, HOMA_SKB_RESERVE);
        skb_reset_transport_header(skb);
        h = (struct data_header *) skb_put(skb, sizeof(*h));
        h->common.sport = htons(sport);
        h->common.dport = htons(dest->dport);
        h->common.id = id;
        h->common.type = DATA;
        h->message_length = htonl(msgout->length);
        h->offset = htonl(msgout->length - bytes_left);
        h->unscheduled = htonl(msgout->unscheduled);
        h->retransmit = 0;
        err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
                                   cur_size);
        if (unlikely(err != 0)) {
            return err;
        }
        dst_hold(dest->dst);
        skb_dst_set(skb, dest->dst);
        *last_link = skb;
        last_link = homa_next_skb(skb);
        *last_link = NULL;
    }
    //要发送的next_packet指向最开始
    msgout->next_packet = msgout->packets;
    return 0;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @hmo:       Structure to clean up.
 * @hsk:       Associated socket.
 */
void homa_message_out_destroy(struct homa_message_out *msgout)
{
    struct sk_buff *skb, *next;
    for (skb = msgout->packets; skb != NULL; skb = next) {
        next = *homa_next_skb(skb);
        kfree_skb(skb);
    }
}

void homa_xmit_packets(struct homa_message_out *msgout, struct sock *sk,
                       struct homa_addr *dest)
{
    while ((msgout->next_offset < msgout->limit) && msgout->next_packet) {
        int err;
        skb_get(msgout->next_packet);
        err = ip_queue_xmit(sk, msgout->next_packet, &dest->flow);
        if (err) {
            printk(KERN_WARNING "ip_queue_xmit failed in homa_xmit_packets: %d", err);
        }else{

        }
        msgout->next_packet = *homa_next_skb(msgout->next_packet);
        msgout->next_offset += HOMA_MAX_DATA_PER_PACKET;
    }
}
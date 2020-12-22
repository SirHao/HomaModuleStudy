/* This file contains functions that handle incoming Homa packets. */

#include "homa_impl.h"

//将一个package加入到整个message_in中，如果这个包没有被加入hmi，那么将会被加入并释放
void homa_add_packet(struct homa_message_in *msgin, struct sk_buff *skb)
{
    struct data_header *h = (struct data_header *) skb->data;
    int offset = ntohl(h->offset);
    int ceiling = msgin->total_length;
    int floor = 0;
    struct sk_buff *skb2;

    //在现有数据包列表中找出要插入新数据包的位置。
    //它不一定要排在最后，但实际上几乎总是会这样，因此请从列表的末尾开始reverse_walk。
    skb_queue_reverse_walk(&msgin->packets, skb2) {
        struct data_header *h2 = (struct data_header *) skb2->data;
        int offset2 = ntohl(h2->offset);
        if (offset2 < offset) {
            floor = offset2 + HOMA_MAX_DATA_PER_PACKET;
            break;
        }
        ceiling = offset2;
    }
    //             <---------------------
    // |     offset2|     floor|     ceiling|

    //新数据包紧接在skb2之后（可能引用标头）。
    //数据包不应在字节范围内重叠，但是下面的代码假定它们可能重叠，因此它将计算新数据包贡献了多少个不重叠的字节。
    if (unlikely(floor < offset)) {
        floor = offset;
    }
    if (ceiling > offset + HOMA_MAX_DATA_PER_PACKET) {
        ceiling = offset + HOMA_MAX_DATA_PER_PACKET;
    }
    //这里就有重复的包的情况，丢弃
    if (floor >= ceiling) {
        /* This packet is redundant. */
        char buffer[100];
        printk(KERN_NOTICE "redundant Homa packet: %s\n", homa_print_header(skb, buffer, sizeof(buffer)));
        kfree_skb(skb);
        return;
    }
    __skb_insert(skb, skb2, skb2->next, &msgin->packets);
    msgin->bytes_remaining -= (ceiling - floor);
}

//对于incoming 的pkg,初始或者找到srpc，按照offset插入hmi中的packages
void homa_data_from_client(struct homa *homa, struct sk_buff *skb,
                           struct homa_sock *hsk, struct homa_server_rpc *srpc)
{
    struct data_header *h = (struct data_header *) skb->data;
    //如果刚才没找到srpc，那么初始化一个，并放入hsk->server_rpcs
    if (!srpc) {
        srpc = (struct homa_server_rpc *) kmalloc(sizeof(*srpc),
                                                  GFP_KERNEL);
        srpc->saddr = ip_hdr(skb)->saddr;
        srpc->sport = ntohs(h->common.sport);
        srpc->id = h->common.id;                       //用client的rpc来分配，所以找rpc的时候需要三个都吻合
        homa_message_in_init(&srpc->request, ntohl(h->message_length),
                             ntohl(h->unscheduled));
        srpc->state = INCOMING;
        list_add(&srpc->server_rpc_links, &hsk->server_rpcs);
    } else if (unlikely(srpc->state != INCOMING)) {
        kfree_skb(skb);
        return;
    }
    homa_add_packet(&srpc->request, skb);
    if (srpc->request.bytes_remaining == 0) {
        struct sock *sk = (struct sock *) hsk;
        printk(KERN_NOTICE "[homa handler] Incoming RPC is READY\n");
        srpc->state = READY;
        list_add(&srpc->ready_links, &hsk->ready_server_rpcs);
        sk->sk_data_ready(sk);
    }else{
        printk(KERN_NOTICE "[homa handler] Incoming RPC is til not READY;remaining:%d \n",srpc->request.bytes_remaining);
    }
}

//将ready的homa socket msg拷贝到user space
int homa_message_in_copy_data(struct homa_message_in *msgin, struct msghdr *msg, int max_bytes)
{
    struct sk_buff *skb;
    int offset;
    int err;
    int remaining = max_bytes;

    //即使数据包具有重叠范围，也请执行正确的操作；基本不回发生
    offset = 0;
    skb_queue_walk(&msgin->packets, skb) {
        struct data_header *h = (struct data_header *) skb->data;
        int this_offset = ntohl(h->offset);
        int this_size = msgin->total_length - offset;
        if (this_size > HOMA_MAX_DATA_PER_PACKET) {
            this_size = HOMA_MAX_DATA_PER_PACKET;
        }
        if (offset > this_offset) {
            this_size -= (offset - this_offset);
        }
        if (this_size > remaining) {
            this_size =  remaining;
        }
        //拷贝函数的精髓所在
        err = skb_copy_datagram_msg(skb, sizeof(*h) + (offset - this_offset), msg, this_size);
        if (err) {
            return err;
        }
        remaining -= this_size;
        offset += this_size;
        if (remaining == 0) {
            break;
        }else if (remaining < 0) {
            printk(KERN_NOTICE "[homa handler] copy err:remaining < 0\n");
            break;
        }
    }
    return max_bytes - remaining;
}

//Destructor for homa_message_in.
void homa_message_in_destroy(struct homa_message_in *msgin)
{
    struct sk_buff *skb, *next;
    skb_queue_walk_safe(&msgin->packets, skb, next) {
        kfree_skb(skb);
    }
}

//Constructor for homa_message_in.
void homa_message_in_init(struct homa_message_in *msgin, int length,
                          int unscheduled)
{
    __skb_queue_head_init(&msgin->packets);
    msgin->total_length = length;
    msgin->bytes_remaining = length;
    msgin->granted = unscheduled;
    msgin->priority = 0;
}
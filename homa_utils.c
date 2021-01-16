/* This file contains miscellaneous utility functions for the Homa protocol. */

#include "homa_impl.h"
//=======================init======================
//初始化homa_addr:就是一堆以前的代码抽出来，给sk添加路由，并记录在homa_address上
int homa_addr_init(struct homa_addr *addr, struct sock *sk, __be32 saddr,
                   __u16 sport, __be32 daddr, __u16 dport)
{
    struct rtable *rt;

    addr->daddr = daddr;
    addr->dport = dport;
    addr->dst = NULL;
    flowi4_init_output(&addr->flow.u.ip4, sk->sk_bound_dev_if, sk->sk_mark,
                       inet_sk(sk)->tos, RT_SCOPE_UNIVERSE, sk->sk_protocol,
                       0, daddr, saddr, htons(dport), htons(sport),
                       sk->sk_uid);
    security_sk_classify_flow(sk, &addr->flow);
    rt = ip_route_output_flow(sock_net(sk), &addr->flow.u.ip4, sk);
    if (IS_ERR(rt)) {
        return PTR_ERR(rt);
    }
    addr->dst = &rt->dst;
    return 0;
}

//=======================iterate find===============
//用来从homa全局变量中用port遍历找到一个homa socket
struct homa_sock *homa_find_socket(struct homa *homa, __u16 port) {
    struct list_head *pos;
    list_for_each(pos, &homa->sockets) {
        struct homa_sock *hsk = list_entry(pos, struct homa_sock, socket_links);
        if ((hsk->client_port == port) || (hsk->server_port == port)) {
            return hsk;
        }
    }
    return NULL;
}
//用来根据id source_rpc-addr&port找到server rpc
struct homa_server_rpc *homa_find_server_rpc(struct homa_sock *hsk, __be32 saddr, __u16 sport, __u64 id)
{
    struct list_head *pos;
    list_for_each(pos, &hsk->server_rpcs) {
        struct homa_server_rpc *srpc = list_entry(pos, struct homa_server_rpc, server_rpc_links);
        if ((srpc->id == id) &&
            (srpc->client.dport == sport) &&
            (srpc->client.daddr == saddr)) {
            return srpc;
        }
    }
    return NULL;
}
// use id to find a home_client_rpc in this sock
struct homa_client_rpc *homa_find_client_rpc(struct homa_sock *hsk,__u16 sport, __u64 id){
    struct list_head *pos;
    list_for_each(pos, &hsk->client_rpcs) {
        struct homa_client_rpc *crpc = list_entry(pos, struct homa_client_rpc, client_rpc_links);
        if (crpc->id == id) {
            return crpc;
        }
    }
    return NULL;
}


//=======================print debug===============
//返回homa的type string
char *homa_symbol_for_type(uint8_t type)
{
	static char buffer[20];
	switch (type) {
	case DATA:
		return "DATA";
	case GRANT:
		return "GRANT";
	case RESEND:
		return "RESEND";
	case BUSY:
		return "BUSY";
	}
	
	/* Using a static buffer can produce garbled text under concurrency,
	 * but (a) it's unlikely (this code only executes if the opcode is
	 * bogus), (b) this is mostly for testing and debugging, and (c) the
	 * code below ensures that the string cannot run past the end of the
	 * buffer, so the code is safe. */
	snprintf(buffer, sizeof(buffer)-1, "UNKNOWN(%u)", type);
	buffer[sizeof(buffer)-1] = 0;
	return buffer;
}
//打印homa的header信息
char *homa_print_header(struct sk_buff *skb, char *buffer, int length)
{
    char *pos = buffer;
    int space_left = length;
    struct common_header *common = (struct common_header *) skb->data;

    int result = snprintf(pos, space_left, "%s from %pI4:%u, id %llu",
                          homa_symbol_for_type(common->type), &ip_hdr(skb)->saddr,
                          ntohs(common->sport), common->id);
    if ((result == length) || (result < 0)) {
        buffer[length-1] = 0;
        return buffer;
    }
    pos += result;
    space_left -= result;
    switch (common->type) {
        case DATA: {
            struct data_header *h = (struct data_header *)
                    skb->data;
            snprintf(pos, space_left,
                     ", message_length %d, offset %d, unscheduled %d%s",
                     ntohl(h->message_length), ntohl(h->offset),
                     ntohl(h->unscheduled),
                     h->retransmit ? " RETRANSMIT" : "");
            break;
        }
        case GRANT: {
            struct grant_header *h = (struct grant_header *) skb->data;
            snprintf(pos, space_left, ", offset %d, priority %u",
                     ntohl(h->offset), h->priority);
            break;
        }
        case RESEND: {
            struct resend_header *h = (struct resend_header *) skb->data;
            snprintf(pos, space_left,
                     ", offset %d, length %d, priority %u%s",
                     ntohl(h->offset), ntohl(h->length),
                     h->priority, h->restart ? ", RESTART" : "");
            break;
        }
        case BUSY:
            /* Nothing to add here. */
            break;
    }
    buffer[length-1] = 0;
    return buffer;
}



//=======================del release===============
//释放homa client rpc
void homa_client_rpc_destroy(struct homa_client_rpc *crpc) {
    homa_addr_destroy(&crpc->dest);
    __list_del_entry(&crpc->client_rpc_links);
    homa_message_out_destroy(&crpc->request);
}
//释放homa server rpc
void homa_server_rpc_destroy(struct homa_server_rpc *srpc) {
    homa_addr_destroy(&srpc->client);
    homa_message_in_destroy(&srpc->request); //close会先释放client rpc，会不会那会已经把client rpc释放掉了
    if (srpc->state == SRPC_RESPONSE)
        homa_message_out_destroy(&srpc->response);
    list_del(&srpc->server_rpc_links);
    if (srpc->state == SRPC_READY)
        __list_del_entry(&srpc->ready_links);
    kfree(srpc);

}
//释放homa_addr的dst
void homa_addr_destroy(struct homa_addr *addr)
{
    dst_release(addr->dst);
}
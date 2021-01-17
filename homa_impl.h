#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
typedef unsigned __poll_t;

#include "homa.h"

//一个包包含的最大数据量(不包含Homa's header, IP header等）；这假设以太网分组帧。
#define HOMA_MAX_DATA_PER_PACKET 1400
//最大的 IP header (V4) size
#define HOMA_MAX_IPV4_HEADER 60
//最大的 homa header size
#define HOMA_MAX_HEADER 40
//限制包总大小
_Static_assert(1500 >= (HOMA_MAX_DATA_PER_PACKET + HOMA_MAX_IPV4_HEADER + HOMA_MAX_HEADER), "Message length constants overflow Etheret frame");
//定义在sk_buffs为Homa之外的header（IPV4+以太网VLAN）保留多少空间。
#define HOMA_SKB_RESERVE (HOMA_MAX_IPV4_HEADER + 20)
// all Homa packet buffers的总大小 "sizeof(void*)" 用来指向homa_next_skb
#define HOMA_SKB_SIZE (HOMA_MAX_DATA_PER_PACKET + HOMA_MAX_HEADER + HOMA_SKB_RESERVE + sizeof(void*))


//===================结构体，变量================
extern struct homa homa;
//[homa_sock] 一个open状态的homa socket的基本信息
struct homa_sock
{
    struct inet_sock inet; //结构的第一部分由通用套接字数据组成inet_sock这必须是第一个字段
    //inet后所有内容都是Homa的specific information
    __u16 server_port;      //接收incoming RPC requests,必须显示bind的port；0 意味着没有绑定；
    __u16 client_port;      //发送outgoing RPC requests使用的port
    __u64 next_outgoing_id; //下一个outgoing RPC requests需要分配的 rpc_id

    struct list_head socket_links;       //用来链接到&homa.sockets
    struct list_head client_rpcs;        //发出这个socket上活跃的rpc list
    struct list_head server_rpcs;        //发往这个socket上活跃的rpc list
    struct list_head ready_server_rpcs;  //state=ready的server rpc
    struct list_head ready_client_rpcs;  //state=ready的client rpc
};

//[homa] - 有关Homa协议实施的Overall information;除单元测试外，一次通常全局唯一
struct homa
{
    __u16 next_client_port;   //使用它作为下一个Homa套接字的client port； 单调递增。
                              // 当前值可能在分配给服务器的范围内； 使用前必须检查。 该端口可能已经在使用中； 必须检查。
    struct list_head sockets; //homa socket list
};


//================header struct========================
//homa_packet_type 枚举 :每种的header都不同
enum homa_packet_type {
    DATA               = 20,
    GRANT              = 21,
    RESEND             = 22,
    BUSY               = 23,
    BOGUS              = 24, /*  unit tests 中使用 */
    /* If you add a new type here, you must also do the following:
     * 1. Change BOGUS so it is the highest opcode
     * 2. Add support for the new opcode in op_symbol and header_to_string
     */
};
//[common_header] 每种Homa packet通用header
struct common_header
{
    __be16 sport;   //source port
    __be16 dport;   //target port
    __be64 id;      //uniq  rpc_id
    __u8 type;      //package type
} __attribute__((packed));// __attribute__((packed))  :使用该属性可以使得变量或者结构体成员使用最小的对齐方式，即对变量是一字节对齐，对域（field）是位对齐
static const __u8 FROM_CLIENT = 1;
static const __u8 FROM_SERVER = 2;

//[data_header] - DATA数据包 （原full_header/frag_header）
// 其中包含来自req/resp msg的连续范围的字节。 数据包中的data size=min(msg,HOMA_MAX_DATA_PER_PACKET)
struct data_header {
    struct common_header common;
    __be32 message_length;    //msg 总长
    __be32 offset;            //这个包中first byte 的offset
    __be32 unscheduled;       //可发送unscheduled byte大小
    __u8 retransmit;          //1表示这是个resend
    //这个header后面就是data
} __attribute__((packed));
_Static_assert(sizeof(struct data_header) <= HOMA_MAX_HEADER,
               "data_header too large");

//[grant_header] 由receiver发送回sender，以指示sender可以在消息中传输其他字节。
struct grant_header
{
    struct common_header common;

    __be32 offset; //sender应该尽快传输data,直到该偏移量为止（但不包括）。
    __u8 priority; //发送方应将此优先级用于此消息的所有将来的MESSAGE_FRAG数据包，直到收到具有较高偏移量的GRANT。 数字越大表示优先级越高。
} __attribute__((packed));
_Static_assert(sizeof(struct grant_header) <= HOMA_MAX_HEADER,
               "grant_header too large");

//[resend_header] 当接收方认为消息数据可能已在传输中丢失时（或者如果担心发送方可能已崩溃），则发送RESEND。 接收者应该重新发送消息的指定部分，即使它先前已经发送过。
struct resend_header
{
    struct common_header common;

    __be32 offset; //resend 开始的offset
    __be32 length; //resend 的总长度
    __u8 priority; //resend 的优先级，发送者应该使用此优先级发送所有请求的数据，除非存在RESTART标志（在这种情况下，该字段将被忽略，sender以unschedule的优先级resend）。
    __u8 restart;  //1 表示服务器不知道此请求，因此client应重置其状态并从头开始重新启动消息。
} __attribute__((packed));
_Static_assert(sizeof(struct resend_header) <= HOMA_MAX_HEADER,
               "resend_header too large");

//[busy_header] 这些数据包告诉receicer发送者仍然alive（即使它没有发送接收者期望的数据）。
struct busy_header
{
    struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct busy_header) <= HOMA_MAX_HEADER,
               "busy_header too large");

//=============socket relative  struct===========
// [homa_addr] rpcid取消，只在rpc放一个u64 id，而将一个rpc的所有peer信息放在这个结构体
struct homa_addr {
    __be32 daddr;               //目的ip
    __u16 dport;                //目的port
    struct flowi flow;          //发送package 的flow信息
    struct dst_entry *dst;      //用于路由的信息，开始应该持有，最终应该释放
};

//[homa_message_out] 描述这个host发出的所有msg,无论req/resp
struct homa_message_out
{
    int length;                //除去header总message size
    struct sk_buff *packets;      //一个simple link,通过homa_next_skb获取下一个sk，这些数据已经打包到sk_buffs中并可以进行传输。
                                 //该列表按消息中的偏移量顺序排列（首先偏移量为0）；
                                 //每个数据包（最后一个数据包除外）均包含有效负载的HOMA_MAX_DATA_PER_PACKET。 注意：我们这里不使用锁

    struct sk_buff *next_packet; //指向request里面下一个要发送的packet;在此之前的所有数据包都已发送。 NULL表示整个消息已发送。
    int next_offset;            //下一个要发送的packet第一个字节在总msg中的offset
    int unscheduled;            //发送的消息的unscheduled初始字节。
    int limit;                  //当offests大于这个数量,发送前需要grant
    __u8 priority;              //后面发送的包的优先级
};
//[homa_message_in] 描述这个host收到的所有msg,无论req/resp
struct homa_message_in {
    struct sk_buff_head packets;//到目前为止已收到此消息的数据包。该列表按偏移量顺序排序（head是最低偏移量），但是数据包可能会乱序接收，因此列表中有时可能会出现漏洞。
    int total_length;           //整个消息的总长度
    int bytes_remaining;        //还没有收到的消息长度,将与priority挂钩
    int granted;                //sender所有grant bytes
    int priority;               //优先级
};

//[homa_client_rpc] 对于从此计算机启动的每个活动RPC，都存在这个结构之一。
struct homa_client_rpc
{
    __u64  id;                          //唯一id
    struct list_head client_rpc_links;  //用来将这个homa_client_rpc连接到&homa_sock.client_rpcs.
    struct homa_addr dest;              //rpc peer的地址信息：ip/port/路由信息等
    struct homa_message_out request;    //message request信息
    struct homa_message_in response;    //message response信息
    enum {
        CRPC_WAITING            = 11,   //没收到response (request may or may not be completely sent).
        CRPC_INCOMING           = 12,   //部分收到了response
        CRPC_READY              = 13    //完全收到response 但并没有被上层read from the socket.
    } state;
    struct list_head ready_links;       //state == READY，与&homa_sock.ready_client_rpcs关联
};
//[homa_server_rpc] 这台计算机作为server角度的所有rpc
struct homa_server_rpc {
    struct homa_addr client;            //client的rpc addr信息
    __u64 id;                           //id(unique from saddr/sport).
    struct homa_message_in request;     //req msg的info
    struct homa_message_out response;   //resp msg的info

    //server rpc状态
    enum {
        SRPC_INCOMING           = 5, //部分接收
        SRPC_READY              = 6, //request 是完整的 但没有通过socket被read
        SRPC_IN_SERVICE         = 7, //request 被read了但是response还没返回
        SRPC_RESPONSE           = 8  //reponse都返回了
    } state;

    struct list_head server_rpc_links;   //用这个存放在&homa_sock.server_rpcs.
    struct list_head ready_links;        //用这个存放在&homa_sock.ready_server_rpcs
};
//=================inline=============
static inline struct homa_sock *homa_sk(const struct sock *sk)
{
    return (struct homa_sock *)sk;
}
static inline struct sk_buff **homa_next_skb(struct sk_buff *skb)
{
    return (struct sk_buff **) (skb->head + HOMA_MAX_DATA_PER_PACKET+ HOMA_MAX_HEADER + HOMA_SKB_RESERVE);
}
//======================================

extern void   homa_addr_destroy(struct homa_addr *addr);
extern int    homa_addr_init(struct homa_addr *addr, struct sock *sk,
                             __be32 saddr, __u16 sport, __be32 daddr, __u16 dport);
extern int    homa_bind(struct socket *sk, struct sockaddr *addr, int addr_len);
extern void   homa_client_rpc_free(struct homa_client_rpc *crpc);
extern struct homa_client_rpc *homa_client_rpc_new(struct homa_sock *hsk,
                                                   struct sockaddr_in *dest, size_t length,
                                                   struct iov_iter *iter, int *err);
extern void   homa_close(struct sock *sock, long timeout);
extern void   homa_data_from_client(struct homa *homa, struct sk_buff *skb,
                                    struct homa_sock *hsk, struct homa_server_rpc *srpc);
extern void   homa_data_from_server(struct homa *homa, struct sk_buff *skb,
                                    struct homa_sock *hsk, struct homa_client_rpc *crpc);
extern int    homa_diag_destroy(struct sock *sk, int err);
extern int    homa_disconnect(struct sock *sk, int flags);
extern int   homa_err_handler(struct sk_buff *skb, u32 info);
extern struct homa_client_rpc *homa_find_client_rpc(struct homa_sock *hsk,
                                                    __u16 sport, __u64 id);
extern struct homa_server_rpc *homa_find_server_rpc(struct homa_sock *hsk,
                                                    __be32 saddr, __u16 sport, __u64 id);
extern struct homa_sock *
homa_find_socket(struct homa *homa, __u16 port);
extern int    homa_get_port(struct sock *sk, unsigned short snum);
extern int    homa_getsockopt(struct sock *sk, int level, int optname,
                              char __user *optval, int __user *option);
extern int    homa_handler(struct sk_buff *skb);
extern int    homa_hash(struct sock *sk);
extern int    homa_ioc_recv(struct sock *sk, unsigned long arg);
extern int    homa_ioc_reply(struct sock *sk, unsigned long arg);
extern int    homa_ioc_send(struct sock *sk, unsigned long arg);
extern int    homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern int    homa_message_in_copy_data(struct homa_message_in *hmi,
                                        struct iov_iter *iter, int max_bytes);
extern void   homa_message_in_destroy(struct homa_message_in *hmi);
extern void   homa_message_in_init(struct homa_message_in *hmi, int length,
                                   int unscheduled);
extern void   homa_message_out_destroy(struct homa_message_out *hmo);
extern int    homa_message_out_init(struct homa_message_out *hmo,
                                    struct sock *sk, struct iov_iter *iter, size_t len,
                                    struct homa_addr *dest, __u16 sport, __u64 id);
extern __poll_t
homa_poll(struct file *file, struct socket *sock,
          struct poll_table_struct *wait);
extern char  *homa_print_header(struct sk_buff *skb, char *buffer, int length);
extern int    homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
                           int noblock, int flags, int *addr_len);
extern void   homa_rehash(struct sock *sk);
extern int    homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int    homa_sendpage(struct sock *sk, struct page *page, int offset,
                            size_t size, int flags);
extern void   homa_server_rpc_free(struct homa_server_rpc *srpc);
extern struct homa_server_rpc *homa_server_rpc_new(struct homa_sock *hsk,
                                                   __be32 source, struct data_header *h, int *err);
extern int    homa_setsockopt(struct sock *sk, int level, int optname,
                              char __user *optval, unsigned int optlen);
extern int    homa_sock_init(struct sock *sk);
extern char  *homa_symbol_for_type(uint8_t type);
extern void   homa_unhash(struct sock *sk);
extern int    homa_v4_early_demux(struct sk_buff *skb);
extern int    homa_v4_early_demux_handler(struct sk_buff *skb);
extern int    homa_wait_ready_msg(struct sock *sk, long *timeo);
extern void   homa_xmit_packets(struct homa_message_out *hmo, struct sock *sk,
                                struct homa_addr *dest);
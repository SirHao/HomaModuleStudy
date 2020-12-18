#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
typedef unsigned __poll_t;

// IP协议空间内的Homa协议号
#define IPPROTO_HOMA 140
// 最大消息长度——不知道怎么定的
#define HOMA_MAX_MESSAGE_LENGTH 1000000

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
    __u32 client_port;      //outgoing RPC requests使用的port
    __u64 next_outgoing_id; //下一个outgoing RPC requests需要分配的 rpc_id
    __u32 server_port;      //接受incomming RPC requests的port.必须显示bind; 0 意味着没有绑定；

    struct list_head socket_links; //用来链接到&homa.sockets
    struct list_head client_rpcs;  //这个socket上活跃的rpc list
};

//[homa] - 有关Homa协议实施的Overall information;除单元测试外，一次通常全局唯一
struct homa
{
    __u32 next_client_port;   //使用它作为下一个Homa套接字的client port； 单调递增。
    struct list_head sockets; //homa socket list
};

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

//[rpc_id]  RPC的唯一标识符（在client）。
//任何给定的瞬间处于活动状态的给定客户端的所有RPC中都必须是唯一的（包括在网络中浮动的延迟数据包）。 server添加client的network address以生成全局唯一标识符
struct rpc_id
{
    __u32 port;            /** @port: 发出RPC的＆homa_socket.client_port。*/
    __u64 sequence;        /** @sequence: 从@socket区分RPC。 */
} __attribute__((packed)); // __attribute__((packed))  :使用该属性可以使得变量或者结构体成员使用最小的对齐方式，即对变量是一字节对齐，对域（field）是位对齐

//[common_header] 每种Homa packet通用header
struct common_header
{
    struct rpc_id rpc_id;
    __u8 type;      //homa_packet_type的枚举
    __u8 direction; //谁发送的包:FROM_CLIENT or FROM_SERVER.
} __attribute__((packed));
static const __u8 FROM_CLIENT = 1;
static const __u8 FROM_SERVER = 2;

//[full_message_header] 其中包含完整的请求或响应消息。
//这个header后面的packet包含整个request/response message.
struct full_message_header
{
    struct common_header common;
    __be16 message_length; //header后面数据的总bytes
} __attribute__((packed));
_Static_assert(sizeof(struct full_message_header) <= HOMA_MAX_HEADER,
               "full_message_header too large");

//[message_frag_header] 其中包含来自request/response message的连续bytes。
//这个header后面的packet是从所有数据offset开始发送的
struct message_frag_header
{
    struct common_header common;

    __be32 message_length; //message数据的总bytes
    __be32 offset;         //这个包在整个msg总长度的偏移量

    __be32 unscheduled_bytes; //发送方unscheduled数据大小；offset在此之后的bytes仅在响应GRANT数据包后发送。
    __u8 retransmit;          //1 意味着这是一个响应resend请求的重发包
} __attribute__((packed));
_Static_assert(sizeof(struct message_frag_header) <= HOMA_MAX_HEADER,
               "message_frag_header too large");

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

//[homa_message_out] 描述这个host发出的所有msg,无论req/resp
struct homa_message_out
{
    int length;                //除去header总message size
    struct sk_buff *packets;      //一个simple link,通过homa_next_skb获取下一个sk，这些数据已经打包到sk_buffs中并可以进行传输。
                                 //该列表按消息中的偏移量顺序排列（首先偏移量为0）；
                                 //每个数据包（最后一个数据包除外）均包含有效负载的HOMA_MAX_DATA_PER_PACKET。 注意：我们这里不使用锁

    struct sk_buff *next_packet; //指向request里面下一个要发送的packet;在此之前的所有数据包都已发送。 NULL表示整个消息已发送。
    int next_offset;         //下一个要发送的packet第一个字节在总msg中的offset
    int unscheduled_bytes; //发送的消息的unscheduled初始字节。
    int limit;             //当offests大于这个数量,发送前需要grant
    __u8 priority;           //后面发送的包的优先级
};

//[homa_client_rpc] 对于从此计算机启动的每个活动RPC，都存在这个结构之一。
struct homa_client_rpc
{
    struct rpc_id id;                   //唯一id
    struct flowi fl;                    //Addressing info
    struct dst_entry *dst;              //用来route的,我们持有一个ref，最终必须释放
    struct list_head client_rpcs_links; //用来将这个homa_client_rpc连接到&homa_sock.client_rpcs.
    struct homa_message_out request;    //message request信息
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
extern int    homa_bind(struct socket *sk, struct sockaddr *addr, int addr_len);
extern void   homa_client_rpc_destroy(struct homa_client_rpc *crpc);
extern void   homa_close(struct sock *sock, long timeout);
extern int    homa_diag_destroy(struct sock *sk, int err);
extern int    homa_disconnect(struct sock *sk, int flags);
extern void   homa_err_handler(struct sk_buff *skb, u32 info);
extern struct homa_sock *homa_find_socket(struct homa *homa, __u32 port);
extern int    homa_get_port(struct sock *sk, unsigned short snum);
extern int    homa_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *option);
extern int    homa_handler(struct sk_buff *skb);
extern int    homa_hash(struct sock *sk);
extern int    homa_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen);
extern int    homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void   homa_message_out_destroy(struct homa_message_out *hmo);
extern int    homa_message_out_init(struct homa_message_out *hmo,
                                    struct sock *sk, struct rpc_id id, __u8 direction,
                                    struct msghdr *msg, size_t len, struct dst_entry *dst);
extern __poll_t homa_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait);
extern char  *homa_print_header(char *packet, char *buffer, int length);
extern int    homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len);
extern void   homa_rehash(struct sock *sk);
extern int    homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int    homa_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags);
extern int    homa_sock_init(struct sock *sk);
extern char  *homa_symbol_for_type(uint8_t type);
extern void   homa_unhash(struct sock *sk);
extern int    homa_v4_early_demux(struct sk_buff *skb);
extern int    homa_v4_early_demux_handler(struct sk_buff *skb);
extern void   homa_xmit_packets(struct homa_message_out *hmo, struct sock *sk, struct flowi *fl);
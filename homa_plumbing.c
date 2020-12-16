#include "homa_impl.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Lucas");
MODULE_DESCRIPTION("Homa transport protocol");
MODULE_VERSION("0.01");

struct homa homa;

// 暂时没有用到，只是在proto homa_proto结构体中赋予变量使用
long sysctl_homa_mem[3] __read_mostly; //系统内存用的
int sysctl_homa_rmem_min
    __read_mostly; //最大接受数据包内存大小
int sysctl_homa_wmem_min
    __read_mostly;                   //最大发送数据包内存大小
atomic_long_t homa_memory_allocated; //已经分配内存

/* 
    proto_ops:该结构定义处理Homa套接字上各种操作的功能。 
    这些函数是相对通用的：它们被调用以实现top-level系统调用。 
    其中许多操作都可以复用独立于Homa协议的PF_INET功能实现。
 */
const struct proto_ops homa_proto_ops = {
    .family = PF_INET,
    .owner = THIS_MODULE,
    .release = inet_release,
    .bind = inet_bind,
    .connect = inet_dgram_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = inet_getname,
    .poll = homa_poll,
    .ioctl = inet_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = sock_common_setsockopt,
    .getsockopt = sock_common_getsockopt,
    .sendmsg = inet_sendmsg,
    .recvmsg = inet_recvmsg,
    .mmap = sock_no_mmap,
    .sendpage = sock_no_sendpage,
    .set_peek_off = sk_set_peek_off,
};

/*
    此结构也定义了处理Homa套接字上各种操作的函数。 
    但是，这些函数比homa_proto_ops中的函数低级：
        它们特定于PF_INET协议家族，并且在许多情况下，它们由homa_proto_ops中的函数调用。 
    这些功能大多数都有特定于Homa的实现。
  */
struct proto homa_prot = {
    .name = "HOMA",
    .owner = THIS_MODULE,
    .close = homa_close,
    .connect = ip4_datagram_connect,
    .disconnect = homa_disconnect,
    .ioctl = homa_ioctl,
    .init = homa_sock_init,
    .destroy = 0,
    .setsockopt = homa_setsockopt,
    .getsockopt = homa_getsockopt,
    .sendmsg = homa_sendmsg,
    .recvmsg = homa_recvmsg,
    .sendpage = homa_sendpage,
    .release_cb = ip4_datagram_release_cb,
    .hash = homa_hash,
    .unhash = homa_unhash,
    .rehash = homa_rehash,
    .get_port = homa_get_port,
    .memory_allocated = &homa_memory_allocated,
    .sysctl_mem = sysctl_homa_mem,
    .sysctl_wmem = &sysctl_homa_wmem_min,
    .sysctl_rmem = &sysctl_homa_rmem_min,
    .obj_size = sizeof(struct homa_sock),
    .diag_destroy = homa_diag_destroy,
};

/*homa协议的 Top-level structure*/
struct inet_protosw homa_protosw = {
    .type = SOCK_DGRAM,          //套接字类型，流套接字类型为SOCK_STREAM、数据报套接字类型为SOCK_DGRAM、原始套接字SOCK_RAW
    .protocol = IPPROTO_HOMA,    //绑定的140
    .prot = &homa_prot,          //low-level homa proto
    .ops = &homa_proto_ops,      //high0level homa proto
    .flags = INET_PROTOSW_REUSE, //端口可复用；其他flag:协议是否永久不可移除;是否是连接型
};

/* IP 用来 deliver incoming Homa packets to us. */
static struct net_protocol homa_protocol = {
    //early_demux用于提前查找skb数据包的监听sock和输入路由dst，提前分流。
    //由于其调用位于正常的路由和sock查找之前，称为early_demux，两个回调函数分别为：tcp_v4_early_demux和udp_v4_early_demux：
    .early_demux = homa_v4_early_demux,
    .early_demux_handler = homa_v4_early_demux_handler,
    //IP层被调用用来处理incomming homa_packet
    .handler = homa_handler,
    .err_handler = homa_err_handler,
    //暂时不知道下面两个是干啥的
    .no_policy = 1,
    .netns_ok = 1,
};

/**
 * homa_init(): invoked when this module is loaded into the Linux kernel
 * @return: 0 on success, otherwise a negative errno.
 */
static int __init homa_init(void)
{
    int status;
    printk(KERN_NOTICE "Homa module loading\n");
    //先注册low-level proto
    status = proto_register(&homa_prot, 1);
    if (status != 0) {
        printk(KERN_ERR "proto_register failed in homa_init: %d\n",status);
        goto out;
    }
    //注册top-level proto
    inet_register_protosw(&homa_protosw);
    //注册high-level
    status = inet_add_protocol(&homa_protocol, IPPROTO_HOMA);
    if (status != 0) {
        printk(KERN_ERR "inet_add_protocol failed in homa_init: %d\n", status);
        goto out_unregister;
    }
    
    homa.next_client_port = 0x10000; //初始化分配的下一个client port
	INIT_LIST_HEAD(&homa.sockets);   //homa socket list初始化

    return 0;

out_unregister:
    inet_unregister_protosw(&homa_protosw);
    proto_unregister(&homa_prot);
out:
    return status;
}

/**
 * homa_exit(): invoked when this module is unloaded from the Linux kernel.
 */
static void __exit

homa_exit(void)
{
    printk(KERN_NOTICE "Homa module unloading\n");
    //3-levels 协议注销
    inet_del_protocol(&homa_protocol, IPPROTO_HOMA);
    inet_unregister_protosw(&homa_protosw);
    proto_unregister(&homa_prot);
}

module_init(homa_init);
module_exit(homa_exit);

void homa_client_rpc_destroy(struct homa_client_rpc *crpc) {
    __list_del_entry(&crpc->client_rpcs_links);
    printk(KERN_NOTICE "[homa close]crpc  link del\n");
    homa_message_out_destroy(&crpc->request);
    printk(KERN_NOTICE "[homa close]crpc  hmo del\n");
}
//proto的一些需要自定义的接口
// homa_close()
//invoked when close system call is invoked on a Homa socket.
void homa_close(struct sock *sk, long timeout)
{
    struct homa_sock *hsk = homa_sk(sk);                        //获取到homa socket 结构体
	struct list_head *pos;
    printk(KERN_NOTICE "[homa close] begin del\n");
	
	list_del(&hsk->socket_links);                               //删除释放所有socket link
    printk(KERN_NOTICE "[homa close]socket_links del\n");
	list_for_each(pos, &hsk->client_rpcs) {        
		struct homa_client_rpc *crpc = list_entry(pos, struct homa_client_rpc, client_rpcs_links);     //释放所有的rpc
        printk(KERN_NOTICE "[homa close]crpc get\n");
		homa_client_rpc_destroy(crpc);
        printk(KERN_NOTICE "[homa close]crpc  free\n");
		kfree(crpc);
	}
    printk(KERN_NOTICE "[homa close]rpc del\n");
    sk_common_release(sk);                                      //整成正常sk_buffer
}


/**
 * homa_disconnect(): invoked when disconnect system call is invoked on a
 * Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_disconnect(struct sock *sk, int flags)
{
    printk(KERN_WARNING
           "unimplemented disconnect invoked on Homa socket\n");
    return -ENOSYS;
}

/**
 * homa_ioctl(): implements the ioctl system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
    printk(KERN_WARNING
           "unimplemented ioctl invoked on Homa socket\n");
    return -EINVAL;
}

/**
 * homa_init_sock(): invoked to initialize a new Homa socket.
 * @return: always 0 (success)
 */
int homa_sock_init(struct sock *sk)
{
    struct homa_sock *hsk = homa_sk(sk);
    hsk->client_port = homa.next_client_port;
    hsk->next_outgoing_id = 1;
    hsk->server_port = 0;
    homa.next_client_port++;
    list_add(&hsk->socket_links, &homa.sockets);
    INIT_LIST_HEAD(&hsk->client_rpcs);
    printk(KERN_NOTICE
           "Homa socket opened\n");
    return 0;
}

/**
 * homa_setsockopt(): implements the getsockopt system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_setsockopt(struct sock *sk, int level, int optname,char __user *optval, unsigned int optlen) {
    printk(KERN_WARNING
           "unimplemented setsockopt invoked on Homa socket:"
           " level %d, optname %d, optlen %d\n",
           level, optname, optlen);
    return -EINVAL;
}

/**
 * homa_getsockopt(): implements the getsockopt system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *option) {
    printk(KERN_WARNING "unimplemented getsockopt invoked on Homa socket:"
           " evel %d, optname %d\n", level, optname);
    return -EINVAL;
}

/**
 * homa_sendmsg(): send a message on a Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
    struct inet_sock *inet = inet_sk(sk);
    struct homa_sock *hsk = homa_sk(sk);
    __be32 saddr, daddr;
    __be16 dport, sport;
    //flowi在某种程度上类似于访问控制列表(ACL):它根据所选L3和L4头字段的值(如IP地址、L4端口号等)定义流量的聚合。例如，它被用作路由查找的搜索键。
    struct flowi4 fl4;
    struct rtable *rt = NULL;
    int err = 0;
    struct homa_client_rpc *crpc = NULL;

    DECLARE_SOCKADDR(
        struct sockaddr_in *, dest_in, msg->msg_name);
    if (msg->msg_namelen < sizeof(*dest_in))
        return -EINVAL;
    if (dest_in->sin_family != AF_INET) {
        return -EAFNOSUPPORT;
    }
    daddr = dest_in->sin_addr.s_addr;
    saddr = inet->inet_saddr;
    dport = 99;
    sport = 99;
    //慢速路径以生成路由结构。首先从调用flowi4_init_output构造描述此UDP流
    flowi4_init_output(&fl4,
                       sk->sk_bound_dev_if, //flowi4_oif
                       sk->sk_mark,         //flowi4_mark
                       inet->tos,           //flowi4_tos
                       RT_SCOPE_UNIVERSE,   //sflowi4_cope ://目的地的距离。“NOWHERE”是为不存在的目的地保留的;"HOST"是我们的本地地址;“LINK”是目的地，位于直接连接;“UNIVERSE”在宇宙中无处不在。
                       sk->sk_protocol,     //flowi4_proto
                       0,                   //flowi4_flags
                       daddr,
                       saddr,
                       dport,
                       inet->inet_sport,
                       sk->sk_uid);
    //将套接字及其流结构传递到安全子系统，以便SELinux或SMACK之类的系统可以在流结构上设置安全性id值。
    security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
    //ip_route_output_flow将调用IP路由代码以为此流生成路由结构
    rt = ip_route_output_flow(sock_net(sk), &fl4, sk);
    if (IS_ERR(rt))
    {
        err = PTR_ERR(rt);
        goto error;
    }
    //分配一个crpc size的内存给crpc
    crpc = (struct homa_client_rpc *) kmalloc(sizeof(*crpc), GFP_KERNEL);
	if (unlikely(!crpc)) {
		return -ENOMEM;
	}
    //给crpc分配id,并且homa_socket的next_outgoing_id自增
    crpc->id.sequence = hsk->next_outgoing_id;
    hsk->next_outgoing_id++;
    //将crpc加入hsk的client_rpcs list中
    list_add(&crpc->client_rpcs_links, &hsk->client_rpcs);

	err = homa_message_out_init(&crpc->request, sk, crpc->id, FROM_CLIENT, msg, len, &rt->dst);
        if (unlikely(err != 0)) {
		goto error;
	}
    printk(KERN_NOTICE "[send msg] rpcID:%llu ; msg len:%lu \n", crpc->id.sequence, len);
	return len;
    // //alloc_skb通过调用函数kmem_cache_alloc从缓存中获取sk_buff数据结构，并通过调用kmalloc获取数据缓冲区，
    // skb = alloc_skb(1500, GFP_KERNEL);
    // //GFP_KERNEL是linux内存分配器的标志，标识着内存分配器将要采取的行为。分配器标志分为行为修饰符，区修饰符及类型。行为修饰符表示内核应当如何分配所需的内存。区修饰符表示内存区应当从何处分配。类型就是行为修饰符和区修饰符的合体
    // /*#define GFP_KERNEL(__GFP_WAIT | __GFP_IO | __GFP_FS)
    //     __GFP_WAIT ： 缺内存页的时候可以睡眠;
    //     __GFP_IO ： 允许启动磁盘IO；
    //     __GFP_FS ： 允许启动文件系统IO。*/
    // if (!skb)
    // {
    //     printk(KERN_NOTICE
    //            "Couldn't allocate sk_buff\n");
    //     return -ENOMEM;
    // }

    // //也不知道干啥，先拿来预留着
    // skb_reserve(skb, 200);
    // err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
    //                            msg_data_left(msg));
    // if (err != 0)
    // {
    //     printk(KERN_NOTICE
    //            "Couldn't add data to sk_buff: %d\n",
    //            err);
    //     goto out;
    // }
    // //debug infomation
    // printk(KERN_NOTICE
    //        "protocol memory allocated %lu\n",
    //        atomic_long_read(homa_prot.memory_allocated));

    // //在skb中添加目的地
    // skb_dst_set(skb, &rt->dst);
    // err = ip_queue_xmit(sk, skb, flowi4_to_flowi(&fl4));

error:
	if (crpc) {
		homa_client_rpc_destroy(crpc);
	}
	return err;
}

/**
 * homa_recvmsg(): receive a message from a Homa socket.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
                 int noblock, int flags, int *addr_len)
{
    printk(KERN_WARNING
           "unimplemented recvmsg invoked on Homa socket\n");
    return -ENOSYS;
}

/**
 * homa_sendpage(): ??.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_sendpage(struct sock *sk, struct page *page, int offset,
                  size_t size, int flags)
{
    printk(KERN_WARNING
           "unimplemented sendpage invoked on Homa socket\n");
    return -ENOSYS;
}

/**
 * homa_hash(): ??.
 * @return: ??
 */
int homa_hash(struct sock *sk)
{
    printk(KERN_WARNING
           "unimplemented hash invoked on Homa socket\n");
    return 0;
}

/**
 * homa_unhash(): ??.
 * @return: ??
 */
void homa_unhash(struct sock *sk)
{
    printk(KERN_WARNING
           "unimplemented unhash invoked on Homa socket\n");
}

/**
 * homa_rehash(): ??.
 * @return: ??
 */
void homa_rehash(struct sock *sk)
{
    printk(KERN_WARNING
           "unimplemented rehash invoked on Homa socket\n");
}

/**
 * homa_get_port(): ??.
 * @return: ??
 */
int homa_get_port(struct sock *sk, unsigned short snum)
{
    printk(KERN_WARNING
           "unimplemented get_port invoked on Homa socket\n");
    return 0;
}

/**
 * homa_diag_destroy(): ??.
 * @return: ??
 */
int homa_diag_destroy(struct sock *sk, int err)
{
    printk(KERN_WARNING
           "unimplemented diag_destroy invoked on Homa socket\n");
    return -ENOSYS;
}

/**
 * homa_v4_early_demux(): invoked by IP for ??.
 * @return: Always 0?
 */
int homa_v4_early_demux(struct sk_buff *skb)
{
    printk(KERN_WARNING
           "unimplemented early_demux invoked on Homa socket\n");
    return 0;
}

/**
 * homa_v4_early_demux_handler(): invoked by IP for ??.
 * @return: Always 0?
 */
int homa_v4_early_demux_handler(struct sk_buff *skb)
{
    printk(KERN_WARNING
           "unimplemented early_demux_handler invoked on Homa socket\n");
    return 0;
}

/**
 * homa_handler(): invoked by IP to handle an incoming Homa packet.
 * @return: Always 0?
 */
int homa_handler(struct sk_buff *skb)
{
    printk(KERN_NOTICE
           "[homa_handler] incoming Homa packet: len %u, data_len %u, data \"%.*s\"\n",
           skb->len, skb->data_len, skb->len, skb->data);
    printk(KERN_NOTICE "[homa_handler] network header size %lu, memory allocated %lu\n",
           skb->data - skb_network_header(skb),
           atomic_long_read(homa_prot.memory_allocated));
    return 0;
}

/**
 * homa_v4_early_demux_handler(): invoked by IP to handle an incoming error
 * packet, such as ICMP UNREACHABLE.
 * @return: Always 0?
 */
void homa_err_handler(struct sk_buff *skb, u32 info)
{
    printk(KERN_WARNING
           "unimplemented err_handler invoked on Homa socket\n");
}

/**
 * homa_poll(): invoked to implement the poll system call.
 * @return: ??
 */
__poll_t homa_poll(struct file *file, struct socket *sock,
                   struct poll_table_struct *wait)
{
    printk(KERN_WARNING
           "unimplemented poll invoked on Homa socket\n");
    return 0;
}
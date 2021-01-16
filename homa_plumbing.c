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
    .bind = homa_bind,
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
    
    homa.next_client_port = HOMA_MIN_CLIENT_PORT; //初始化分配的下一个client port
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
/**
* homa_bind（）-为Homa套接字实现bind系统调用;与其他AF_INET协议不同，仅用于一个client
*/
int homa_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
    struct homa_sock *hsk = homa_sk(sock->sk);
    struct homa_sock *owner;
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    __u32 port;

    if (addr_len < sizeof(*addr_in)) {
        return -EINVAL;
    }
    if (addr_in->sin_family != AF_INET) {
        return -EAFNOSUPPORT;
    }
    port = ntohs(addr_in->sin_port);
    if ((port == 0) || (port >= HOMA_MIN_CLIENT_PORT)) {
        return -EINVAL;
    }
    //找到对应的port所在的socket,将对应传入的port绑定到socket
    owner = homa_find_socket(&homa, port);
    if ((owner != NULL) && (owner != hsk)) {
        return -EADDRINUSE;
    }
    hsk->server_port = port;
    printk(KERN_NOTICE "[homa_bind]success bind port: %d\n", port);
    return 0;
}

//proto的一些需要自定义的接口
//invoked when close system call is invoked on a Homa socket.
void homa_close(struct sock *sk, long timeout)
{
    struct homa_sock *hsk = homa_sk(sk);                        //获取到homa socket 结构体
	struct list_head *pos, *next;
    printk(KERN_NOTICE "[homa_close]closing socket %d\n", hsk->client_port);
	
	list_del(&hsk->socket_links);                               //删除home.sockets link
	//释放所有的rpc
    list_for_each_safe(pos, next, &hsk->client_rpcs) {
        struct homa_client_rpc *crpc = list_entry(pos,struct homa_client_rpc, client_rpc_links);    //释放所有的rpc
		homa_client_rpc_destroy(crpc);
		kfree(crpc);
	}
    list_for_each_safe(pos, next, &hsk->server_rpcs) {
        struct homa_server_rpc *srpc = list_entry(pos, struct homa_server_rpc, server_rpc_links);
        homa_server_rpc_destroy(srpc);
        kfree(srpc);
    }
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
 * homa_init_sock(): invoked to initialize a new Homa socket.
 * @return: always 0 (success)
 */
int homa_sock_init(struct sock *sk)
{
    struct homa_sock *hsk = homa_sk(sk);
    hsk->server_port = 0;
    while (1) {
        if (homa.next_client_port < HOMA_MIN_CLIENT_PORT) {
            homa.next_client_port = HOMA_MIN_CLIENT_PORT;
        }
        if (!homa_find_socket(&homa, homa.next_client_port)) {
            break;
        }
        homa.next_client_port++;
    }
    hsk->client_port = homa.next_client_port;
    homa.next_client_port++;
    hsk->next_outgoing_id = 1;
    list_add(&hsk->socket_links, &homa.sockets);
    INIT_LIST_HEAD(&hsk->client_rpcs);
    INIT_LIST_HEAD(&hsk->server_rpcs);
    INIT_LIST_HEAD(&hsk->ready_server_rpcs);
    INIT_LIST_HEAD(&hsk->ready_client_rpcs);
    printk(KERN_NOTICE "[hsk init]opened socket %d\n", hsk->client_port);
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
int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
    return -EINVAL;
}

/**
 * homa_recvmsg(): receive a message from a Homa socket.
 * @Non-zero:非0表示设置了阻塞等待时间
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len) {
    return -EINVAL;
}

/*!
 * ioctl来发消息的核心逻辑
 * @param sk 发送用的sk
 * @param arg user-space传入的arg
 * @return 0:success, otherwise:errno.
 */
int homa_ioc_send(struct sock *sk, unsigned long arg) {
    struct homa_sock *hsk = homa_sk(sk);
    struct homa_args_send_ipv4 args;
    struct homa_client_rpc *crpc = NULL;

    struct iovec iov;
    struct iov_iter iter;
    int err;

    //从用户空间拷贝arg的参数，拷贝的是source_addr的信息
    //第三个参数是预计拷贝的字节数，这里就是拷贝所有的用户参数 buf len address
    if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
        return -EFAULT;
    printk(KERN_NOTICE "[homa_ioc_send] args.request: %p, args.reqlen: %lu\n", args.request,args.reqlen);
    //用户用于发送msg buffer的地址和长度 存到 iov 、iter 中
    err = import_single_range(WRITE, args.request, args.reqlen, &iov, &iter);
    if (unlikely(err))
        return err;

    if (unlikely(args.dest_addr.sin_family != AF_INET))
        return -EAFNOSUPPORT;

    lock_sock(sk);      //加个锁
    crpc = (struct homa_client_rpc *) kmalloc(sizeof(*crpc), GFP_KERNEL);//创建一个client prc
    if (unlikely(!crpc)) {
        err = -ENOMEM;
        goto error;
    }

    crpc->id = hsk->next_outgoing_id;   //crpc被分配id
    hsk->next_outgoing_id++;            //这个socket的next id被自增
    list_add(&crpc->client_rpc_links, &hsk->client_rpcs);

    err = homa_addr_init(&crpc->dest, sk, hsk->inet.inet_saddr,
                         hsk->client_port, args.dest_addr.sin_addr.s_addr,ntohs(args.dest_addr.sin_port));
    if (unlikely(err != 0)) {
        goto error;
    }

    err = homa_message_out_init(&crpc->request, sk, &iter, args.reqlen,
                                &crpc->dest, hsk->client_port, crpc->id);
    if (unlikely(err != 0)) {
        goto error;
    }
    crpc->state = CRPC_WAITING;
    homa_xmit_packets(&crpc->request, sk, &crpc->dest);
    printk(KERN_NOTICE "[homa_ioc_send]Packet xmitted up to offset %d\n", crpc->request.next_offset);
    if (unlikely(copy_to_user(&((struct homa_args_send_ipv4 *) arg)->id,
                              &crpc->id, sizeof(crpc->id))))
        return -EFAULT;
    release_sock(sk);
    return 0;

    error:
    if (crpc) {
        homa_client_rpc_destroy(crpc);
    }
    release_sock(sk);
    return err;
}

/*!
 * ioctl来收消息的核心逻辑
 * @param sk 接收的sk
 * @param arg 用来给user-space返回值的arg
 * @return 0:success 否则:error
 */
int homa_ioc_recv(struct sock *sk, unsigned long arg) {
    struct homa_sock *hsk = homa_sk(sk);
    struct homa_args_recv_ipv4 args;
    struct iovec iov;
    struct iov_iter iter;
    int err;
    struct homa_message_in *msgin;
    struct homa_addr *source;
    long timeo;
    int noblock = 0;
    int result;
    struct homa_client_rpc *crpc = NULL;

    if (unlikely(copy_from_user(&args, (void *) arg,
                                offsetof(struct homa_args_recv_ipv4, source_addr))))
    return -EFAULT;
    err = import_single_range(READ, args.buf, args.len, &iov,
                              &iter);
    if (unlikely(err))
        return err;

    while (1) {
        if (!list_empty(&hsk->ready_server_rpcs)) {
            struct homa_server_rpc *srpc;
            srpc = list_first_entry(&hsk->ready_server_rpcs,
            struct homa_server_rpc, ready_links);
            list_del(&srpc->ready_links);
            srpc->state = SRPC_IN_SERVICE;
            msgin = &srpc->request;
            source = &srpc->client;
            args.id = srpc->id;
            break;
        }
        if (!list_empty(&hsk->ready_client_rpcs)) {
            crpc = list_first_entry(&hsk->ready_client_rpcs,
            struct homa_client_rpc, ready_links);
            msgin = &crpc->response;
            source = &crpc->dest;
            args.id = crpc->id;
            break;
        }
        if (noblock)
            return -EAGAIN;
        timeo = sock_rcvtimeo(sk, noblock);
        timeo = homa_wait_ready_msg(sk, &timeo);
        if (signal_pending(current))
            return sock_intr_errno(timeo);
        printk(KERN_NOTICE "[homa_ioc_recv]Woke up, trying again\n");
    }

    args.source_addr.sin_family = AF_INET;
    args.source_addr.sin_port = htons(source->dport);
    args.source_addr.sin_addr.s_addr = source->daddr;
    memset(args.source_addr.sin_zero, 0,
           sizeof(args.source_addr.sin_zero));
    homa_message_in_copy_data(msgin, &iter, args.len);
    result = msgin->total_length;
    if (crpc) {
        homa_client_rpc_destroy(crpc);
    }
    homa_message_in_destroy(msgin);
    if (unlikely(copy_to_user(
            &((struct homa_args_recv_ipv4 *) arg)->source_addr,
            &args.source_addr, sizeof(args) -
                               offsetof(struct homa_args_recv_ipv4, source_addr))))
    return -EFAULT;
    printk(KERN_NOTICE "Leaving homa_recvmsg normally\n");
    return result;
}
//int homa_ioc_recv(struct sock *sk, unsigned long arg) {
//    struct homa_sock *hsk = homa_sk(sk);
//    struct homa_args_recv_ipv4 args;
//    struct homa_message_in *msgin;
//    struct homa_addr *source;
//    struct homa_client_rpc *crpc = NULL;
//
//    struct iovec iov;
//    struct iov_iter iter;
//
//    int err;
//    long timeo;
//    int noblock = 0;
//    int result;
//
//
//    //从用户空间拷贝arg的参数，拷贝的是source_addr的信息
//    //第三个参数是预计拷贝的字节数，这里就是拷贝地址结构体之前的值(也就是下一个函数import_single_range用到的buf和len)
//    if (unlikely(copy_from_user(&args, (void *) arg, offsetof(struct homa_args_recv_ipv4, source_addr))))
//        return -EFAULT;
//    //用户用于接收msg的地址和期望长度 存到 iov 、iter 中
//    err = import_single_range(READ, args.buf, args.len, &iov, &iter);
//    if (unlikely(err))
//        return err;
//
//    //开始循环接收
//    while (1) {
//        if (!list_empty(&hsk->ready_server_rpcs)) {
//            struct homa_server_rpc *srpc;
//            srpc = list_first_entry(&hsk->ready_server_rpcs, struct homa_server_rpc, ready_links);  //get the first ready srpc
//            list_del(&srpc->ready_links);                                                           //remove this rpc from list
//            srpc->state = SRPC_IN_SERVICE;                                                          //set rpc status
//            msgin = &srpc->request;                                                                 //get homa_message_in
//            source = &srpc->client;                                                                 //get sender info
//            args.id = srpc->id;                                                                     //copy rpc_id to userspace
//            break;
//        }
//        if (!list_empty(&hsk->ready_client_rpcs)) {
//            crpc = list_first_entry(&hsk->ready_client_rpcs, struct homa_client_rpc, ready_links);
//            msgin = &crpc->response;
//            source = &crpc->dest;
//            args.id = crpc->id;
//            break;
//        }
//        //noblock and still not recv msg:return
//        if (noblock) {
//            return -EAGAIN;
//        }
//        //wait
//        timeo = sock_rcvtimeo(sk, noblock);
//        timeo = homa_wait_ready_msg(sk, &timeo);
//        if (signal_pending(current)) {
//            printk("[homa_recvmsg]Aborting homa_ioc_recv because of errno %d\n", -sock_intr_errno(timeo));
//            return sock_intr_errno(timeo);
//        }
//        printk(KERN_NOTICE "[homa_recvmsg]Woke up, trying again\n");
//    }
//
//    //copy meta info to userspace
//    args.source_addr.sin_family = AF_INET;
//    args.source_addr.sin_port = htons(source->dport);
//    args.source_addr.sin_addr.s_addr = source->daddr;
//    memset(args.source_addr.sin_zero, 0,sizeof(args.source_addr.sin_zero));
//
//    //copy data to userspace
//    homa_message_in_copy_data(msgin, &iter, args.len);
//    result = msgin->total_length;
//
//    if(crpc){
//        homa_client_rpc_destroy(crpc);
//    }
//    homa_message_in_destroy(msgin);
//    if (unlikely(copy_to_user(
//            &((struct homa_args_recv_ipv4 *) arg)->source_addr,
//            &args.source_addr,
//            sizeof(args) - offsetof(struct homa_args_recv_ipv4, source_addr)
//                    )))
//    return -EFAULT;
//    printk(KERN_NOTICE "[homa_recvmsg]Leaving homa_recvmsg normally\n");
//    return result;
//}
/**
    * homa_wait_ready_msg（）-等待直到至少有一条完整的消息准备服务。
    * @sk：消息将到达的Homa套接字。
    * @timeo：最长等待时间； 修改后返回保留等待剩余时间。
    *返回：零或负的errno值返回到应用程序。
*/
int homa_wait_ready_msg(struct sock *sk, long *timeo)
{
    DEFINE_WAIT_FUNC(wait, woken_wake_function);                                        //初始化一个wait_queue_t类型变量wait ，包含func:woken_wake_function
    int rc;
    //sk_sleep:wait_queue_head_t类型的字段 sk_sleep 用来表示在这个 sock 上等待事件发生
    add_wait_queue(sk_sleep(sk), &wait);                                                //把sk的等待队列赋给wait
    sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
    rc = sk_wait_event(sk,
                       timeo,
                       !list_empty(&homa_sk(sk)->ready_server_rpcs) || !list_empty(&homa_sk(sk)->ready_client_rpcs),
                       &wait);                                                          //该函数调用schedule_timeout进入睡眠，其进一步调用了schedule函数，首先从运行队列删除，其次加入到等待队列
    sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
    remove_wait_queue(sk_sleep(sk), &wait);                                             //移除等待队列
    return rc;
}

/*!
 * Base on known rpc_id and sender address ,reply some msg to sender
 * @param sk
 * @param arg
 * @return
 */
int homa_ioc_reply(struct sock *sk,unsigned long arg){
    struct homa_sock *hsk=homa_sk(sk);
    struct homa_args_reply_ipv4 args;
    struct iovec iov;
    struct iov_iter iter;
    int err;
    struct homa_server_rpc *srpc;

    printk(KERN_NOTICE "[homa_ioc_reply]Starting homa_ioc_reply\n");
    //copy data from user
    if (unlikely(copy_from_user(&args, (void *) arg, sizeof(args))))
        return -EFAULT;
    //define iov address
    err = import_single_range(WRITE, args.response, args.resplen, &iov,
                              &iter);
    if (unlikely(err))
        return err;

    if (unlikely(args.dest_addr.sin_family != AF_INET))
        return -EAFNOSUPPORT;

    printk(KERN_NOTICE "[homa_ioc_reply]Calling homa_find_server_rpc\n");
    srpc = homa_find_server_rpc(hsk, args.dest_addr.sin_addr.s_addr, ntohs(args.dest_addr.sin_port), args.id);
    if (!srpc || (srpc->state != SRPC_IN_SERVICE)) {
        //release_sock(sk);
        return 0;
    }
    srpc->state = SRPC_RESPONSE;
    printk(KERN_NOTICE "[homa_ioc_reply]Found server rpc for reply\n");

    err = homa_message_out_init(&srpc->response, sk, &iter, args.resplen, &srpc->client, hsk->client_port, srpc->id);
    if (unlikely(err))
        goto error;
    homa_xmit_packets(&srpc->response, sk, &srpc->client);
    //release_sock(sk);
    return err;

error:
    printk(KERN_NOTICE "Error %d in homa_ioc_reply, deleting rpc\n", err);
    list_del(&srpc->server_rpc_links);
    homa_server_rpc_destroy(srpc);
    //release_sock(sk);
    return err;
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
int homa_handler(struct sk_buff *skb) {
    char buffer[200];
    __be32 saddr = ip_hdr(skb)->saddr;
    int length = skb->len;
    struct common_header *h = (struct common_header *) skb->data;
    struct homa_server_rpc *srpc;
    struct homa_sock *hsk;
    __u16 dport;

    if (length < HOMA_MAX_HEADER) {
        printk(KERN_WARNING "[homa_hsk]Homa packet from %pI4 too short: %d bytes\n", &saddr, length);
        goto discard;
    }
    printk(KERN_NOTICE "[homa_hsk]incoming Homa packet: %s\n",
            homa_print_header(skb, buffer, sizeof(buffer)));

    dport = ntohs(h->dport);
    hsk = homa_find_socket(&homa, dport);
    if (!hsk) {
        printk(KERN_WARNING "[homa_hsk]Homa packet from %pI4 sent to unknown port %u\n", &saddr, dport);
        goto discard;
    }
    //if dport is a server port which bind and used to receive data
    if (dport < HOMA_MIN_CLIENT_PORT) {
        //find a existed srpc or return null
        srpc = homa_find_server_rpc(hsk, saddr, ntohs(h->sport), h->id);
        switch (h->type) {
            case DATA:
                homa_data_from_client(&homa, skb, hsk, srpc);
                break;
            case GRANT:
                goto discard;
            case RESEND:
                goto discard;
            case BUSY:
                goto discard;
        }
    } else {
        // else mean this is a client and receive response from server
        struct homa_client_rpc *crpc;
        crpc = homa_find_client_rpc(hsk, ntohs(h->sport), h->id);
        if (!crpc)
            goto discard;
        switch (h->type) {
            case DATA:
                homa_data_from_server(&homa, skb, hsk, crpc);
                break;
            case GRANT:
                goto discard;
            case RESEND:
                goto discard;
            case BUSY:
                goto discard;
        }
    }
    return 0;

    discard:
    kfree_skb(skb);
    return 0;
}

/**
 * homa_ioctl(): implements the ioctl system call for Homa sockets.
 * @return: 0 on success, otherwise a negative errno.
 */
int homa_ioctl(struct sock *sk, int cmd, unsigned long arg) {
    switch (cmd) {
        case HOMAIOCSEND:
            return homa_ioc_send(sk, arg);
        case HOMAIOCRECV:
            return homa_ioc_recv(sk, arg);
        case HOMAIOCINVOKE:
            printk(KERN_NOTICE "HOMAIOCINVOKE not yet implemented\n");
            return -EINVAL;
        case HOMAIOCREPLY:
            return homa_ioc_reply(sk, arg);
        case HOMAIOCABORT:
            printk(KERN_NOTICE "HOMAIOCABORT not yet implemented\n");
            return -EINVAL;
        default:
            printk(KERN_NOTICE "Unknown Homa ioctl: %d\n", cmd);
            return -EINVAL;
    }
}

/**
 * homa_v4_early_demux_handler(): invoked by IP to handle an incoming error
 * packet, such as ICMP UNREACHABLE.
 * @return: Always 0?
 */
int homa_err_handler(struct sk_buff *skb, u32 info)
{
    printk(KERN_WARNING
           "unimplemented err_handler invoked on Homa socket\n");
    return 0;
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
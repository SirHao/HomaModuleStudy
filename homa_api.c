//此文件包含实现对应用程序可见的Homa API的函数。 它旨在成为part of user-level runtime lib

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "homa.h"

/**
* homa_recv（）-等待传入消息（请求或响应）并返回。
* @sockfd：用于在其上接收消息的套接字的文件描述符。
* @buf: 传入消息的缓冲区的第一个字节。
* @len: @request中可用的字节数。
* @src_addr: 发件人的地址将在此处返回。
* @addrlen: @src_addr上的可用空间（以字节为单位）。
* @id：与消息关联的RPC的唯一标识符 将在这里返回。
*
*return：传入消息的总大小。这可能比len更大，在这种情况下，传入消息的最后一个字节 被丢弃。 负值表示错误。
*/
size_t homa_recv(int sockfd, void *buf, size_t len, struct sockaddr *src_addr,
                 size_t addrlen, uint64_t *id)
{
    struct homa_args_recv_ipv4 args;
    int result;

    if (addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -EINVAL;
    }
    args.buf = (void *) buf;
    args.len = len;
    result = ioctl(sockfd, HOMAIOCRECV, &args);
    *((struct sockaddr_in *) src_addr) = args.source_addr;
    *id = args.id;
    return result;
}

/**
* homa_send（）-发送请求消息以启动RPC。
* @sockfd：在其上发送消息的套接字的文件描述符。
* @request：包含请求消息的缓冲区的第一个字节。
* @reqlen： request处的字节数。
* @dest_addr：应将请求发送到的服务器地址。
* @addrlen：dest_addr的大小（以字节为单位)。
* @id：将在此处返回请求的唯一标识符;以后可用于查找此请求的响应。
*
* 返回：0表示请求已被接受。 负值表示错误。
*/
int homa_send(int sockfd, const void *request, size_t reqlen,
              const struct sockaddr *dest_addr, size_t addrlen,
              uint64_t *id)
{
    struct homa_args_send_ipv4 args;
    int result;

    if (dest_addr->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -EAFNOSUPPORT;
    }
    args.request = (void *) request;
    args.reqlen = reqlen;
    args.dest_addr = *((struct sockaddr_in *) dest_addr);
    args.id = 0;
    result = ioctl(sockfd, HOMAIOCSEND, &args);
    *id = args.id;
    return result;
}
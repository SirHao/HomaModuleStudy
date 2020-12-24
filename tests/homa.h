//homa内核调用接口
#include <linux/types.h>
#ifndef __KERNEL__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    //Homa的IP协议空间中的协议号（这不是正式分配的插槽）。
    #define IPPROTO_HOMA 140

    //最大的单次收发消息大小
    #define HOMA_MAX_MESSAGE_LENGTH 1000000

    //16位端口空间被划分为两个非重叠区域。 端口1-32767专为定义明确的服务器端口保留。
    //其余端口用于client port； 这些由Homa自动分配。 端口0被保留。
    #define HOMA_MIN_CLIENT_PORT 0x8000

    //Homa套接字上的I/O ctl call。
    //这些特定的值是随机选择的，可能需要重新考虑以确保它们不与其他任何冲突。
    #define HOMAIOCSEND   1003101
    #define HOMAIOCRECV   1003102
    #define HOMAIOCINVOKE 1003103
    #define HOMAIOCREPLY  1003104
    #define HOMAIOCABORT  1003105
    //ioctl每个signal对应的处理函数
    extern int    homa_send(int sockfd, const void *request, size_t reqlen,
                            const struct sockaddr *dest_addr, size_t addrlen,
                            uint64_t *id);
    extern size_t homa_recv(int sockfd, void *buf, size_t len,
                            struct sockaddr *src_addr, size_t addrlen,
                            uint64_t *id);
    extern size_t homa_invoke(int sockfd, const void *request, size_t reqlen,
                              const struct sockaddr *dest_addr, size_t addrlen,
                              void *response, size_t resplen);
    extern int    homa_reply(int sockfd, const void *response, size_t resplen,
                             const struct sockaddr *dest_addr, size_t addrlen,
                             uint64_t id);
    extern int    homa_abort(int sockfd, uint64_t id);

    //userspace HOMAIOCSEND传递data到kernel space的format; 假设使用IPV4.
    struct homa_args_send_ipv4 {
        void *request;
        size_t reqlen;
        struct sockaddr_in dest_addr;
        __u64 id;
    };

    //userspace HOMAIOCRECV接收data与kernel space的format; 假设使用IPV4.
    struct homa_args_recv_ipv4 {
        void *buf;
        size_t len;
        struct sockaddr_in source_addr;
        __u64 id;
    };

    //passes arguments and results betweeen homa_invoke and the HOMAIOCINVOKE ioctl.假设使用IPV4.
    struct homa_args_invoke_ipv4 {
        void *request;
        size_t reqlen;
        struct sockaddr_in dest_addr;
        void *response;
        size_t resplen;
    };

    //passes arguments and results betweeen homa_reply and the HOMAIOCREPLY ioctl. 假设使用IPV4.
    struct homa_args_reply_ipv4 {
        const void *buf;
        size_t len;
        const struct sockaddr_in dest_addr;
        __u64 id;
    };

#ifdef __cplusplus
}
#endif
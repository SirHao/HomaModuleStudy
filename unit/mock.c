/* This file provides simplified substitutes for many Linux variables and
 * functions, in order to allow Homa unit tests to be run outside a Linux
 * kernel.
 */

#include <stdio.h>

#include "homa_impl.h"
#include "unit_ccutils.h"
#include "unit_mock.h"

#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"

/* It isn't safe to include some header files, such as stdlib, because
 * they conflict with kernel header files. The explicit declarations
 * below replace those header files.
 */

extern void       free(void *ptr);
extern void      *malloc(size_t size);
extern void      *memcpy(void *dest, const void *src, size_t n);

/* Keeps track of all sk_buffs that are alive in the current test.
 * Reset for each test.*/
static struct unit_hash *buffs_in_use = NULL;

struct task_struct *current_task = NULL;
unsigned long ex_handler_refcount = 0;
unsigned long phys_base = 0;

extern void add_wait_queue(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry) {}

struct sk_buff *__alloc_skb(unsigned int size, gfp_t priority, int flags,
		int node)
{
	return 0;
}

bool _copy_from_iter_full(void *addr, size_t bytes, struct iov_iter *i)
{
	return true;
}

bool _copy_from_iter_full_nocache(void *addr, size_t bytes, struct iov_iter *i)
{
	return true;
}

unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return 0;
}

bool csum_and_copy_from_iter_full(void *addr, size_t bytes, __wsum *csum,
			       struct iov_iter *i)
{
	return true;
}

unsigned long _copy_from_user(void *to, const void __user *from,
		unsigned long n)
{
	return 0;
}

int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr,
		int addr_len)
{
	return 0;
}

void ip4_datagram_release_cb(struct sock *sk) {}

void dst_release(struct dst_entry *dst) {}

int import_single_range(int type, void __user *buf, size_t len,
		struct iovec *iov, struct iov_iter *i)
{
	return 0;
}

int inet_add_protocol(const struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int inet_del_protocol(const struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	return 0;
}

int inet_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len,
		int peer)
{
	return 0;
}

int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return 0;
}

int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		int flags)
{
	return 0;
}

void inet_register_protosw(struct inet_protosw *p) {}

int inet_release(struct socket *sock)
{
	return 0;
}

int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	return 0;
}

void inet_unregister_protosw(struct inet_protosw *p) {}

int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	return 0;
}

struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4,
		const struct sock *sk)
{
	return NULL;
}

void kfree(const void *block) {}

void kfree_skb(struct sk_buff *skb)
{
	skb->users.refs.counter--;
	if (skb->users.refs.counter > 0)
		return;
	if (!buffs_in_use || unit_hash_get(buffs_in_use, skb) == NULL) {
		printf("*** Unknown sk_buff released.\n");
		return;
	}
	unit_hash_erase (buffs_in_use, skb);
	free(skb->head);
	free(skb);
}

void *__kmalloc(size_t size, gfp_t flags)
{
	return NULL;
}

void lock_sock_nested(struct sock *sk, int subclass) {}

ssize_t __modver_version_show(struct module_attribute *a,
		struct module_kobject *b, char *c)
{
	return 0;
}

int printk(const char *s, ...)
{
	return 0;
}

int proto_register(struct proto *prot, int alloc_slab)
{
	return 0;
}

void proto_unregister(struct proto *prot) {}

void release_sock(struct sock *sk) {}

void remove_wait_queue(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry) {}

void security_sk_classify_flow(struct sock *sk, struct flowi *fl) {}

void sk_common_release(struct sock *sk) {}

int sk_set_peek_off(struct sock *sk, int val)
{
	return 0;
}

int skb_copy_datagram_iter(const struct sk_buff *from, int offset,
		struct iov_iter *to, int size)
{
	return 0;
}

void *skb_put(struct sk_buff *skb, unsigned int len)
{
	return NULL;
}

int sock_common_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen)
{
	return 0;
}

int sock_common_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, unsigned int optlen)
{
	return 0;
}

int sock_no_accept(struct socket *sock, struct socket *newsock, int flags,
		bool kern)
{
	return 0;
}

int sock_no_listen(struct socket *sock, int backlog)
{
	return 0;
}

int sock_no_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma)
{
	return 0;
}

int sock_no_shutdown(struct socket *sock, int how)
{
	return 0;
}

ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
		size_t size, int flags)
{
	return 0;
}

int sock_no_socketpair(struct socket *sock1, struct socket *sock2)
{
	return 0;
}

long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode,
		long timeout)
{
	return 0;
}

void __warn_printk(const char *s, ...) {}

int woken_wake_function(struct wait_queue_entry *wq_entry, unsigned mode,
		int sync, void *key)
{
	return 0;
}

/**
 * mock_skb_teardown() - Invoked at the end of each test to check for
 * consistency issues with sk_buffs, and to reset skb-related information.
 */
void mock_skb_teardown(void)
{
	int count = unit_hash_size(buffs_in_use);
	if (count > 0)
		FAIL("%u sk_buffs still in use after test", count);
	unit_hash_free(buffs_in_use);
	buffs_in_use = NULL;
}

/**
 * mock_buff_new() - Allocate and return a packet buffer. The buffer is
 * initialized as if it just arrived from the network.
 * @saddr:        IPV4 address to use as the sender of the packet, in
 *                network byte order.
 * @h:            Header for the buffer; actual length and contents depend
 *                on the type.
 * @extra_bytes:  How much additional data to add to the buffer after
 *                the header.
 * @first_value:  Determines the data contents: the first __u32 will have
 *                this value, and each successive __u32 will increment by 4.
 * 
 * Return:        A packet buffer containing the information described above.
 *                The caller owns this buffer and is responsible for freeing it.
 */
struct sk_buff *mock_skb_new(__be32 saddr, struct common_header *h,
		int extra_bytes, int first_value)
{
	int header_size, i, ip_size;
	
	switch (h->type) {
	case DATA:
		header_size = sizeof(struct data_header);
		break;
	case GRANT:
		header_size = sizeof(struct grant_header);
		break;
	case RESEND:
		header_size = sizeof(struct resend_header);
		break;
	case BUSY:
		header_size = sizeof(struct busy_header);
		break;
	default:
		printf("*** Unknown packet type %d in new_buff.\n", h->type);
		header_size = sizeof(struct common_header);
		break;
	}
	struct sk_buff *skb = malloc(sizeof(struct sk_buff));
	if (!buffs_in_use)
		buffs_in_use = unit_hash_new();
	unit_hash_set(buffs_in_use, skb, "used");
	
	/* Round up sizes to whole words for convenience. */
	ip_size = (sizeof(struct iphdr) + 3) & ~3;
	/* Round up extra data space to whole words for convenience. */
	skb->head = malloc(ip_size + header_size + ((extra_bytes+3)&~3));
	skb->data = skb->head + ip_size;
	skb->network_header = ip_size - sizeof(struct iphdr);
	skb->transport_header = ip_size;
	skb->data = skb->head + ip_size;
	memcpy(skb->data, h, header_size);
	for (i = 0; i < extra_bytes; i += 4) {
		*(int *)(skb->data + header_size + i) = first_value + i;
	}
	skb->len = header_size + extra_bytes;
	skb->users.refs.counter = 1;
	ip_hdr(skb)->saddr = saddr;
	return skb;
}
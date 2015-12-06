/*
 * Most of the codes for this file is brought from kernel source code.
 * 
 */

#ifndef _LKM_UTIL_H
#define _LKM_UTIL_H

#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <net/flow.h>
#include <net/route.h>
#include <net/ip.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#include <linux/fdtable.h>
#endif

#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/jiffies.h>
#include <asm/tlbflush.h>

#define wait_for_sig_or_timeout(timeout) schedule_timeout_interruptible(timeout)
#define wait_for_timeout(timeout) schedule_timeout_uninterruptible(timeout)

struct pollfd_ex_t {
    struct pollfd pollfd;
    void *data;
    int (*poll_func)(void *data, poll_table *pt);
};

#define MIN(arg1, arg2) (arg1 < arg2 ? arg1 : arg2)
#define MAX(arg1, arg2) (arg1 > arg2 ? arg1 : arg2)

#define E_EVENTS (POLLERR|POLLHUP|POLLNVAL)

#define NOW_SECS (CURRENT_TIME_SEC.tv_sec)

#define NOTIFY_SIG (SIGINT)
#define SEND_FORCE (1)
#define notify(tskp) send_sig(NOTIFY_SIG, (tskp), SEND_FORCE)

#define INVOKED_BY_TGROUP_LEADER() (current == current->group_leader)

#define lkmalloc(size) kzalloc(size, GFP_ATOMIC)
#define lkmfree(ptr) kfree(ptr)

#define BYTES_ALIGN(size) (((size) + (sizeof(long) - 1)) & ~(sizeof(long) - 1))

#define SOCK_CLIENT_TAG (1U << 30)

#define IS_IPV4_SA(addr)    \
    ((addr)->sa_family == AF_INET)

#define IS_CLIENT_SOCK(sock)                    \
    ((sock)->file && ((sock)->file->f_flags & SOCK_CLIENT_TAG))

#define SET_CLIENT_FLAG(sock) do {              \
    if ((sock)->file)                           \
    (sock)->file->f_flags |= SOCK_CLIENT_TAG;   \
} while (0)

#define CLEAR_CLIENT_FLAG(sock) do {            \
    if ((sock)->file)                           \
    (sock)->file->f_flags &= ~SOCK_CLIENT_TAG;  \
} while (0)

#define SK_ESTABLISHING(sk) \
    (sk->sk_state == TCP_SYN_SENT)

#define SK_ESTABLISHED(sk)  \
    (sk->sk_state == TCP_ESTABLISHED)

#define SET_SOCK_STATE(sock, STATE)    \
    ((sock)->state = STATE)

#define SOCK_ESTABLISHED(sock) \
    ((sock)->sk && SK_ESTABLISHED((sock)->sk))

#define IS_TCP_SOCK(sock) \
    ((sock)->type == SOCK_STREAM)

#define IS_UNCONNECTED_SOCK(sock) \
    ((sock)->type == SS_UNCONNECTED)

#define lkm_atomic32_read(v) atomic_read((atomic_t *)v) 
#define lkm_atomic32_add(v, a) atomic_add_return(a, (atomic_t *)v)
#define lkm_atomic32_sub(v, a) atomic_sub_return(a, (atomic_t *)v)
#define lkm_atomic32_set(v, a) atomic_set((atomic_t *)v, a) 

#define lkm_atomic64_read(v) atomic64_read((atomic64_t *)v) 
#define lkm_atomic64_add(v, a) atomic64_add_return(a, (atomic64_t *)v)
#define lkm_atomic64_sub(v, a) atomic64_sub_return(a, (atomic64_t *)v)
#define lkm_atomic64_set(v, a) atomic64_set((atomic64_t *)v, a) 

#if BITS_PER_LONG == 32 //32 bits

typedef atomic_t lkm_atomic_t;
#define lkm_atomic_read(v) lkm_atomic32_read(v)
#define lkm_atomic_add(v, a) lkm_atomic32_add(v, a)
#define lkm_atomic_sub(v, a) lkm_atomic32_sub(v, a)
#define lkm_atomic_set(v, a) lkm_atomic32_set(v, a)

#elif BITS_PER_LONG == 64 //64bits

typedef atomic64_t lkm_atomic_t;
#define lkm_atomic_read(v) lkm_atomic64_read(v)
#define lkm_atomic_add(v, a) lkm_atomic64_add(v, a)
#define lkm_atomic_sub(v, a) lkm_atomic64_sub(v, a)
#define lkm_atomic_set(v, a) lkm_atomic64_set(v, a)

#endif

#define lkm_get_file(fd)            \
    ({ struct file * __file;    \
     rcu_read_lock();       \
     __file = fcheck_files(TASK_FILES(current), fd); \
     rcu_read_unlock(); \
     __file;})

#define TASK_FILES(tsk) (tsk)->files

#define FILE_FDT_TYPE typeof(((struct files_struct *)0)->fdtab)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)

#define TASK_FILES_FDT(tsk) ({   \
        FILE_FDT_TYPE * __tmp;      \
        rcu_read_lock();            \
        __tmp = rcu_dereference(TASK_FILES(tsk)->fdt);  \
        rcu_read_unlock();  \
        __tmp;})

#else

#define TASK_FILES_FDT(tsk) ({   \
        FILE_FDT_TYPE * __tmp;      \
        rcu_read_lock();            \
        __tmp = rcu_dereference_check_fdtable(TASK_FILES(tsk), TASK_FILES(tsk)->fdt);  \
        rcu_read_unlock();  \
        __tmp;})

#endif

#define FDT_GET_FILE(fdt) ({    \
        struct file *__tmp;     \
        rcu_read_lock();        \
        __tmp = rcu_dereference(fdt->fd[fd]);   \
        rcu_read_unlock();  \
        __tmp;})

#define lkm_setrlimit(resource, new_rlim)                       \
    do {                                                        \
        struct rlimit *old_rlim;                                \
                                                                \
        old_rlim = current->signal->rlim + resource;            \
        *old_rlim = new_rlim;                                   \
    } while (0)


#define SOCKADDR_FAMILY(sockaddr_ptr) (((struct sockaddr_in *)(sockaddr_ptr)))->sin_family
#define SOCKADDR_IP(sockaddr_ptr) (((struct sockaddr_in *)(sockaddr_ptr)))->sin_addr.s_addr
#define SOCKADDR_PORT(sockaddr_ptr) (((struct sockaddr_in *)(sockaddr_ptr)))->sin_port

typedef struct array_t array_t;
extern int lkm_poll(array_t *, int timeout);

#define lkm_jiffies (unsigned)jiffies

//Compat for 32-bits jiffies
static inline u64 lkm_jiffies_elapsed_from(u64 from)
{
    s64 elapsed_jiffies = lkm_jiffies - from;

    return elapsed_jiffies >= 0 ? elapsed_jiffies : (elapsed_jiffies + ULONG_MAX);
}

static inline int file_refcnt_read(struct file *filp)
{
    return lkm_atomic32_read(&filp->f_count);
}

static inline int file_refcnt_inc(struct file *filp)
{
    return lkm_atomic32_add(&filp->f_count, 1);
}

static inline int file_refcnt_dec(struct file *filp)
{
    return lkm_atomic32_sub(&filp->f_count, 1);
}

static inline void file_refcnt_set(struct file *filp, int c)
{
    lkm_atomic32_set(&filp->f_count, c);
}

struct fd_entry {
    int fd;
    struct list_head siblings;
};

static inline int lkm_get_unused_fd(void)
{
    int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 10)
    fd = get_unused_fd_flags(0);
#else
    fd = get_unused_fd();
#endif

    return fd;
}

struct sockaddr_in;
extern int lkm_create_tcp_connect(struct sockaddr_in *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 10)
extern int lkm_sock_map_fd(struct socket *sock, int flags);
#endif

static inline void TASK_GET_FDS(struct task_struct *tsk, struct list_head *fds_list)
{
    int i, j = 0;
    FILE_FDT_TYPE *fdt;
    
    fdt = TASK_FILES_FDT(tsk);
    
    for (;;) {
        unsigned long set;
        struct fd_entry *tmp;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
        i = j * __NFDBITS;
#else
        i = j * BITS_PER_LONG;
#endif

        if (i >= fdt->max_fds)
            break;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
        set = fdt->open_fds->fds_bits[j++];
#else
        set = fdt->open_fds[j++];
#endif

        while (set) {

            if (set & 1) {
                /*Collect the fds list and must free mem space by caller.*/
                tmp = (typeof(*tmp) *)lkmalloc(sizeof(typeof(*tmp)));
                tmp->fd = i;
                list_add_tail(&tmp->siblings, fds_list);
            }
            i++;
            set >>= 1;

        }
    }
}

static inline void task_fd_install(struct task_struct *tsk, int fd, struct file *filp)
{
    FILE_FDT_TYPE *fdt;
    struct files_struct *files = TASK_FILES(tsk);

    spin_lock(&files->file_lock);

    fdt = TASK_FILES_FDT(tsk);
    rcu_assign_pointer(fdt->fd[fd], filp);

    spin_unlock(&files->file_lock);
}


static inline struct socket *getsock(int fd)
{
    struct file *filp;
    FILE_FDT_TYPE *fdt = TASK_FILES_FDT(current);

    filp = FDT_GET_FILE(fdt);
    if (filp)
        return (struct socket *)filp->private_data;

    return NULL;
}

#define getsockcliaddr(sock, address) getsockaddr(sock, address, 0)
#define getsockservaddr(sock, address) getsockaddr(sock, address, 1)
static inline int getsockaddr(struct socket *sock, struct sockaddr *address, int peer)
{
    int len;
    int err;

    if (!sock->sk)
        return 0;

    err = sock->ops->getname(sock, address, &len, peer);
    if (err)
        return 0;

    return 1;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
static inline int lkm_ip_route_connect(struct rtable **rp, u32 dst,
		u32 src, u32 tos, int oif, u8 protocol,
		u16 sport, u16 dport, struct sock *sk,
		int flags)
{
    struct flowi fl = { .oif = oif,
        .nl_u = { .ip4_u = { .daddr = dst,
            .saddr = src,
            .tos   = tos } },
        .proto = protocol,
        .uli_u = { .ports =
            { .sport = sport,
                .dport = dport } } };
	int err;

	if (!dst || !src) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
		err = __ip_route_output_key(rp, &fl);
#else 
		err = __ip_route_output_key(sock_net(sk), rp, &fl);
#endif
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	security_sk_classify_flow(sk, &fl);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
	return ip_route_output_flow(rp, &fl, sk, flags);
#else
	return ip_route_output_flow(sock_net(sk), rp, &fl, sk, flags);
#endif

}
#endif

static inline int getsocklocaladdr(struct socket *sock, struct sockaddr *cliaddr, struct sockaddr *servaddr) 
{
    struct sock *sk = sock->sk;
    struct sockaddr_in *usin = (struct sockaddr_in *)servaddr;
    struct inet_sock *inet = inet_sk(sk);
    struct rtable *rt; 
    __be32 daddr, nexthop;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
    __be16 orig_sport, orig_dport;
    struct flowi4 *fl4;
    int err; 
    struct ip_options_rcu *inet_opt;

    nexthop = daddr = SOCKADDR_IP(usin);
    inet_opt = rcu_dereference_protected(inet->inet_opt,
            sock_owned_by_user(sk));
    if (inet_opt && inet_opt->opt.srr) {
        if (!daddr)
            return 0;
        nexthop = inet_opt->opt.faddr;
    }

    orig_sport = inet->inet_sport;
    orig_dport = SOCKADDR_PORT(usin);
    fl4 = &inet->cork.fl.u.ip4;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
    rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
            RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
            IPPROTO_TCP,
            orig_sport, orig_dport, sk, 1);
#else
    rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
            RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
            IPPROTO_TCP,
            orig_sport, orig_dport, sk);
#endif

    if (IS_ERR(rt)) {
        err = PTR_ERR(rt);
        if (err == -ENETUNREACH)
            IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
        return 0;
    }

    if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
        ip_rt_put(rt);
        return 0;
    }

    SOCKADDR_IP(cliaddr) = fl4->saddr;

#else

    int tmp;

    nexthop = daddr = SOCKADDR_IP(usin);

#if defined(optlength)

	if (inet->opt && inet->opt->srr) {
        if (!daddr)
            return 0;
        nexthop = inet->opt->faddr;
    }

#else

	{
		struct ip_options_rcu *inet_opt;
		inet_opt = inet->inet_opt;
		if (inet_opt && inet_opt->opt.srr) {
			if (!daddr)
				return 0;
			nexthop = inet_opt->opt.faddr;
		}    
	}

#endif

    tmp = lkm_ip_route_connect(&rt, nexthop, inet->saddr,
            RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
            IPPROTO_TCP,
            inet->sport, usin->sin_port, sk, 1);
    if (tmp < 0)
        return 0;

    if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
        ip_rt_put(rt);
        return 0;
    }

    SOCKADDR_IP(cliaddr) = rt->rt_src;

#endif

    return 1;
}

static inline int is_sock_fd(int fd)
{
    struct kstat statbuf;

    if(vfs_fstat(fd, &statbuf) < 0)
        return 0;

    return S_ISSOCK(statbuf.mode);
}

static inline void sk_destroy(struct sock *sk)
{
    sk_common_release(sk);
}

static inline time_t get_fmtime(char *fname)
{
    struct kstat statbuf;

    if (vfs_stat(fname, &statbuf) < 0)
        return 0;

    return statbuf.mtime.tv_sec; 
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)

#if BITS_PER_LONG == 32

static inline pte_t *my_lookup_address(unsigned long address, unsigned int *level/*cummy for compile*/)
{
    pgd_t *pgd = pgd_offset_k(address);
    pud_t *pud;
    pmd_t *pmd;
    if (pgd_none(*pgd))
        return NULL;
    pud = pud_offset(pgd, address);
    if (pud_none(*pud))
        return NULL;
    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd))
        return NULL;
    if (pmd_large(*pmd))
        return (pte_t *)pmd;
    return pte_offset_kernel(pmd, address);
}

#elif BITS_PER_LONG == 64

static inline pte_t *my_lookup_address(unsigned long address, unsigned int *level/*dummy for compile*/)
{
    pgd_t *pgd = pgd_offset_k(address);
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    if (pgd_none(*pgd))
        return NULL;
    pud = pud_offset(pgd, address);
    if (!pud_present(*pud))
        return NULL;
    pmd = pmd_offset(pud, address);
    if (!pmd_present(*pmd))
        return NULL;
    if (pmd_large(*pmd))
        return (pte_t *)pmd;
    pte = pte_offset_kernel(pmd, address);
    if (pte && !pte_present(*pte))
        pte = NULL;
    return pte;
}

#endif

#define lkm_lookup_address my_lookup_address

#else

#define lkm_lookup_address lookup_address

#endif

#define lkm_ptep_val(ptep) (*((unsigned long *)(ptep))) 

static inline void set_page_rw(unsigned long addr) 
{
    unsigned int level;

    pte_t *ptep = lkm_lookup_address(addr, &level);

    if (lkm_ptep_val(ptep) & ~_PAGE_RW) 
        lkm_ptep_val(ptep) |= _PAGE_RW;
}

static inline void set_page_ro(unsigned long addr) 
{
    unsigned int level;

    pte_t *ptep = lkm_lookup_address(addr, &level);

    if (lkm_ptep_val(ptep) & _PAGE_RW)
        lkm_ptep_val(ptep) &= ~_PAGE_RW;
}

static inline void page_protection_disable(unsigned long addr, int pages)
{
    while (pages-- > 0) {
        set_page_rw(addr);
        addr += PAGE_SIZE;
    }
    
    __flush_tlb_all();
}

static inline void page_protection_enable(unsigned long addr, int pages)
{
    while (pages-- > 0) {
        set_page_ro(addr);
        addr += PAGE_SIZE;
    }
    
    __flush_tlb_all();
}

//Usually stand for host based OS.

static inline void page_protection_global_disable(void) 
{
    unsigned long value;

    asm volatile("mov %%cr0,%0" : "=r" (value));

    if (value & 0x10000UL) {
        value &= ~0x10000UL;
        asm volatile("mov %0, %%cr0": : "r" (value));
    }
}

static inline void page_protection_global_enable(void) 
{
    unsigned long value;

    asm volatile("mov %%cr0,%0" : "=r" (value));

    if (!(value & 0x10000UL)) {
        value |= 0x10000UL;
        asm volatile("mov %0, %%cr0": : "r" (value));
    }
}

#endif

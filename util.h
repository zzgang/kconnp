/*
 * The codes of this file is brought from kernel, and changed it to appreciate the lkm
 * 
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/stat.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#include <linux/fdtable.h>
#endif
#include <asm/atomic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>

#define lkmalloc(size) kzalloc(size, GFP_KERNEL)
#define lkmfree(ptr) kfree(ptr)

//#define SOCK_CLIENT_TAG 1 << (sizeof(unsigned long)*8 - 1)

#define SOCK_CLIENT_TAG 0x10000000

#define IS_CLIENT_SOCK(sock) \
    ((sock)->file->f_flags & SOCK_CLIENT_TAG)

#define SET_CLIENT_FLAG(sock)   \
    ((sock)->file->f_flags |= SOCK_CLIENT_TAG)

#define CLEAR_CLIENT_FLAG(sock) \
    ((sock)->file->f_flags &= ~SOCK_CLIENT_TAG)

#define SOCK_ESTABLISHED(sock) \
    ((sock)->sk && (sock)->sk->sk_state == TCP_ESTABLISHED)

#define IS_TCP_SOCK(sock) \
    ((sock)->type == SOCK_STREAM)


#define lkm_atomic_read(v) atomic64_read((atomic64_t *)v) 
#define lkm_atomic_add(v, a) atomic64_add_return(a, (atomic64_t *)v)
#define lkm_atomic_sub(v, a) atomic64_sub_return(a, (atomic64_t *)v)
#define lkm_atomic_set(v, a) atomic64_set_return((atomic64_t *)v, a)

static inline int file_count_read(struct file *filp)
{
    return lkm_atomic_read(&filp->f_count);
}

static inline int file_count_dec(struct file *filp, int c)
{
    return lkm_atomic_sub(&filp->f_count, c);
}

static inline int file_count_inc(struct file *filp, int i)
{
    return lkm_atomic_add(&filp->f_count, i);
}

#define TASK_FILES(tsk) (tsk)->files

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
#define FILE_FDT_TYPE typeof(((struct files_struct *)0)->fdtab)
#define TASK_FILES_FDT(tsk) rcu_dereference(TASK_FILES(tsk)->fdt)
#else  //todo...
#define FILE_FDT_TYPE (struct files_struct *)
#define TASK_FILES_FDT(tsk) TASK_FILES(tsk)
#endif

int task_alloc_fd(struct task_struct *tsk, unsigned start, unsigned flags);

static inline int task_get_unused_fd(struct task_struct *tsk)
{
    return task_alloc_fd(tsk, 0, 0);
}

static inline void task_put_unused_fd(struct task_struct *tsk, unsigned int fd)
{
    struct files_struct *files = TASK_FILES(tsk);
    FILE_FDT_TYPE *fdt = TASK_FILES_FDT(tsk);

    spin_lock(&files->file_lock);
    __FD_CLR(fd, fdt->open_fds);
    if (fd < files->next_fd)
        files->next_fd = fd;
    spin_unlock(&files->file_lock);
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

    filp = rcu_dereference(fdt->fd[fd]);
    if (filp)
        return (struct socket *)filp->private_data;

    return NULL;
}

static inline int getsockservaddr(struct socket *sock, struct sockaddr *address)
{
    int len;
    return sock->ops->getname(sock, address, &len, 1);
}

static inline int is_sock_fd(int fd)
{
    struct kstat statbuf;
    if(vfs_fstat(fd, &statbuf) < 0)
        return 0;
    return S_ISSOCK(statbuf.mode);
}

static inline time_t get_fmtime(char *fname)
{
    struct kstat statbuf;
    if (vfs_stat(fname, &statbuf) < 0)
        return 0;
    return statbuf.mtime.tv_sec; 
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)

static inline void set_page_rw(unsigned long addr) 
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte & ~_PAGE_RW) 
        pte->pte |= _PAGE_RW;
}

static inline void set_page_ro(unsigned long addr) 
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte &= ~_PAGE_RW;
}

#else

static inline void disable_page_protection(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
        value &= ~0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static inline void enable_page_protection(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
        value |= 0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

#endif //end KERNEL_VERSION

#endif

#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/version.h>
#include "sockp.h"
#include "connp.h"
#include "sys_call.h"
#include "lkm_util.h"

static inline int connp_move_addr_to_kernel(void __user *uaddr, int ulen, 
        struct sockaddr *kaddr)
{
    if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
        return -EINVAL;

    if (ulen == 0)
        return 1;

    if (copy_from_user(kaddr, uaddr, ulen)){
        printk(KERN_ERR "move to kernel copy data EFAULT;\n");
        return -EFAULT;
    }

    return 0;
}

#ifdef __NR_socketcall /*32 bits*/
asmlinkage long connp_sys_socketcall(int call, unsigned long __user *args)
{
    unsigned long a[6];
    int err; 

    switch(call) {
        case SYS_CONNECT:
            if (copy_from_user(a, args, 3 * sizeof(a[0]))) {
                printk(KERN_ERR "connect Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_connect(a[0], (struct sockaddr __user *)a[1], a[2]);
            if (err > 0)
                goto orig_sys_socketcall;
            break;

        case SYS_SHUTDOWN:
            if (copy_from_user(a, args, 2 * sizeof(a[0]))){
                printk(KERN_ERR "shutdown Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_shutdown(a[0], a[1]); 
            if (err)
                goto orig_sys_socketcall;
            break;

        case SYS_SEND:
            if (copy_from_user(a, args, 4 * sizeof(a[0]))) {
                printk(KERN_ERR "send Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_send(a[0], (void __user *)a[1], a[2], a[3]);
            if (!err)
                goto orig_sys_socketcall;
            break;

        case SYS_SENDTO:
            if (copy_from_user(a, args, 6 * sizeof(a[0]))) {
                printk(KERN_ERR "sendto Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_sendto(a[0], (void __user *)a[1], a[2], a[3],
                            (struct sockaddr __user *)a[4], a[5]);
            if (!err) 
                goto orig_sys_socketcall;
            break;

        case SYS_RECV:
            if (copy_from_user(a, args, 4 * sizeof(a[0]))) {
                printk(KERN_ERR "recv Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_recv(a[0], (void __user *)a[1], a[2], a[3]);
            if (!err)
                goto orig_sys_socketcall;
            break;

        case SYS_RECVFROM:
            if (copy_from_user(a, args, 6 * sizeof(a[0]))) {
                printk(KERN_ERR "recvfrom Efault!\n");
                return -EFAULT;
            }
            err = socketcall_sys_recvfrom(a[0], (void __user *)a[1], a[2], a[3],
                            (struct sockaddr __user *)a[4], a[5]);
            if (!err)
                goto orig_sys_socketcall;
            break;

        default:
orig_sys_socketcall:
            return jmp_orig_sys_call(orig_sys_socketcall);
            break;
    }

    return err;
}
#endif

inline long socketcall_sys_connect(int fd, 
        struct sockaddr __user * uservaddr, int addrlen) 
{
    struct sockaddr_storage servaddr;
    int err;
     
    err = connp_move_addr_to_kernel(uservaddr, addrlen, (struct sockaddr *)&servaddr);
    if (err < 0)
        return err;
    
    if ((err = fetch_conn_from_connp(fd, (struct sockaddr *)&servaddr))) {
        if (err == CONN_BLOCK)
            return 0;
        else if (err == CONN_NONBLOCK)
            return -EINPROGRESS;
    }
   
    return 1; 
}

asmlinkage long connp_sys_connect(int fd, 
        struct sockaddr __user * uservaddr, int addrlen)
{
    int err;
    err = socketcall_sys_connect(fd, uservaddr, addrlen);
    if (err <= 0) {
        return err;
    }
        
    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_connect);
#else
        jmp_orig_sys_call3(orig_sys_connect, fd, uservaddr, addrlen);
#endif
}

inline long socketcall_sys_shutdown(int fd, int way)
{
    if (connp_fd_allowed(fd))
        return 0;

    return 1;
}

asmlinkage long connp_sys_shutdown(int fd, int way)
{
    int err;
    err = socketcall_sys_shutdown(fd, way);
    if (!err)
        return 0;
    
    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_shutdown);
#else
        jmp_orig_sys_call2(orig_sys_shutdown, fd, way);  
#endif
}

asmlinkage ssize_t connp_sys_write(int fd, const char __user *buf, size_t count)
{
    if (check_if_ignore_primitives(fd, buf, count))
        return count;

    {
        long cnt = check_if_ignore_auth_procedure(fd, buf, count, 'w');
        if (cnt) 
            return cnt;
    }

    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_write);
#else 
        jmp_orig_sys_call3(orig_sys_write, fd, buf, count);
#endif
}

asmlinkage ssize_t connp_sys_read(int fd, const char __user *buf, size_t count)
{
    long cnt;
    cnt = check_if_ignore_auth_procedure(fd, buf, count, 'r');
    if (cnt)
        return cnt;

    return 
#if BITS_PER_LONG == 32 
        jmp_orig_sys_call(orig_sys_read);
#else
        jmp_orig_sys_call3(orig_sys_read, fd, buf, count);
#endif
}

#ifdef __NR_socketcall
asmlinkage long socketcall_sys_send(int sockfd, const void __user *buf, size_t len, int flags)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;
    
    {
        long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'w');
        if (cnt) 
            return cnt;
    }

    return 0;
}

asmlinkage long socketcall_sys_recv(int sockfd, const void __user *buf, size_t len, int flags)
{
    long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'r');
    if (cnt) 
        return cnt;

    return 0;
}
#endif

inline long socketcall_sys_sendto(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *dest_addr, int addrlen)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;

    {
        long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'w');
        if (cnt) 
            return cnt;
    }

    return 0;
}


asmlinkage long connp_sys_sendto(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *dest_addr, int addrlen)
{
    int err;
    err = socketcall_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (err) 
        return err;

    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_sendto);
#else
        jmp_orig_sys_call6(orig_sys_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
#endif
}

inline ssize_t socketcall_sys_recvfrom(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *src_addr, int addrlen)
{
    long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'r');
    if (cnt) 
        return cnt;

    return 0;
}


asmlinkage ssize_t connp_sys_recvfrom(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *src_addr, int addrlen)
{
    int err;
    err = socketcall_sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (err) 
        return err;

    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_recvfrom);
#else
        jmp_orig_sys_call6(orig_sys_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
#endif
}

asmlinkage long connp_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
                            long timeout_msecs)
{
    if (nfds == 1) {
        struct pollfd pfd;
        u32 retcnt;
        if (copy_from_user(&pfd, ufds, sizeof(struct pollfd)))
            goto orig_poll;

        if (!(pfd.events & POLLIN)) 
            goto orig_poll;

        retcnt = check_if_ignore_auth_procedure(pfd.fd, NULL, 0, 'i'); //POLLIN
        if (retcnt) {
            pfd.revents &= POLLIN;
            if (__put_user(pfd, ufds))
                goto orig_poll;

            return 1;
        }
    }

orig_poll:
    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_poll);
#else
        jmp_orig_sys_call3(orig_sys_poll, ufds, nfds, timeout_msecs);
#endif
}

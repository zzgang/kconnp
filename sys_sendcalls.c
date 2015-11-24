#include "sys_call.h"
#include "lkm_util.h"
#include "connp.h"

asmlinkage ssize_t connp_sys_write(int fd, const char __user * buf, size_t count)
{
    if (check_if_ignore_primitives(fd, buf, count))
        return count;

    return orig_sys_write(fd, buf, count); 
}

#ifdef __NR_socketcall
asmlinkage long connp_sys_send(int sockfd, const void __user * buf, size_t len, int flags)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;

    return orig_sys_send(sockfd, buf, len, flags);
}
#endif

asmlinkage long connp_sys_sendto(int sockfd, const void __user * buf, size_t len, 
                int flags, const struct sockaddr __user * dest_addr, int addrlen)
{
    if (check_if_ignore_primitives(sockfd, buf, len))
        return len;

    return orig_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

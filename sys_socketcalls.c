#include <asm/uaccess.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/version.h>
#include "sockp.h"
#include "connp.h"
#include "sys_call.h"
#include "util.h"

static inline int connp_move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
    if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
        return -EINVAL;

    if (ulen == 0)
        return 0;

    if (copy_from_user(kaddr, uaddr, ulen))
        return -EFAULT;

    return 0;
}

#ifdef __NR_socketcall /*32 bits*/
asmlinkage long connp_sys_socketcall(int call, unsigned long __user *args)
{
    unsigned long a[6];
    int err;
    
    switch(call) {
        case SYS_CONNECT:
            if (copy_from_user(a, args, 3 * sizeof(a[0])))
                return -EFAULT;
            err = connp_sys_connect(a[0], (struct sockaddr __user *)a[1], a[2]);
            break;
        case SYS_SHUTDOWN:
            if (copy_from_user(a, args, 2 * sizeof(a[0])))
                return -EFAULT;
            err = connp_sys_shutdown(a[0], a[1]); 
            break;
        default:
            //Calculate the stack size in this function to clean it and jmp orig_sys_socketcall directly.
            asm volatile(".align 4\n\t"
                    "movl %%esp, %%eax\n\t"
                    "movl $0x0, %%ecx\n\t"
                    "movl %2, %%ebx\n\t"
                    "movl %3, %%edx\n\t"
                    "1:addl $0x4, %%ecx\n\t"
                    "addl $0x4, %%eax\n\t"
                    "cmpl (%%eax), %%ebx\n\t"
                    "jne 1b\n\t"
                    "cmpl 0x4(%%eax), %%edx\n\t"
                    "je 2f\n\t"
                    "jmp 1b\n\t"
                    "2:subl $0x4, %%ecx\n\t"
                    "addl %%ecx, %%esp\n\t" //clean the stack in this function.
                    "movl %%esp, %%ecx\n\t"
                    "subl $0x4, %%ecx\n\t" //%esp - $0x4
                    "cmpl %%ecx, %%ebp\n\t" //check if using %ebp.
                    "jne 3f\n\t"
                    "mov -0x4(%%esp), %%ebp\n\t" //pop %ebp
                    "3:jmp *%1\n\t" //change eip to orig_sys_socketcall directly.
                    :"=a"(err) //dummy for no compile warning.
                    :"m"(orig_sys_socketcall), "m"(call), "m"(args));
            break;
    }

    return err;
}
#endif

asmlinkage long connp_sys_connect(int fd, struct sockaddr __user * uservaddr, 
        int addrlen)
{
    struct sockaddr_storage address;
    int err;

    err = connp_move_addr_to_kernel(uservaddr, addrlen, (struct sockaddr *)&address);
    if (err < 0)
        return -EFAULT;

    if (fetch_conn_from_connp(fd, (struct sockaddr *)&address))
        return 0;

    return orig_sys_connect(fd, uservaddr, addrlen);
}

asmlinkage long connp_sys_shutdown(int fd, int way)
{
    if (insert_into_connp_if_permitted(fd)) 
        return orig_sys_close(fd); //only remove the fd of the file table.
    else
        return orig_sys_shutdown(fd, way);
}

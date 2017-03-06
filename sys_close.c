#include "sys_call.h"
#include "connp.h"
#include "lkm_util.h"

asmlinkage long connp_sys_close(int fd)
{
    insert_into_connp_if_permitted(fd);

    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_close);
#else 
        jmp_orig_sys_call1(orig_sys_close, fd);
#endif
}

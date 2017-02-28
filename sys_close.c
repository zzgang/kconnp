#include "sys_call.h"
#include "connp.h"
#include "lkm_util.h"

asmlinkage long connp_sys_close(int fd)
{
    insert_into_connp_if_permitted(fd);

    return jmp_orig_sys_call(orig_sys_close, ASM_INSTRUCTION);
}

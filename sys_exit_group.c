#include "sys_call.h"
#include "connp.h"
#include "lkm_util.h"

asmlinkage long connp_sys_exit_group(int error_code)
{
    SYS_CALL_START();
    if (INVOKED_BY_TGROUP_LEADER())   //Must be thread group leader!
        connp_sys_exit_prepare();

    return jmp_orig_sys_call(orig_sys_exit_group, ASM_INSTRUCTION);
}

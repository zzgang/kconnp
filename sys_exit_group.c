#include "sys_call.h"
#include "connp.h"
#include "lkm_util.h"

asmlinkage long connp_sys_exit_group(int error_code)
{
    if (INVOKED_BY_TGROUP_LEADER())   //Must be thread group leader!
        connp_sys_exit_prepare();

    return 
#if BITS_PER_LONG == 32
        jmp_orig_sys_call(orig_sys_exit_group);
#else
        jmp_orig_sys_call1(orig_sys_exit_group, error_code);
#endif
}

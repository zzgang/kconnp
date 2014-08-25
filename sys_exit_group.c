#include "sys_call.h"
#include "connp.h"
#include "lkm_util.h"

asmlinkage long connp_sys_exit_group(int error_code)
{
    if (INVOKED_BY_TGROUP_LEADER())   //Must be thread group leader!
        connp_sys_exit_prepare();

    return orig_sys_exit_group(error_code); 
}

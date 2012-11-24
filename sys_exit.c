#include "sys_call.h"
#include "connp.h"
asmlinkage long connp_sys_exit(int error_code)
{
    connp_sys_exit_prepare();
    return orig_sys_exit(error_code); 
}

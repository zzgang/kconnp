#include "sys_call.h"
#include "connp.h"
#include "util.h"

asmlinkage long connp_sys_close(int fd)
{
    insert_into_connp_if_permitted(fd);
    return orig_sys_close(fd);  
}

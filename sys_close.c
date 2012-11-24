#include "sys_call.h"
#include "connp.h"
#include "util.h"

asmlinkage long connp_sys_close(int fd)
{
    if (fd == -1) 
        return scan_connp_shutdown_timeout();
    insert_into_connp_if_permitted(fd);
    return orig_sys_close(fd);  
}

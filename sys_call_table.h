#ifndef _SYS_CALL_TABLE_H
#define _SYS_CALL_TABLE_H

#include "sys_call_table_ea.h"

//get sys call table's effective address in the kernel.
static inline unsigned long  get_syscall_table_ea(void)
{
    return SYS_CALL_TABLE_EA;
}

#endif

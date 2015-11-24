#include <linux/syscalls.h>
#include "sys_call_table.h"
#include "sys_call.h"
#include "lkm_util.h"

/*original sys calls*/
#ifdef __NR_socketcall
sys_socketcall_func_ptr_t orig_sys_socketcall = (void *)SYS_SOCKETCALL_EA;
sys_send_func_ptr_t orig_sys_send = (void *)SYS_SEND_EA;
#endif

sys_connect_func_ptr_t orig_sys_connect = (void *)SYS_CONNECT_EA;
sys_shutdown_func_ptr_t orig_sys_shutdown = (void *)SYS_SHUTDOWN_EA;
sys_close_func_ptr_t orig_sys_close = (void *)SYS_CLOSE_EA;
sys_exit_func_ptr_t orig_sys_exit = (void *)SYS_EXIT_EA;
sys_exit_func_ptr_t orig_sys_exit_group = (void *)SYS_EXIT_GROUP_EA;
sys_write_func_ptr_t orig_sys_write = (void *)SYS_WRITE_EA;
sys_sendto_func_ptr_t orig_sys_sendto = (void *)SYS_SENDTO_EA;

/*new sys calls*/
#ifdef __NR_socketcall
static sys_socketcall_func_ptr_t new_sys_socketcall = connp_sys_socketcall;
#else  //__NR_connect and __NR_shutdown
static sys_connect_func_ptr_t new_sys_connect = connp_sys_connect;
static sys_shutdown_func_ptr_t new_sys_shutdown = connp_sys_shutdown;
static sys_sendto_func_ptr_t new_sys_sendto = connp_sys_sendto;
#endif

static sys_close_func_ptr_t new_sys_close = connp_sys_close;
static sys_exit_func_ptr_t new_sys_exit = connp_sys_exit;
static sys_exit_func_ptr_t new_sys_exit_group = connp_sys_exit_group;
static sys_write_func_ptr_t new_sys_write = connp_sys_write;

static int build_syscall_func_table(unsigned long *sys_call_table, int *nr_min, int *nr_max);

static struct syscall_func_struct syscall_func[] = { //initial.
#ifdef __NR_socketcall //usually for 32 bits.
    {
        .name = "sys_socketcall", 
        .sym_addr = SYS_SOCKETCALL_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_socketcall, 
        .orig_sys_func = (void**)&orig_sys_socketcall
    },
#else
    {
        .name = "sys_connect", 
        .sym_addr = SYS_CONNECT_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_connect, 
        .orig_sys_func = (void**)&orig_sys_connect
    },
    {
        .name = "sys_shutdown", 
        .sym_addr = SYS_SHUTDOWN_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_shutdown, 
        .orig_sys_func = (void **)&orig_sys_shutdown
    },
    {
        .name = "sys_sendto", 
        .sym_addr = SYS_SENDTO_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_sendto, 
        .orig_sys_func = (void **)&orig_sys_sendto
    },
#endif
    {
        .name = "sys_close", 
        .sym_addr = SYS_CLOSE_EA, 
        .real_addr = (unsigned long)sys_close, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_close, 
        .orig_sys_func = (void **)&orig_sys_close
    },
    {
        .name = "sys_exit", 
        .sym_addr = SYS_EXIT_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_exit, 
        .orig_sys_func = (void **)&orig_sys_exit
    },
    {
        .name = "sys_exit_group", 
        .sym_addr = SYS_EXIT_GROUP_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_exit_group, 
        .orig_sys_func = (void **)&orig_sys_exit_group
    },
    {
        .name = "sys_write", 
        .sym_addr = SYS_WRITE_EA, 
        .real_addr = 0, 
        .nr = -1, 
        .new_sys_func = (void **)&new_sys_write, 
        .orig_sys_func = (void **)&orig_sys_write
    },
    {NULL, 0, 0, -1, NULL, NULL} //end tag.
};

static int build_syscall_func_table(unsigned long *sys_call_table, int *nr_min, int *nr_max)
{
    struct syscall_func_struct *p;
    int i;

    for (p = syscall_func; p->name; p++) {
        if (p->real_addr && (p->real_addr != p->sym_addr)) {//check symbol map addr.
            printk(KERN_ERR "Current kernel is ambiguous!"); 
            return 0;
        }
        for (i = 0;  i < MAX_SYS_CALL_NUM; i++) 
            if (sys_call_table[i] == p->sym_addr) {//match the symbol map addr.
                p->nr = i;
                *p->orig_sys_func = (void *)sys_call_table[i]; //reassign.
                break;
            }
        
        if (i >= MAX_SYS_CALL_NUM) {
            printk(KERN_ERR "Can't find the sys call \"%s\", consider enlarging the macro MAX_SYS_CALL_NUM", p->name); 
            return 0;
        }

        if (*nr_min > p->nr)
           *nr_min = p->nr;

        if (*nr_max < p->nr) 
           *nr_max = p->nr; 
    }

    return 1;
}

/**
 *@brief set syscall table.
 *@param flag: 0: replace 1: restore
 */
int connp_set_syscall(int flag)
{
    struct syscall_func_struct *p;
    unsigned long * sys_call_table;
    static int sys_call_span_pages, nr_min, nr_max;

    *(unsigned long *)&sys_call_table = get_syscall_table_ea();

    if (flag & SYSCALL_REPLACE) { //init.
        if (!build_syscall_func_table((unsigned long *)sys_call_table, 
            &nr_min, &nr_max)) {
            return 0;
        }
        sys_call_span_pages = (((unsigned long)&sys_call_table[nr_max] >> PAGE_SHIFT) - ((unsigned long)&sys_call_table[nr_min] >> PAGE_SHIFT)) + 1;
    }

    preempt_disable();

    page_protection_disable((unsigned long)&sys_call_table[nr_min], sys_call_span_pages);

    for (p = syscall_func; p->name; p++) {
        if (flag & SYSCALL_REPLACE) { //Replace
            xchg(&sys_call_table[p->nr], (unsigned long)*p->new_sys_func);
            printk(KERN_INFO "Replace %s: nr %d, addr %p", p->name, p->nr, *p->new_sys_func);
        } else if (flag & SYSCALL_RESTORE) { //Restore
            xchg(&sys_call_table[p->nr], (unsigned long)*p->orig_sys_func);
            printk(KERN_INFO "Restore %s: nr %d, addr %p", p->name, p->nr, *p->orig_sys_func);
        }
    }

    page_protection_enable((unsigned long)&sys_call_table[nr_min], sys_call_span_pages);
    
    preempt_enable();

    return 1;
}

#ifndef _SYS_CALL_H
#define _SYS_CALL_H

#include <linux/linkage.h>
#include <linux/socket.h>
#include <linux/unistd.h>

#define SYSCALL_REPLACE (1 << 0)
#define SYSCALL_RESTORE (1 << 1)

#define replace_syscalls() connp_set_syscall(SYSCALL_REPLACE)
#define restore_syscalls() connp_set_syscall(SYSCALL_RESTORE)

#define MAX_SYS_CALL_NUM 2048

struct syscall_func_struct {
    char *name; //sys call name.
    unsigned long sym_addr; // Get from symbol map file.
    unsigned long real_addr; //Get from kernel symbol table.
    int nr; //sys call nr
    void ** new_sys_func;
    void ** orig_sys_func;
};

extern int connp_set_syscall(int flag);

typedef asmlinkage long (*sys_connect_func_ptr_t)(int fd, struct sockaddr __user *, int addrlen);
typedef asmlinkage long (*sys_shutdown_func_ptr_t)(int fd, int way);
typedef asmlinkage long (*sys_close_func_ptr_t)(int fd);
typedef asmlinkage long (*sys_exit_func_ptr_t)(int error_code);

extern sys_connect_func_ptr_t orig_sys_connect;
extern sys_shutdown_func_ptr_t orig_sys_shutdown;
extern sys_close_func_ptr_t orig_sys_close;
extern sys_exit_func_ptr_t orig_sys_exit;
extern sys_exit_func_ptr_t orig_sys_exit_group;

#ifdef __NR_socketcall
typedef asmlinkage long (*sys_socketcall_func_ptr_t)(int call, unsigned long __user *args);
extern sys_socketcall_func_ptr_t orig_sys_socketcall;
#endif

asmlinkage long connp_sys_connect(int fd, struct sockaddr __user *, int addrlen);
asmlinkage long connp_sys_shutdown(int fd, int way);
asmlinkage long connp_sys_close(int fd);
asmlinkage long connp_sys_exit(int error_code);
asmlinkage long connp_sys_exit_group(int error_code);
#ifdef __NR_socketcall
asmlinkage long connp_sys_socketcall(int call, unsigned long __user *args);
#endif

#endif

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
typedef asmlinkage ssize_t (*sys_write_func_ptr_t)(int fd, const char __user * buf, size_t count);
typedef asmlinkage long (*sys_sendto_func_ptr_t)(int sockfd, const void __user * buf, size_t len, int flags, const struct sockaddr __user * addr, int addrlen);

extern sys_connect_func_ptr_t orig_sys_connect;
extern sys_shutdown_func_ptr_t orig_sys_shutdown;
extern sys_close_func_ptr_t orig_sys_close;
extern sys_exit_func_ptr_t orig_sys_exit;
extern sys_exit_func_ptr_t orig_sys_exit_group;
extern sys_write_func_ptr_t orig_sys_write;
extern sys_sendto_func_ptr_t orig_sys_sendto;

#ifdef __NR_socketcall
typedef asmlinkage long (*sys_socketcall_func_ptr_t)(int call, unsigned long __user *args);
typedef asmlinkage long (*sys_send_func_ptr_t)(int sockfd, const void __user * buf, size_t len, int flags);
extern sys_socketcall_func_ptr_t orig_sys_socketcall;
extern sys_send_func_ptr_t orig_sys_send;
#endif

asmlinkage long connp_sys_connect(int fd, struct sockaddr __user *, int addrlen);
asmlinkage long connp_sys_shutdown(int fd, int way);
asmlinkage long connp_sys_close(int fd);
asmlinkage long connp_sys_exit(int error_code);
asmlinkage long connp_sys_exit_group(int error_code);
asmlinkage ssize_t connp_sys_write(int fd, const char __user * buf, size_t count);
asmlinkage long connp_sys_sendto(int sockfd, const void __user * buf, size_t len, int flags, const struct sockaddr __user * dest_addr, int addrlen);

#ifdef __NR_socketcall
asmlinkage long connp_sys_socketcall(int call, unsigned long __user *args);
asmlinkage long connp_sys_send(int sockfd, const void __user * buf, size_t len, int flags);
#endif

#endif

#ifndef SYS_CALL_H
#define SYS_CALL_H

#include <linux/linkage.h>
#include <linux/socket.h>
#include <linux/unistd.h>
#include "sockp.h"

#define SYSCALL_REPLACE (1 << 0)
#define SYSCALL_RESTORE (1 << 1)

#define replace_syscalls() connp_set_syscall(SYSCALL_REPLACE)
#define restore_syscalls() connp_set_syscall(SYSCALL_RESTORE)

#define MAX_SYS_CALL_NUM 2048

struct pollfd; 

struct syscall_func_struct {
    char *name; //sys call name.
    unsigned long sym_addr; // Get from symbol map file.
    unsigned long real_addr; //Get from kernel symbol table.
    int nr; //sys call nr
    void ** new_sys_func;
    void ** orig_sys_func;
};

extern int connp_set_syscall(int flag);

typedef asmlinkage  long (*sys_connect_func_ptr_t)(int fd, struct sockaddr __user *, int addrlen);
typedef asmlinkage long (*sys_shutdown_func_ptr_t)(int fd, int way);
typedef asmlinkage long (*sys_close_func_ptr_t)(int fd);
typedef asmlinkage long (*sys_exit_func_ptr_t)(int error_code);

typedef asmlinkage ssize_t (*sys_write_func_ptr_t)(int fd, const char __user *buf, size_t count);
typedef asmlinkage ssize_t (*sys_sendto_func_ptr_t)(int sockfd, const void __user *buf, size_t len, int flags, const struct sockaddr __user *addr, int addrlen);

typedef asmlinkage ssize_t (*sys_read_func_ptr_t)(int fd, const char __user *buf, size_t count);
typedef asmlinkage ssize_t (*sys_recvfrom_func_ptr_t)(int sockfd, const void __user *buf, size_t len, int flags, const struct sockaddr __user *addr, int addrlen);
typedef asmlinkage long (*sys_poll_func_ptr_t)(struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs);

extern sys_connect_func_ptr_t orig_sys_connect;
extern sys_shutdown_func_ptr_t orig_sys_shutdown;
extern sys_close_func_ptr_t orig_sys_close;
extern sys_exit_func_ptr_t orig_sys_exit;
extern sys_exit_func_ptr_t orig_sys_exit_group;
extern sys_write_func_ptr_t orig_sys_write;
extern sys_sendto_func_ptr_t orig_sys_sendto;
extern sys_read_func_ptr_t orig_sys_read;
extern sys_recvfrom_func_ptr_t orig_sys_recvfrom;
extern sys_poll_func_ptr_t orig_sys_poll;

#ifdef __NR_socketcall
typedef asmlinkage long (*sys_socketcall_func_ptr_t)(int call, unsigned long __user *args);
typedef asmlinkage long (*sys_send_func_ptr_t)(int sockfd, const void __user * buf, size_t len, int flags);
typedef asmlinkage long (*sys_recv_func_ptr_t)(int sockfd, const void __user * buf, size_t len, int flags);
extern sys_socketcall_func_ptr_t orig_sys_socketcall;
extern sys_send_func_ptr_t orig_sys_send;
extern sys_recv_func_ptr_t orig_sys_recv;
#endif

extern asmlinkage long connp_sys_connect(int fd, struct sockaddr __user *, int addrlen);
extern asmlinkage long connp_sys_shutdown(int fd, int way);
extern asmlinkage long connp_sys_close(int fd);
extern asmlinkage long connp_sys_exit(int error_code);
extern asmlinkage long connp_sys_exit_group(int error_code);
extern asmlinkage ssize_t connp_sys_write(int fd, const char __user * buf, size_t count);
extern asmlinkage long connp_sys_sendto(int sockfd, const void __user * buf, size_t len, int flags, const struct sockaddr __user * dest_addr, int addrlen);
extern asmlinkage ssize_t connp_sys_read(int fd, const char __user *buf, size_t count);
extern asmlinkage ssize_t connp_sys_recvfrom(int sockfd, const void __user *buf, size_t len, int flags, const struct sockaddr __user *addr, int addrlen);
extern asmlinkage long connp_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
                    long timeout_msecs);

#ifdef __NR_socketcall
extern asmlinkage long connp_sys_socketcall(int call, unsigned long __user *args);
extern asmlinkage long socketcall_sys_send(int sockfd, const void __user * buf, size_t len, int flags);
extern asmlinkage long socketcall_sys_recv(int sockfd, const void __user * buf, size_t len, int flags);
#endif

extern long socketcall_sys_connect(int fd, struct sockaddr __user *, int addrlen);
extern long socketcall_sys_sendto(int sockfd, const void __user * buf, size_t len, int flags, const struct sockaddr __user * dest_addr, int addrlen);
extern ssize_t socketcall_sys_recvfrom(int sockfd, const void __user *buf, size_t len, int flags, const struct sockaddr __user *addr, int addrlen);
extern long socketcall_sys_shutdown(int fd, int way);
extern int socketcall_move_addr_to_kernel(void __user *uaddr, int ulen, 
                struct sockaddr *kaddr);

#endif

#ifndef __SYS_CALL_H
#define __SYS_CALL_H

#include <linux/linkage.h>
#include <linux/socket.h>
#include <linux/unistd.h>

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

typedef asmlinkage long (*sys_connect_func_ptr_t)(int fd, struct sockaddr __user *, int addrlen);
typedef asmlinkage long (*sys_shutdown_func_ptr_t)(int fd, int way);
typedef asmlinkage long (*sys_close_func_ptr_t)(int fd);
typedef asmlinkage long (*sys_exit_func_ptr_t)(int error_code);

typedef asmlinkage ssize_t (*sys_write_func_ptr_t)(int fd, const char __user *buf, size_t count);
typedef asmlinkage ssize_t (*sys_sendto_func_ptr_t)(int sockfd, const void __user *buf, size_t len, int flags, const struct sockaddr __user *addr, int addrlen);

typedef asmlinkage ssize_t (*sys_read_func_ptr_t)(int fd, const char __user *buf, size_t count);
typedef asmlinkage ssize_t (*sys_recvfrom_func_ptr_t)(int sockfd, const void __user *buf, ssize_t len, int flags, const struct sockaddr __user *addr, int addrlen);
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
extern asmlinkage long connp_sys_send(int sockfd, const void __user * buf, size_t len, int flags);
extern asmlinkage long connp_sys_recv(int sockfd, const void __user * buf, size_t len, int flags);
#endif

#if BITS_PER_LONG == 32

#define AX %%eax
#define BX %%ebx
#define CX %%ecx
#define DX %%edx
#define SI %%esi
#define DI %%edi
#define SP %%esp
#define BP %%ebp

#else /*64 bits*/

#define AX %%rax
#define BX %%rbx
#define CX %%rcx
#define DX %%rdx
#define SI %%rsi
#define DI %%rdi
#define SP %%rsp
#define BP %%rbp

#endif

#define ASM_INSTRUCTION  \
         push AX; \
         push DX;   \
         push CX;  \
         push SI;  \
         push DI; \
         mov %0, AX; \
         mov BP, CX;    \
         sub SP, CX;    \
         sar %2, CX;      \
         add $0x1, CX;      \
         mov SP, SI;    \
         mov SP, DI;    \
         sub %1, DI;     \
         s_%=:mov (SI), DX;  \
         mov DX, (DI);        \
         add %1, SI;       \
         add %1, DI;     \
         loop s_%=;               \
         mov AX, (BP);         \
         sub %1, SP;         \
         sub %1, BP;         \
         pop DI;           \
         pop SI;           \
         pop CX;           \
         pop DX;            \
         pop AX;           \
 

#define jmp_orig_call_pass(orig_sys_call, ...)    \
    ({                            \
     asm volatile(#__VA_ARGS__       \
         :                       \
         :"m"(orig_sys_call), "i"(sizeof(long)), "i"(sizeof(long)/2));   \
     0;})

#define jmp_orig_sys_call(orig_sys_call, asm_instruction) \
    jmp_orig_call_pass(orig_sys_call, asm_instruction)

#endif

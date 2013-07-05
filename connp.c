#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/spinlock.h>
#include "sys_call.h"
#include "util.h"
#include "cfg.h"
#include "sockp.h"
#include "connp.h"
#include "connpd.h"
#include "preconnect.h"

static inline void do_close_timeout_pending_fds(void);
static int insert_socket_to_connp(struct sockaddr *, struct socket *);
static int insert_into_connp(struct sockaddr *, struct socket *);
static inline int sock_remap_fd(int fd, struct socket *, struct socket *);

static int close_pending_fds_init(void);
static inline int close_pending_fds_is_empty(void);
static inline int close_pending_fds_is_full(void);

static struct {
    int fds[NR_SOCKET_CLOSE_PENDING];
    int current_idx;
    spinlock_t fds_lock;
} close_pending_fds;

static int close_pending_fds_init()
{
    spin_lock_init(&close_pending_fds.fds_lock);
    return 1;
}

static inline int close_pending_fds_is_empty()
{
    return close_pending_fds.current_idx == 0;
}

static inline int close_pending_fds_is_full()
{
    return close_pending_fds.current_idx == (sizeof(close_pending_fds.fds) / sizeof(close_pending_fds.fds[0]));
}

int close_pending_fds_push(int fd)
{
    spin_lock(&close_pending_fds.fds_lock);

    if (close_pending_fds_is_full()) {
        spin_unlock(&close_pending_fds.fds_lock);
        return -1;
    }

    close_pending_fds.fds[close_pending_fds.current_idx++] = fd;

    spin_unlock(&close_pending_fds.fds_lock);

    return fd;
}

int close_pending_fds_pop(void)
{
    int fd = -1;

    spin_lock(&close_pending_fds.fds_lock);

    if (close_pending_fds_is_empty())
        goto out_unlock;

    fd = close_pending_fds.fds[--close_pending_fds.current_idx];

out_unlock:
    spin_unlock(&close_pending_fds.fds_lock);
    return fd;
}

static int insert_socket_to_connp(struct sockaddr *servaddr, struct socket *sock)
{
    int connpd_fd;

    connpd_fd = task_get_unused_fd(CONNP_DAEMON_TSKP);
    if (connpd_fd < 0)
        return 0;

    task_fd_install(CONNP_DAEMON_TSKP, connpd_fd, sock->file);
    file_count_inc(sock->file, 1); //add file reference count.

    if (!insert_socket_to_sockp(servaddr, sock, connpd_fd, SOCK_RECLAIM)) {
        close_pending_fds_push(connpd_fd);
        return 0;
    }

    /*Notify connpd to poll in time.*/
    notify(CONNP_DAEMON_TSKP);

    return 1;
}

static int insert_into_connp(struct sockaddr *servaddr, struct socket *sock)
{
    int fc;

    fc = file_count_read(sock->file);

    if (fc == 1 && insert_socket_to_connp(servaddr, sock))
        return 1;

    if (fc == 2 && free_socket_to_sockp(servaddr, sock)) 
        return 1;

    return 0;
}

int insert_into_connp_if_permitted(int fd)
{
    struct socket *sock;
    struct sockaddr address;
    int err;

    connpd_rlock();

    if (!CONNP_DAEMON_EXISTS() || INVOKED_BY_CONNP_DAEMON())
        goto ret_fail;

    if (!is_sock_fd(fd))
        goto ret_fail;

    sock = getsock(fd);
    if (!sock || !IS_TCP_SOCK(sock) || !IS_CLIENT_SOCK(sock) || !SOCK_ESTABLISHED(sock))
        goto ret_fail;

    err = getsockservaddr(sock, &address);
    if (err)
        goto ret_fail;

    if (address.sa_family != AF_INET 
            || IN_LOOPBACK(ntohl(((struct sockaddr_in *)&address)->sin_addr.s_addr))
            || !cfg_conn_is_positive(&address)) 
        goto ret_fail;

    connpd_runlock();

    return insert_into_connp(&address, sock);

ret_fail:
    connpd_runlock();
    return 0;
}

/**
 *Destory the new alloc socket and map the sockd's socket.
 */
static inline int sock_remap_fd(int fd, struct socket *new_sock, struct socket *old_sock)
{
    fput(old_sock->file); //close file and socket.
    task_fd_install(current, fd, new_sock->file);
    file_count_inc(new_sock->file, 1); //add file reference count;

    return 1;
}

int fetch_conn_from_connp(int fd, struct sockaddr *address)
{
    struct socket *sock, *sock_new;
    int ret = 0; 

    connpd_rlock(); 

    if (!CONNP_DAEMON_EXISTS()) {
        ret = 0;
        goto ret_unlock;
    }

    if (address->sa_family != AF_INET
            || IN_LOOPBACK(ntohl(((struct sockaddr_in *)address)->sin_addr.s_addr))
            || !cfg_conn_acl_allowd(address)) {
        ret = 0;
        goto ret_unlock;
    }

    if (!is_sock_fd(fd)) {
        ret = 0;
        goto ret_unlock;
    }

    sock = getsock(fd);
    if (!sock || !IS_TCP_SOCK(sock)) {
        ret = 0;
        goto ret_unlock;
    }

    if ((sock_new = apply_socket_from_sockp(address)))
        if (sock_remap_fd(fd, sock_new, sock)) {
            ret = 1;
            goto ret_unlock;
        }

    SET_CLIENT_FLAG(sock);

ret_unlock:
    connpd_runlock();
    return ret;
}

static inline void do_close_timeout_pending_fds()
{
    int fd;

    shutdown_timeout_sock_list();

    while ((fd = close_pending_fds_pop()) >= 0)
        orig_sys_close(fd);

}

/**
 *Wait events of connpd fds or timeout.
 */
static int connp_fds_events_or_timout(void)
{
    struct poll_wqueues table;
    poll_table *pt;
    int events = 0;
    int timed_out = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
    ktime_t expire;
    struct timespec end_time, time_out = {.tv_sec = 1/*second*/, .tv_nsec = 0};

    ktime_get_ts(&end_time);
    end_time = lkm_timespec_add_safe(end_time, time_out);
    expire = timespec_to_ktime(end_time);
#else
    long __timeout = 1000/*miliseconds*/;
#endif

    lkm_poll_initwait(&table);
    pt = &(&table)->pt;

    for (;;) {
        struct fd_entry *pos, *tmp;
        LIST_HEAD(fds_list);

        if (signal_pending(current))
            flush_signals(current);
        
        sockp_get_fds(&fds_list);
        list_for_each_entry_safe(pos, tmp, &fds_list, siblings) {
            if (!events) 
                events = fd_poll(pos->fd, POLLRDHUP|POLLERR|POLLHUP, pt);

            if (events)
                set_pt_qproc(pt, NULL);

            lkmfree(pos);
        }

        set_pt_qproc(pt, NULL); 

        if (events)
            break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
        if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE/*Receive signals*/, 
                    &expire, 0))
            goto break_timeout;
#else
        __timeout = schedule_timeout_interruptible(__timeout);
        if (!__timeout)
            goto break_timeout;
#endif
break_timeout:
        timed_out = 1;
        break;
    }

    lkm_poll_freewait(&table); 

    return events || timed_out;
}

/**
 * Shutdown sockets which are passive closed or expired or LRU replaced.
 * must be executed by connpd.
 */
int scan_connp_shutdown_timeout_or_preconnect()
{
    BUG_ON(!INVOKED_BY_CONNP_DAEMON());

    if (connp_fds_events_or_timout()) {
        do_close_timeout_pending_fds();
        scan_spare_conns_preconnect(); 
    }

    return 0;
}

void connp_sys_exit_prepare()
{
    struct fd_entry *pos, *tmp;

    LIST_HEAD(fds_list);
    TASK_GET_FDS(current, &fds_list);
    list_for_each_entry_safe(pos, tmp, &fds_list, siblings) {
        insert_into_connp_if_permitted(pos->fd);
        lkmfree(pos);
    } 
}

int connp_init()
{
    if (!connpd_start()) {
        printk(KERN_ERR "Error: create connp daemon thread error!\n");
        return 0;
    }

    if (!cfg_init()) {
        cfg_destroy();
        connpd_stop();
        printk(KERN_ERR "Error: cfg_init error!\n");
        return 0;
    }

    if (!sockp_init()) {
        cfg_destroy();
        connpd_stop();
        printk(KERN_ERR "Error: sockp_init error!\n");
        return 0;
    }

    close_pending_fds_init();

    if (!replace_syscalls()) {
        sockp_destroy();
        cfg_destroy();
        connpd_stop();
        printk(KERN_ERR "Error: replace_syscalls error!\n");
        return 0;
    }

    return 1;
}

void connp_destroy()
{
    restore_syscalls();
    connpd_stop();
    sockp_destroy();
    cfg_destroy();
}

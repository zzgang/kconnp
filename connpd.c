#include <linux/kthread.h>
#include "connpd.h"
#include "connp.h"
#include "sockp.h"
#include "sys_call.h"
#include "preconnect.h"
#include "util.h"

#define CONNPD_NAME "kconnpd"
#define CONNP_DAEMON_SET(v) (connp_daemon = (v))


struct task_struct * volatile connp_daemon;

static int connpd_func(void *data);
static int connpd_start(void);
static void connpd_stop(void);

static void connpd_unused_fds_prefetch(void);
static void connpd_unused_fds_put(void);

static int shutdown_timeout_or_preconnect(void);
static int connp_fds_events_or_timout(void);
static void do_close_timeout_pending_fds(void);

static int connpd_unused_fds_init(void);
static inline int connpd_unused_fds_is_empty(void);
static inline int connpd_unused_fds_is_full(void);

static int connpd_close_pending_fds_init(void);
static inline int connpd_close_pending_fds_is_empty(void);
static inline int connpd_close_pending_fds_is_full(void);

static struct {
    int fds[NR_MAX_OPEN_FDS/2];
    int current_idx;
    spinlock_t fds_lock;
} connpd_unused_fds;

static int connpd_unused_fds_init()
{
    spin_lock_init(&connpd_unused_fds.fds_lock);
    return 1;
}

static inline int connpd_unused_fds_is_empty()
{
    return (connpd_unused_fds.current_idx == 0);
}

static inline int connpd_unused_fds_is_full()
{
    return (connpd_unused_fds.current_idx == (NR_MAX_OPEN_FDS/2 - 1));
}

int connpd_unused_fds_push(int fd)
{
    spin_lock(&connpd_unused_fds.fds_lock);

    if (connpd_unused_fds_is_full()) {
        spin_unlock(&connpd_unused_fds.fds_lock);
        return -1;
    }

    connpd_unused_fds.fds[connpd_unused_fds.current_idx++] = fd;

    spin_unlock(&connpd_unused_fds.fds_lock);

    return fd;
}

int connpd_unused_fds_pop(void)
{
    int fd = -1;

    spin_lock(&connpd_unused_fds.fds_lock);

    if (connpd_unused_fds_is_empty())
        goto out_unlock;

    fd = connpd_unused_fds.fds[--connpd_unused_fds.current_idx];

out_unlock:
    spin_unlock(&connpd_unused_fds.fds_lock);
    return fd;
}


static struct {
    int fds[NR_MAX_OPEN_FDS];
    int current_idx;
    spinlock_t fds_lock;
} connpd_close_pending_fds;

static int connpd_close_pending_fds_init()
{
    spin_lock_init(&connpd_close_pending_fds.fds_lock);
    return 1;
}

static inline int connpd_close_pending_fds_is_empty()
{
    return (connpd_close_pending_fds.current_idx == 0);
}

static inline int connpd_close_pending_fds_is_full()
{
    return (connpd_close_pending_fds.current_idx == (NR_MAX_OPEN_FDS - 1));
}

int connpd_close_pending_fds_push(int fd)
{
    spin_lock(&connpd_close_pending_fds.fds_lock);

    if (connpd_close_pending_fds_is_full()) {
        spin_unlock(&connpd_close_pending_fds.fds_lock);
        return -1;
    }

    connpd_close_pending_fds.fds[connpd_close_pending_fds.current_idx++] = fd;

    spin_unlock(&connpd_close_pending_fds.fds_lock);

    return fd;
}

int connpd_close_pending_fds_pop(void)
{
    int fd = -1;

    spin_lock(&connpd_close_pending_fds.fds_lock);

    if (connpd_close_pending_fds_is_empty())
        goto out_unlock;

    fd = connpd_close_pending_fds.fds[--connpd_close_pending_fds.current_idx];

out_unlock:
    spin_unlock(&connpd_close_pending_fds.fds_lock);
    return fd;
}

static void connpd_unused_fds_prefetch()
{
    int fd;

    while ((fd = lkm_get_unused_fd()) >= 0) {
        if (connpd_unused_fds_push(fd) >= 0)
            continue;
        else {
            put_unused_fd(fd);
            break;
        }
    }
}

static void connpd_unused_fds_put()
{
    int fd;

    while ((fd = connpd_unused_fds_pop()) >= 0)
        put_unused_fd(fd);
}

static void do_close_timeout_pending_fds()
{
    int fd;

    shutdown_timeout_sock_list();

    while ((fd = connpd_close_pending_fds_pop()) >= 0)
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
 */
static int shutdown_timeout_or_preconnect()
{
    if (connp_fds_events_or_timout()) {
        do_close_timeout_pending_fds();
        scan_spare_conns_preconnect(); 
    }
    
    return 0;
}

static int connpd_func(void *data)
{
    /*Unblock the NOTIFY_SIG for kernel thread 
      that has invoked the daemonize function*/
    allow_signal(NOTIFY_SIG);
    
    for(;;) {

        if (kthread_should_stop()) {

            connp_wlock();
            CONNP_DAEMON_SET(NULL);
            connp_wunlock();
           
            connpd_unused_fds_put(); 
            do_close_timeout_pending_fds();
            close_all_files();

            break;

        } else {

            connpd_unused_fds_prefetch();
            shutdown_timeout_or_preconnect();

        }

    }

    return 1;
}

/**
 *Create the kconnpd and start it.
 */
static int connpd_start(void)
{
    struct task_struct *ptr;
    
    ptr = kthread_run(connpd_func, NULL, CONNPD_NAME);
    
    if (!IS_ERR(ptr)) 
        CONNP_DAEMON_SET(ptr);
    else 
        printk(KERN_ERR "Create connpd error!\n");

    return IS_ERR(ptr) ? 0 : 1; 
}

/**
 *Stop the kconnpd.
 */
static void connpd_stop(void)
{
    kthread_stop(CONNP_DAEMON_TSKP);
}

int connpd_init()
{
    connpd_unused_fds_init();
    connpd_close_pending_fds_init();

    if (!connpd_start())
        return 0;

    return 1;
}

void connpd_destroy(void)
{
    connpd_stop();
}

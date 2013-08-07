#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include "sys_call.h"
#include "util.h"
#include "array.h"
#include "sockp.h"

/**Poll start**/
struct poll_table_page {
    struct poll_table_page * next;
    struct poll_table_entry * entry;
    struct poll_table_entry entries[0];
};

#define POLL_TABLE_FULL(table) \
    ((unsigned long)((table)->entry+1) > PAGE_SIZE + (unsigned long)(table))

static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
        poll_table *p);

/*
 * Add two timespec values and do a safety check for overflow.
 * It's assumed that both values are valid (>= 0)
 */

#undef TIME_T_MAX
#define TIME_T_MAX (time_t)((1UL << ((sizeof(time_t) << 3) - 1)) - 1)
static inline struct timespec lkm_timespec_add_safe(const struct timespec lhs,
        const struct timespec rhs)
{
    struct timespec res;

    set_normalized_timespec(&res, lhs.tv_sec + rhs.tv_sec,
            lhs.tv_nsec + rhs.tv_nsec);

    if (res.tv_sec < lhs.tv_sec || res.tv_sec < rhs.tv_sec)
        res.tv_sec = TIME_T_MAX;

    return res;
}

static inline void set_pt_qproc(poll_table *pt, void *v)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    pt = NULL;
#else
    pt->_qproc = v;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

static inline void set_pt_key(poll_table *pt, int events)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    pt->key = events;
#else
    pt->_key = events;
#endif
}

#endif

#define lkm_get_file(fd)            \
    ({ struct file * __file;    \
     rcu_read_lock();       \
     __file = fcheck_files(TASK_FILES(current), fd); \
     rcu_read_unlock(); \
     __file;})

#undef DEFAULT_POLLMASK
#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

static int inline do_poll(struct pollfd *pfd, poll_table *pwait)
{
    unsigned int mask;
    int events;
    int fd;

    fd = pfd->fd;
    events = pfd->events;
    mask = 0;
    if (fd >= 0) {
        struct file * file;
        struct pollfd_ex_t *pfdt;
        struct socket_bucket *sb;

        file = lkm_get_file(fd); /*Needn't add f_count*/

        mask = POLLNVAL;

        if (file != NULL) {
            mask = DEFAULT_POLLMASK;

            events = events|POLLERR|POLLHUP;

            if (file->f_op && file->f_op->poll) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
                if (pwait)
                    set_pt_key(pwait, events);
#endif

                pfdt = container_of(pfd, struct pollfd_ex_t, pollfd); 

                sb = (struct socket_bucket *)(pfdt->data);

                spin_lock(&sb->s_lock);
                if (sb->sock->sk)
                    mask = file->f_op->poll(file, pwait);
                spin_unlock(&sb->s_lock);

            }

            /* Mask out unneeded events. */
            mask &= events;
        }
    }

    return mask;
}

static void lkm_poll_initwait(struct poll_wqueues *pwq)
{
    init_poll_funcptr(&pwq->pt, __pollwait);
    pwq->error = 0;
    pwq->table = NULL;
    pwq->inline_index = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
    pwq->polling_task = current;
    pwq->triggered = 0;
#endif
}

static inline void free_poll_entry(struct poll_table_entry *entry)
{
    remove_wait_queue(entry->wait_address, &entry->wait);
}

static void lkm_poll_freewait(struct poll_wqueues *pwq)
{
    struct poll_table_page * p = pwq->table;
    int i;

    for (i = 0; i < pwq->inline_index; i++)
        free_poll_entry(pwq->inline_entries + i);

    while (p) {
        struct poll_table_entry * entry;
        struct poll_table_page *old;

        entry = p->entry;
        do {
            entry--;
            free_poll_entry(entry);
        } while (entry > p->entries);
        old = p;
        p = p->next;
        free_page((unsigned long) old);
    }
}

static struct poll_table_entry *poll_get_entry(struct poll_wqueues *p)
{
    struct poll_table_page *table = p->table;

    if (p->inline_index < N_INLINE_POLL_ENTRIES)
        return p->inline_entries + p->inline_index++;

    if (!table || POLL_TABLE_FULL(table)) {
        struct poll_table_page *new_table;

        new_table = (struct poll_table_page *) __get_free_page(GFP_ATOMIC);
        if (!new_table) {
            p->error = -ENOMEM;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
            __set_current_state(TASK_RUNNING);
#endif
            return NULL;
        }
        new_table->entry = new_table->entries;
        new_table->next = table;
        p->table = new_table;
        table = new_table;
    }

    return table->entry++;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
static int __pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
    struct poll_wqueues *pwq = wait->private;
    DECLARE_WAITQUEUE(dummy_wait, pwq->polling_task);

    smp_wmb();
    pwq->triggered = 1;

    return default_wake_function(&dummy_wait, mode, sync, key);
}

static int pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
    struct poll_table_entry *entry;

    entry = container_of(wait, struct poll_table_entry, wait);
    if (key && !((unsigned long)key & entry->key))
        return 0;
#endif

    return __pollwake(wait, mode, sync, key);
}
#endif

/* Add a new entry */
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
        poll_table *p)
{
    struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
    struct poll_table_entry *entry = poll_get_entry(pwq);

    if (!entry)
        return;

    entry->filp = filp;
    entry->wait_address = wait_address;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 2, 45)
    entry->key = p->key;
#else
    entry->key = p->_key;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
    init_waitqueue_func_entry(&entry->wait, pollwake);
    entry->wait.private = pwq;
#else 
    init_waitqueue_entry(&entry->wait, current);
#endif

    add_wait_queue(wait_address, &entry->wait);
}

int lkm_poll(array_t *list, int sec)
{
    struct poll_wqueues table;
    poll_table *pt;
    int count = 0;
    int timed_out = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)

    ktime_t expire;
    struct timespec end_time, time_out = {.tv_sec = sec/*second*/, .tv_nsec = 0};

    ktime_get_ts(&end_time);
    end_time = lkm_timespec_add_safe(end_time, time_out);
    expire = timespec_to_ktime(end_time);

#else

    long __timeout = sec * HZ;

#endif

    lkm_poll_initwait(&table);
    pt = &(&table)->pt;

    for (;;) {
        int idx;

        if (!(list))
            goto ignore_poll;

        for (idx = 0; idx < (list)->elements; idx++) {
            struct pollfd_ex_t *pfdt;
            struct pollfd *pfd;

            pfdt = (struct pollfd_ex_t *)(list)->get(list, idx);

            pfd = (struct pollfd *)&pfdt->pollfd;

            pfd->revents = do_poll(pfd, pt);

            if (pfd->revents) {

                count++;
                set_pt_qproc(pt, NULL);

            }

        }

ignore_poll:

        set_pt_qproc(pt, NULL); 

        if (!count) {
            if (signal_pending(current)) {
                count = -EINTR;
                flush_signals(current);
            }
        }

        if (count || timed_out)
            break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
        if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE/*Receive signals*/, 
                    &expire, 0))
            timed_out = 1;
#else
        __timeout = schedule_timeout_interruptible(__timeout);
        if (!__timeout)
            timed_out = 1;
#endif
    }

    lkm_poll_freewait(&table); 

    return count;
}
/**Poll END**/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 10)
static int sock_map_fd(struct socket *sock, int flags)
{
    struct file *newfile;
    int fd;

    fd = get_unused_fd_flags(flags);
    if (unlikely(fd < 0))
        return fd;

    newfile = sock_alloc_file(sock, flags, NULL);
    if (likely(!IS_ERR(newfile))) {
        fd_install(fd, newfile);
        return fd;
    }

    put_unused_fd(fd);
    return PTR_ERR(newfile);
}
#endif

int lkm_create_tcp_connect(struct sockaddr_in *address)
{
    int fd;
    struct socket *sock;
    int err;

    fd = sock_create(address->sin_family, SOCK_STREAM, 0, &sock);
    if (fd < 0)
        return fd;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
    fd = sock_map_fd(sock);
#else
    fd = sock_map_fd(sock, 0);
#endif
    if (fd < 0) {
        sock_release(sock);
        return fd;
    }

    sock->file->f_flags |= O_NONBLOCK;

    err = sock->ops->connect(sock, (struct sockaddr *)address,
            sizeof(struct sockaddr), sock->file->f_flags);

    SET_CLIENT_FLAG(sock);

    return fd;
}

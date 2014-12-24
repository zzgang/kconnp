#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include "sys_call.h"
#include "array.h"
#include "lkm_util.h"

/* Poll funcs start */
struct poll_table_entry_alias {
    struct file *filp;
    unsigned long key;
    wait_queue_t wait;
    wait_queue_head_t *wait_address;
};

struct poll_wqueues_alias {
    poll_table pt;
    struct poll_table_page *table;
    struct task_struct *polling_task;
    int triggered;
    int error;
    int inline_index;
    struct poll_table_entry_alias inline_entries[N_INLINE_POLL_ENTRIES];
};

struct poll_table_page {
    struct poll_table_page *next;
    struct poll_table_entry_alias *entry;
    struct poll_table_entry_alias entries[0];
};

#define POLL_TABLE_FULL(table) \
    ((unsigned long)((table)->entry+1) > PAGE_SIZE + (unsigned long)(table))

static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
        poll_table *p);

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

#undef DEFAULT_POLLMASK
#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

static int inline do_poll(struct pollfd_ex_t *pfdt, poll_table *pwait)
{
    unsigned int mask;
    int events;
    int fd;
    struct pollfd *pfd;

    pfd = &pfdt->pollfd;

    fd = pfd->fd;
    events = pfd->events;
    mask = 0;
    if (fd >= 0) {
        struct file * file;
        struct pollfd_ex_t *pfdt;

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

                if (pfdt->data && pfdt->poll_func)
                    mask = pfdt->poll_func(pfdt->data, pwait);
                else 
                    mask = file->f_op->poll(file, pwait);
            }

            /* Mask out unneeded events. */
            mask &= events;
        }
    }

    return mask;
}

static void lkm_poll_initwait(struct poll_wqueues_alias *pwq)
{
    init_poll_funcptr(&pwq->pt, __pollwait);
    pwq->error = 0;
    pwq->table = NULL;
    pwq->inline_index = 0;
    pwq->polling_task = current;
    pwq->triggered = 0;
}

static inline void free_poll_entry(struct poll_table_entry_alias *entry)
{
    remove_wait_queue(entry->wait_address, &entry->wait);
}

static void lkm_poll_freewait(struct poll_wqueues_alias *pwq)
{
    struct poll_table_page *p = pwq->table;
    int i;

    for (i = 0; i < pwq->inline_index; i++)
        free_poll_entry(pwq->inline_entries + i);

    while (p) {
        struct poll_table_entry_alias * entry;
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

static struct poll_table_entry_alias *poll_get_entry(struct poll_wqueues_alias *p)
{
    struct poll_table_page *table = p->table;

    if (p->inline_index < N_INLINE_POLL_ENTRIES)
        return p->inline_entries + p->inline_index++;

    if (!table || POLL_TABLE_FULL(table)) {
        struct poll_table_page *new_table;

        new_table = (struct poll_table_page *) __get_free_page(GFP_ATOMIC);
        if (!new_table) {
            p->error = -ENOMEM;
            return NULL;
        }
        new_table->entry = new_table->entries;
        new_table->next = table;
        p->table = new_table;
        table = new_table;
    }

    return table->entry++;
}

static int __pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
    struct poll_wqueues_alias *pwq = wait->private;
    DECLARE_WAITQUEUE(dummy_wait, pwq->polling_task);

    smp_wmb();
    pwq->triggered = 1;

    return default_wake_function(&dummy_wait, mode, sync, key);
}

static int pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
    struct poll_table_entry_alias *entry;

    entry = container_of(wait, struct poll_table_entry_alias, wait);
    if (key && !((unsigned long)key & entry->key))
        return 0;

    return __pollwake(wait, mode, sync, key);
}

/* Add a new entry */
static void __pollwait(struct file *filp, 
        wait_queue_head_t *wait_address, poll_table *p)
{
    struct poll_wqueues_alias *pwq = container_of(p, struct poll_wqueues_alias, pt);
    struct poll_table_entry_alias *entry = poll_get_entry(pwq);

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

    init_waitqueue_func_entry(&entry->wait, pollwake);
    entry->wait.private = pwq;

    add_wait_queue(wait_address, &entry->wait);
}

int lkm_poll(array_t *pfdt_list, int timeo)
{
    struct poll_wqueues_alias table;
    poll_table *pt;
    int count = 0;
    int timed_out = 0;
    long __timeout = timeo * HZ;

    lkm_poll_initwait(&table);
    pt = &(&table)->pt;
    for (;;) {
        int idx;

        if (!(pfdt_list))
            goto ignore_poll;

        for (idx = 0; idx < (pfdt_list)->elements; idx++) {
            struct pollfd_ex_t *pfdt;
            struct pollfd *pfd;

            pfdt = (struct pollfd_ex_t *)(pfdt_list)->get(pfdt_list, idx);

            pfd = (struct pollfd *)&pfdt->pollfd;

            pfd->revents = do_poll(pfdt, pt);

            if (pfd->revents) {

                count++;
                pt = NULL;

            }

        }

ignore_poll:

        pt = NULL;

        if (!count) {
            if (signal_pending(current)) {
                count = -EINTR;
                flush_signals(current);
            }
        }

        if (count || timed_out)
            break;

        __timeout = wait_for_sig_or_timeout(__timeout);
        if (!__timeout)
            timed_out = 1;
    }

    lkm_poll_freewait(&table); 

    return count;
}
/* Poll funcs END */

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

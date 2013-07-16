#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include "sys_call.h"
#include "util.h"

/**poll functions**/
struct poll_table_page {
    struct poll_table_page * next;
    struct poll_table_entry * entry;
    struct poll_table_entry entries[0];
};

#define POLL_TABLE_FULL(table) \
    ((unsigned long)((table)->entry+1) > PAGE_SIZE + (unsigned long)(table))

static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
        poll_table *p);

void lkm_poll_initwait(struct poll_wqueues *pwq)
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

static void free_poll_entry(struct poll_table_entry *entry)
{
    remove_wait_queue(entry->wait_address, &entry->wait);
    /*Not needed by f_count*/
    //fput(entry->filp);
}

void lkm_poll_freewait(struct poll_wqueues *pwq)
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

        new_table = (struct poll_table_page *) __get_free_page(GFP_KERNEL);
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
    /*Needn't add f_count*/
    //get_file(filp);
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
/**End poll functions**/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 10)
static int sock_map_fd(struct socket *sock, int flags)
{
    struct file *newfile;
    int fd = get_unused_fd_flags(flags);
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

    err = sock->ops->connect(sock, (struct sockaddr *)address,
            sizeof(struct sockaddr), sock->file->f_flags);
    if (err < 0) {
        orig_sys_close(fd);
        return err;
    }

    SET_CLIENT_FLAG(sock);

    return fd;
}

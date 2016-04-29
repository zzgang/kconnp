#include <linux/kthread.h>
#include "connpd.h"
#include "connp.h"
#include "sockp.h"
#include "sys_call.h"
#include "preconnect.h"
#include "lkm_util.h"
#include "array.h"

#define CONNPD_NAME "kconnpd"
#define CONNP_DAEMON_SET(v) (connp_daemon = (v))

struct task_struct * volatile connp_daemon;

static int connpd_func(void *data);
static int connpd_start(void);
static void connpd_stop(void);

static int connpd_do_poll(void *data, poll_table *pt);
static void connp_wait_events_or_timout(void);

static void connpd_unused_fds_prefetch(void);
static void connpd_unused_fds_put(void);

#define CLOSE_ALL 0
#define CLOSE_TIMEOUT 1
#define close_all_files() do_close_files(CLOSE_ALL)
#define close_timeout_files() do_close_files(CLOSE_TIMEOUT)
static void do_close_files(int close_type);

struct stack_t *connpd_close_pending_fds, 
               *connpd_unused_fds;

#define connpd_close_pending_fds_init(num) \
    stack_init(&connpd_close_pending_fds, num, sizeof(int), WITHOUT_MUTEX)

#define connpd_close_pending_fds_destroy() \
    do {     \
        if (connpd_close_pending_fds)   \
        connpd_close_pending_fds->destroy(&connpd_close_pending_fds); \
    } while(0)

#define connpd_unused_fds_init(num) \
    stack_init(&connpd_unused_fds, num, sizeof(int), WITH_MUTEX)

#define connpd_unused_fds_destroy() \
    do {    \
        if (connpd_unused_fds)           \
        connpd_unused_fds->destroy(&connpd_unused_fds);     \
    } while(0)

static void connpd_unused_fds_prefetch()
{
    int fd;

    while ((fd = lkm_get_unused_fd()) >= 0) {
        if (connpd_unused_fds_in(fd) >= 0)
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

    while ((fd = connpd_unused_fds_out()) >= 0)
        put_unused_fd(fd);
}

static void do_close_files(int close_type)
{
    int fd;

    if (close_type == CLOSE_ALL)
        shutdown_all_sock_list();
    else 
        shutdown_timeout_sock_list();

    while ((fd = connpd_close_pending_fds_out()) >= 0)
        orig_sys_close(fd);

}

static int connpd_do_poll(void *data, poll_table *pt)
{
    struct socket_bucket *sb;
    struct file *file;
    int mask = 0;

    sb = (struct socket_bucket *)data;
    file = lkm_get_file(sb->connpd_fd);
    
    spin_lock(&sb->s_lock);
    if (sb->sock->sk)
        mask = file->f_op->poll(file, pt);
    spin_unlock(&sb->s_lock);

    return mask;
}

/**
 *Wait events or timeout.
 */
static void connp_wait_events_or_timout(void)
{
    int nums;
    struct socket_bucket **sb;
    struct pollfd_ex_t pfdt;
    struct array_t *pollfd_array;
    int count = 0;
    int idx = 0;
    int timeout = 1;//sec

    nums = sockp_sbs_check_list->elements;

    if (!array_init(&pollfd_array, nums, sizeof(struct pollfd_ex_t)))
        goto poll;
    
    while ((sb = (struct socket_bucket **)sockp_sbs_check_list_out())) {

        pfdt.pollfd.fd = (*sb)->connpd_fd;
        pfdt.pollfd.events = POLLRDHUP;
        pfdt.pollfd.revents = 0;
        pfdt.data = (*sb);
        pfdt.poll_func = connpd_do_poll;

        pollfd_array->set(pollfd_array, &pfdt, idx++);

    }

poll:
    count = lkm_poll(pollfd_array, timeout);

    if (!pollfd_array)
        return;

    if (count <= 0)
        goto out_free;

    {
        struct pollfd_ex_t *pfdp;
        
        for(idx = 0; idx < pollfd_array->elements; idx++) {

            pfdp = (struct pollfd_ex_t *)pollfd_array->get(pollfd_array, idx);

            if (pfdp && (pfdp->pollfd.revents & (POLLRDHUP|E_EVENTS))) {
                struct socket *sock;

                sock = ((struct socket_bucket *)pfdp->data)->sock;
                set_sock_close_now(sock, 1);
            }

        }
    }

out_free:
    pollfd_array->destroy(&pollfd_array);
}

static int connpd_func(void *data)
{
    struct rlimit new_rlim = {NR_MAX_OPEN_FDS, NR_MAX_OPEN_FDS};

    lkm_setrlimit(RLIMIT_NOFILE, new_rlim);
    
    allow_signal(NOTIFY_SIG);
   
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    init_waitqueue_head(&current->files->resize_wait);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
        init_waitqueue_head(&current->files->resize_wait);
#endif

    for(;;) {

        if (kthread_should_stop()) {

            connp_wlock();
           
            connpd_unused_fds_put(); 
            close_all_files();

            CONNP_DAEMON_SET(NULL);

            connp_wunlock();

            break;

        } else {
            //Scan and shutdown
            close_timeout_files();

            connpd_unused_fds_prefetch();
            
            scan_spare_conns_preconnect(); 
            
            conn_stats_info_dump();

            connp_wait_events_or_timout();

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
        printk(KERN_ERR "Create connpd error!");

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
    if (!connpd_close_pending_fds_init(NR_MAX_OPEN_FDS))
        return 0;

    if (!connpd_unused_fds_init(NR_MAX_OPEN_FDS/2)) {
        connpd_close_pending_fds_destroy();
        return 0;
    }

    if (!connpd_start())
        return 0;
 
    return 1;
}

void connpd_destroy(void)
{
    connpd_stop();

    connpd_close_pending_fds_destroy();
    connpd_unused_fds_destroy();
}

#include <linux/kthread.h>
#include "connpd.h"
#include "connp.h"
#include "sockp.h"
#include "sys_call.h"
#include "preconnect.h"
#include "util.h"
#include "array.h"

#define CONNPD_NAME "kconnpd"
#define CONNP_DAEMON_SET(v) (connp_daemon = (v))

struct task_struct * volatile connp_daemon;

static int connpd_func(void *data);
static int connpd_start(void);
static void connpd_stop(void);

static int shutdown_timeout_or_preconnect(void);
static inline int connp_fds_events_or_timout(void);

static void connpd_unused_fds_prefetch(void);
static void connpd_unused_fds_put(void);

#define CLOSE_ALL 0
#define CLOSE_TIMEOUT 1
#define close_all_files() do_close_files(CLOSE_ALL)
#define close_timeout_files() do_close_files(CLOSE_TIMEOUT)
static void do_close_files(int close_type);

struct stack_t *connpd_close_pending_fds, 
               *connpd_poll_pending_fds, 
               *connpd_unused_fds;

#define connpd_close_pending_fds_init(num) \
    stack_init(&connpd_close_pending_fds, num, sizeof(int))

#define connpd_poll_pending_fds_init(num) \
    stack_init(&connpd_poll_pending_fds, num, sizeof(int))

#define connpd_unused_fds_init(num) \
    stack_init(&connpd_unused_fds, num, sizeof(int))


#define connpd_close_pending_fds_destroy() \
    do {     \
        if (connpd_close_pending_fds)   \
        connpd_close_pending_fds->destroy(&connpd_close_pending_fds); \
    } while(0)

#define connpd_poll_pending_fds_destroy() \
    do {  \
        if (connpd_poll_pending_fds)                    \
        connpd_poll_pending_fds->destroy(&connpd_poll_pending_fds);  \
    } while(0)

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

/**
 *Wait events of connpd fds or timeout.
 */
static inline int connp_fds_events_or_timout(void)
{
    int nums;
    int fd;
    struct pollfd pfd;
    struct array_t *pollfd_array = NULL;
    int count;
    int idx = 0;

    nums = connpd_poll_pending_fds->elements;

    if (!array_init(&pollfd_array, nums, sizeof(struct pollfd)))
        goto poll;
    
    while ((fd = fd_list_out(connpd_poll_pending_fds)) >= 0) {

        pfd.fd = fd;
        pfd.events = POLLRDHUP;
        pfd.revents = 0;

        pollfd_array->set(pollfd_array, &pfd, idx++);

    }

poll:
    count = lkm_poll(pollfd_array, 1);

    if (!pollfd_array || count <= 0)
        goto out;
    
    {
        struct pollfd *pfdp;
        
        for(idx = 0; idx < pollfd_array->elements; idx++) {

            pfdp = (struct pollfd *)pollfd_array->get(pollfd_array, idx);

            if (pfdp && (pfdp->revents & (POLLRDHUP|E_EVENTS))) {
                struct socket *sock = getsock(pfdp->fd);
                set_sock_close_now(sock, 1); 
            }

        }
    }

    pollfd_array->destroy(&pollfd_array);

out:
    return 1;
}

/**
 * Shutdown sockets which are passive closed or expired or LRU replaced.
 */
static int shutdown_timeout_or_preconnect()
{
    if (connp_fds_events_or_timout()) {

        close_timeout_files();
        scan_spare_conns_preconnect(); 

    }

    return 0;
}

static int connpd_func(void *data)
{
    allow_signal(NOTIFY_SIG);

    for(;;) {

        if (kthread_should_stop()) {

            connp_wlock();
           
            connpd_unused_fds_put(); 
            close_all_files();

            CONNP_DAEMON_SET(NULL);

            connp_wunlock();

            break;

        } else {

            conn_stats_info_dump();
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
    if (!connpd_close_pending_fds_init(NR_MAX_OPEN_FDS))
        return 0;

    if (!connpd_poll_pending_fds_init(NR_MAX_OPEN_FDS)) {
        connpd_close_pending_fds_destroy();
        return 0;
    }

    if (!connpd_unused_fds_init(NR_MAX_OPEN_FDS/2)) {
        connpd_poll_pending_fds_destroy();
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
    connpd_poll_pending_fds_destroy();
    connpd_unused_fds_destroy();
}

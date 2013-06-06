#include <linux/kthread.h>
#include "connpd.h"
#include "connp.h"

#define CONNPD_NAME "kconnpd"

/**
 *The global connp daemon ptr.
 */
struct task_struct * volatile connp_daemon;

rwlock_t connpd_lock;

#define CONNP_DAEMON_SET(v) (connp_daemon = (v))

static int connpd_func(void *data)
{
    for(;;) {

        if (kthread_should_stop()) {
            
            connpd_wlock();
            CONNP_DAEMON_SET(NULL);
            connpd_wunlock();
            
            close_all_fds();
            
            break;
        } else
            scan_connp_shutdown_timeout();

    }

    return 1;
}

/**
 *Create the kconnpd and start it.
 */
int connpd_start(void)
{
    struct task_struct *ptr;
    
    connpd_rwlock_init();

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
void connpd_stop(void)
{
    kthread_stop(CONNP_DAEMON_TSKP);
}

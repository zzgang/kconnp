#ifndef _CONNPD_H
#define _CONNPD_H

#include <linux/spinlock.h>

extern struct task_struct * volatile connp_daemon;
extern int connpd_start(void);
extern void connpd_stop(void);

extern rwlock_t connpd_lock;
/* connpd lock funcions */
static inline void connpd_rwlock_init(void) 
{
    rwlock_init(&connpd_lock);
}

static inline void connpd_rlock(void)
{
    read_lock(&connpd_lock);
}

static inline void connpd_runlock(void)
{
    read_unlock(&connpd_lock);
}

static inline void connpd_wlock(void)
{
    write_lock(&connpd_lock);
}

static inline void connpd_wunlock(void)
{
    write_unlock(&connpd_lock);
}

/*end*/

#define CONNP_DAEMON_TSKP (connp_daemon)
#define CONNP_DAEMON_EXISTS() CONNP_DAEMON_TSKP
#define INVOKED_BY_CONNP_DAEMON() \
            (current == connp_daemon)

#endif

#ifndef _CONNPD_H
#define _CONNPD_H

#include <linux/spinlock.h>

extern struct task_struct * volatile connp_daemon;
extern int connpd_start(void);
extern void connpd_stop(void);
extern inline void connpd_rwlock_init(void);
extern inline void connpd_rlock(void);
extern inline void connpd_runlock(void);
extern inline void connpd_wlock(void);
extern inline void connpd_wunlock(void);

#define CONNP_DAEMON_TSKP (connp_daemon)
#define CONNP_DAEMON_EXISTS() CONNP_DAEMON_TSKP
#define INVOKED_BY_CONNP_DAEMON() \
            (current == connp_daemon)

#endif

#ifndef _CONNPD_H
#define _CONNPD_H

#include <linux/spinlock.h>

#include "stack.h"
#include "cfg.h"
#include "kconnp.h"

#define NR_MAX_OPEN_FDS CONNECTION_LIMIT

#define CONNP_DAEMON_TSKP (connp_daemon)
#define CONNP_DAEMON_EXISTS() CONNP_DAEMON_TSKP
#define INVOKED_BY_CONNP_DAEMON() (current == CONNP_DAEMON_TSKP)

extern struct task_struct * volatile connp_daemon;

extern int connpd_init(void);
extern void connpd_destroy(void);

extern struct stack_t *connpd_close_pending_fds, 
                      *connpd_unused_fds;

#define fd_list_in(list, fd) \
    ({int *ele = (int *)(list)->in(list, &fd); \
     ele ? *ele : -1;})
#define fd_list_out(list) \
    ({int *ele = (int *)(list)->out(list); \
     ele ? *ele : -1;})

#define connpd_get_unused_fd() connpd_unused_fds_out()

#define connpd_unused_fds_in(fd) fd_list_in(connpd_unused_fds, fd)
#define connpd_unused_fds_out() fd_list_out(connpd_unused_fds) 

#define connpd_close_pending_fds_in(fd) fd_list_in(connpd_close_pending_fds, fd)
#define connpd_close_pending_fds_out() fd_list_out(connpd_close_pending_fds)

#endif

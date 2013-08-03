#ifndef _CONNPD_H
#define _CONNPD_H

#include <linux/spinlock.h>

#include "stack.h"

#define NR_MAX_OPEN_FDS 1024

#define CONNP_DAEMON_TSKP (connp_daemon)
#define CONNP_DAEMON_EXISTS() CONNP_DAEMON_TSKP
#define INVOKED_BY_CONNP_DAEMON() (current == CONNP_DAEMON_TSKP)

extern struct task_struct * volatile connp_daemon;

extern int connpd_init(void);
extern void connpd_destroy(void);

extern struct stack_t *connpd_close_pending_fds,
               *connpd_poll_pending_fds,
               *connpd_unused_fds;

#define connpd_get_unused_fd()  connpd_unused_fds_out()

#define connpd_unused_fds_in(fd) fd_list_in(connpd_unused_fds, fd)
#define connpd_unused_fds_out() fd_list_out(connpd_unused_fds) 

#define connpd_close_pending_fds_in(fd) fd_list_in(connpd_close_pending_fds, fd)
#define connpd_close_pending_fds_out() fd_list_out(connpd_close_pending_fds)

#define connpd_poll_pending_fds_in(fd) fd_list_in(connpd_poll_pending_fds, fd)
#define connpd_poll_pending_fds_out() fd_list_out(connpd_poll_pending_fds)

#endif

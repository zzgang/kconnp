#ifndef _CONNP_H
#define _CONNP_H

#include <linux/file.h>
#include <linux/sched.h>
#include "sockp.h"

#define NR_MAX_BINDING_FDS 1024
#define NR_SOCKET_CLOSE_PENDING NR_MAX_BINDING_FDS

#define CONNP_DAEMON_TSKP (connp_daemon)
#define CONNP_DAEMON_EXISTS() CONNP_DAEMON_TSKP
#define CONNP_DAEMON_SET(v) \
        (connp_daemon = (v))
#define INVOKED_BY_CONNP_DAEMON() \
        (current == connp_daemon)

extern struct task_struct * volatile connp_daemon;

extern struct socket_bucket *attach_pending_sbs_push(struct socket_bucket *);
extern struct socket_bucket *attach_pending_sbs_pop(void);

extern int close_pending_fds_push(int fd);
extern int close_pending_fds_pop(void);

extern int scan_connp_shutdown_timeout(void);
extern int insert_into_connp_if_permitted(int fd);
extern int fetch_conn_from_connp(int fd, struct sockaddr *);

extern void connp_sys_exit_prepare(void);

extern int connp_init(void);
extern void connp_destroy(void);

#endif

#ifndef _CONNP_H
#define _CONNP_H

#include <linux/file.h>
#include <linux/sched.h>
#include "sockp.h"

typedef enum {
    CLOSE_POSITIVE = 0,
    CLOSE_PASSIVE
} conn_close_way_t;

struct conn_attr_t {
    conn_close_way_t close_way;
    int close_now;
    struct {
        unsigned int all_count;
        unsigned int idle_count;
    } stats;
};

extern int insert_into_connp_if_permitted(int fd);
extern int fetch_conn_from_connp(int fd, struct sockaddr *);

extern void connp_sys_exit_prepare(void);

extern int connp_init(void);
extern void connp_destroy(void);

#endif

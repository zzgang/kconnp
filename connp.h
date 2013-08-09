#ifndef _CONNP_H
#define _CONNP_H

#include <linux/file.h>
#include <linux/sched.h>
#include "sockp.h"

#define CONN_BLOCK 1
#define CONN_NONBLOCK 2
#define CONN_IS_NONBLOCK(filp) ((filp)->f_flags & O_NONBLOCK)

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
        atomic_t connected_all_count;
        atomic_t connected_hit_count;
    } stats;
};

extern int insert_into_connp_if_permitted(int fd);
extern int fetch_conn_from_connp(int fd, struct sockaddr *);

extern void connp_sys_exit_prepare(void);

extern int connp_init(void);
extern void connp_destroy(void);

#define ALL_COUNT 0
#define IDLE_COUNT 1
#define CONNECTED_ALL_COUNT 2
#define CONNECTED_HIT_COUNT 3
#define conn_add_all_count(addr) conn_add_count(addr, ALL_COUNT)
#define conn_add_idle_count(addr) conn_add_count(addr, IDLE_COUNT)
#define conn_add_connected_all_count(addr) conn_add_count(addr, CONNECTED_ALL_COUNT)
#define conn_add_connected_hit_count(addr) conn_add_count(addr, CONNECTED_HIT_COUNT)
extern int conn_add_count(struct sockaddr *, int count_type);

extern int conn_spec_check_close_flag(struct sockaddr *);

extern void conn_stats_info_dump(void);

extern rwlock_t connp_rwlock;
/* connpd lock funcions */
static inline void connp_rwlock_init(void) 
{
    rwlock_init(&connp_rwlock);
}

static inline void connp_rlock(void)
{
    read_lock(&connp_rwlock);
}

static inline void connp_runlock(void)
{
    read_unlock(&connp_rwlock);
}

static inline void connp_wlock(void)
{
    write_lock(&connp_rwlock);
}

static inline void connp_wunlock(void)
{
    write_unlock(&connp_rwlock);
}
/*end*/

#endif

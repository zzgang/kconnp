#ifndef _CONNP_H
#define _CONNP_H

#include <linux/file.h>
#include <linux/sched.h>
#include "sockp.h"

#define CONN_BLOCK    1
#define CONN_NONBLOCK 2
#define CONN_IS_NONBLOCK(filp) ((filp)->f_flags & O_NONBLOCK)

//cfg flags
#define CONN_STATEFUL (1<<0) //stateful connection

#define CONN_PASSIVE_TIMEOUT_JIFFIES_THRESHOLD (60 * HZ) /*1 minute*/

typedef enum {
    CLOSE_POSITIVE = 0,
    CLOSE_PASSIVE
} conn_close_way_t;

struct conn_attr_t {
    struct {
        conn_close_way_t close_way;
        u64 last_set_jiffies;
    } close_way_attrs;

    u64 keep_alive;
    int close_now;

    struct {
        unsigned int all_count;
        unsigned int idle_count;
        lkm_atomic_t connected_hit_count;
        lkm_atomic_t connected_miss_count;
    } stats;
};

extern int check_if_ignore_primitives(int fd, const char __user * buf, size_t len);
extern int connp_fd_allowed(int fd);
extern int insert_into_connp_if_permitted(int fd);
extern int fetch_conn_from_connp(int fd, struct sockaddr *);

extern void connp_sys_exit_prepare(void);

extern int connp_init(void);
extern void connp_destroy(void);

#define ALL_COUNT 0
#define IDLE_COUNT 1
#define CONNECTED_HIT_COUNT 2
#define CONNECTED_MISS_COUNT 3
#define conn_inc_all_count(addr) conn_inc_count(addr, ALL_COUNT)
#define conn_inc_idle_count(addr) conn_inc_count(addr, IDLE_COUNT)
#define conn_inc_connected_hit_count(addr) conn_inc_count(addr, CONNECTED_HIT_COUNT)
#define conn_inc_connected_miss_count(addr) conn_inc_count(addr, CONNECTED_MISS_COUNT)
extern int conn_inc_count(struct sockaddr *, int count_type);

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

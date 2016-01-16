/**
 *Header for sockp.c
 *Date 05/27/2012
 *Author Zhigang Zhang <zzgang2008@gmail.com>
 */
#ifndef _SOCKP_H
#define _SOCKP_H

#include <linux/in.h> /*define struct sockaddr_in*/
#include <linux/net.h> /*define struct socket*/
#include <net/tcp_states.h>
#include "stack.h"

#define SOCKP_DEBUG 0

#define NR_SOCKET_BUCKET NR_MAX_OPEN_FDS

#define NR_HASH ((NR_SOCKET_BUCKET)/2 + 1)
#define NR_SHASH (NR_SOCKET_BUCKET)

#define WAIT_TIMEOUT (GN("connection_wait_timeout") * HZ)//seconds

#define MAX_REQUESTS ({                                         \
        u64 requests = GN("max_requests_per_connection");       \
        requests ? requests : ~0ULL;                            \
        })

#define LRU 1 //LRU replace algorithm

#define shutdown_all_sock_list() shutdown_sock_list(SHUTDOWN_ALL)
#define shutdown_timeout_sock_list() shutdown_sock_list(SHUTDOWN_IDLE)

typedef enum {
    SOCK_RECLAIM = 0,
    SOCK_PRECONNECT
} sock_create_way_t;

typedef enum {
    SHUTDOWN_ALL,
    SHUTDOWN_IDLE
} shutdown_way_t;

struct socket_bucket {
    struct sockaddr cliaddr;
    struct sockaddr servaddr;

    struct socket *sock;
    struct sock *sk;

    sock_create_way_t sock_create_way;

    unsigned char sb_in_use;
    unsigned char sock_in_use; /*tag: wether it is in use*/

    unsigned char sock_close_now; /*tag: wether be closed at once*/

    u64 sock_create_jiffies; /*the jiffies to be inserted*/
    u64 last_used_jiffies; /*the last used jiffies*/

    u64 uc; /*used count*/

    struct socket_bucket *sb_prev;
    struct socket_bucket *sb_next; /*for hash table*/

    struct socket_bucket *sb_sprev;
    struct socket_bucket *sb_snext; /*for with sk addr hash table*/

    struct socket_bucket *sb_trav_prev; /*traverse all used buckets*/
    struct socket_bucket *sb_trav_next;

    struct socket_bucket *sb_free_prev; /*free bucket indicator*/
    struct socket_bucket *sb_free_next;

    int connpd_fd; /*attached fd of the connpd*/

    spinlock_t s_lock; //sb spin lock
};

extern struct stack_t *sockp_sbs_check_list;

#define sockp_sbs_check_list_in(sb) \
    sockp_sbs_check_list->in(sockp_sbs_check_list, sb)

#define sockp_sbs_check_list_out(sb) \
    sockp_sbs_check_list->out(sockp_sbs_check_list)

#define SOCK_SET_ATTR_DEFINE(sock, attr) \
    void set_##attr(struct socket *sock, typeof(((struct socket_bucket *)NULL)->attr) attr)

extern void set_sock_close_now(struct socket *sock, typeof(((struct socket_bucket *)NULL)->sock_close_now) close_now);

/**
 *Apply a existed socket from socket pool.
 */
extern struct socket_bucket *apply_sk_from_sockp(struct sockaddr *, struct sockaddr *);

/**
 *Free a socket which is returned by 'apply_socket_from_sockp', return the bucket of this socket.
 */
extern int free_sk_to_sockp(struct sock *, struct socket_bucket **);

/**
 *Insert a new socket to sockp, return the new bucket of this socket.
 */
extern int insert_sock_to_sockp(struct sockaddr *, struct sockaddr *, 
        struct socket *, int fd, sock_create_way_t create_way, 
        struct socket_bucket **sbpp);

extern void shutdown_sock_list(shutdown_way_t shutdown_way);

extern int sockp_init(void);
extern void sockp_destroy(void);

#endif

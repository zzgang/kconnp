/**
 *Kernel socket pool
 *Author Zhigang Zhang <zzgang2008@gmail.com>
 */
#include <linux/string.h>
#include <linux/jiffies.h>
#include <net/sock.h>
#include <linux/spinlock.h> 
#include "sys_call.h"
#include "connpd.h"
#include "sockp.h"
#include "util.h"
#include "cfg.h"
#include "preconnect.h"

//spin lock
#define SOCKP_LOCK_T spinlock_t
#define SOCKP_LOCK_INIT()  spin_lock_init(&ht.ht_lock)
#define SOCKP_LOCK() spin_lock(&ht.ht_lock)
#define SOCKP_UNLOCK() spin_unlock(&ht.ht_lock)
#define SOCKP_LOCK_DESTROY()

#define HASH(address_ptr) ht.hash_table[_hashfn((struct sockaddr_in *)(address_ptr))]
#define SHASH(sk) ht.shash_table[_shashfn(sk)]

#define KEY_MATCH_CAST(address_ptr1, address_ptr2) ((address_ptr1)->sin_port == (address_ptr2)->sin_port && (address_ptr1)->sin_addr.s_addr == (address_ptr2)->sin_addr.s_addr)
#define KEY_MATCH(address_ptr1, address_ptr2) KEY_MATCH_CAST((struct sockaddr_in *)address_ptr1, (struct sockaddr_in *)address_ptr2)
#define SKEY_MATCH(sk_ptr1, sk_ptr2) (sk_ptr1 == sk_ptr2)

#define PUT_SB(sb) ((sb)->sb_in_use = 0) 

#define IN_HLIST(head, bucket) ({                       \
        struct socket_bucket *__p;                      \
        for (__p = (head); __p; __p = __p->sb_next) {   \
        LOOP_COUNT_SAFE_CHECK(__p);                        \
        if (__p == (bucket))                            \
        break;                                          \
        }                                               \
        LOOP_COUNT_RESET();                                 \
        __p;})

#define INSERT_INTO_HLIST(head, bucket) \
    do {                      \
        (bucket)->sb_prev = NULL; \
        (bucket)->sb_next = (head); \
        if ((head))     \
        (head)->sb_prev = (bucket); \
        (head) = (bucket);  \
    } while(0)

#define REMOVE_FROM_HLIST(head, bucket) \
    do {  \
        if ((bucket)->sb_prev)                  \
        (bucket)->sb_prev->sb_next = (bucket)->sb_next; \
        if ((bucket)->sb_next)              \
        (bucket)->sb_next->sb_prev = (bucket)->sb_prev; \
        if ((head) == (bucket)) \
        (head) = (bucket)->sb_next;     \
    } while(0)

#define IN_SHLIST(head, bucket) ({                      \
        struct socket_bucket *__p;                      \
        for (__p = (head); __p; __p = __p->sb_snext) {  \
        LOOP_COUNT_SAFE_CHECK(__p);                        \
        if (__p == (bucket))                            \
        break;                                          \
        }                                               \
        LOOP_COUNT_RESET();                             \
        __p;})

#define INSERT_INTO_SHLIST(head, bucket) \
    do {                               \
        (bucket)->sb_sprev = NULL; \
        (bucket)->sb_snext = (head); \
        if ((head))     \
        (head)->sb_sprev = (bucket); \
        (head) = (bucket);\
    } while(0)

#define REMOVE_FROM_SHLIST(head, bucket) \
    do {    \
        if ((bucket)->sb_sprev)                  \
        (bucket)->sb_sprev->sb_snext = (bucket)->sb_snext; \
        if ((bucket)->sb_snext)              \
        (bucket)->sb_snext->sb_sprev = (bucket)->sb_sprev; \
        if ((head) == (bucket)) \
        (head) = (bucket)->sb_snext;    \
    } while(0)

#define IN_TLIST(bucket) ({                                             \
        struct socket_bucket *__p;                                      \
        for (__p = ht.sb_trav_head; __p; __p = __p->sb_trav_next) {     \
        LOOP_COUNT_SAFE_CHECK(__p);                                        \
        if (__p == (bucket))                                            \
        break;                                                          \
        }                                                               \
        LOOP_COUNT_RESET();                                             \
        __p;})

#define INSERT_INTO_TLIST(bucket) \
    do {    \
        (bucket)->sb_trav_next = NULL; \
        (bucket)->sb_trav_prev = ht.sb_trav_tail;  \
        if (!ht.sb_trav_head)              \
        ht.sb_trav_head = (bucket);    \
        if (ht.sb_trav_tail)               \
        ht.sb_trav_tail->sb_trav_next = (bucket);  \
        ht.sb_trav_tail = (bucket); \
    } while(0)

#define REMOVE_FROM_TLIST(bucket) \
    do {    \
        if ((bucket)->sb_trav_next)  \
        (bucket)->sb_trav_next->sb_trav_prev = (bucket)->sb_trav_prev; \
        if ((bucket)->sb_trav_prev) \
        (bucket)->sb_trav_prev->sb_trav_next = (bucket)->sb_trav_next; \
        if ((bucket) == ht.sb_trav_head)  \
        ht.sb_trav_head = (bucket)->sb_trav_next; \
        if ((bucket) == ht.sb_trav_tail)   \
        ht.sb_trav_tail = (bucket)->sb_trav_prev; \
    } while(0)

#define SOCKADDR_COPY(sockaddr_dest, sockaddr_src) memcpy((void *)sockaddr_dest, (void *)sockaddr_src, sizeof(struct sockaddr))

#define INIT_SB(sb, s, fd, way)   \
    do {    \
        (sb)->sb_in_use = 1;  \
        (sb)->sock_in_use = 0;    \
        (sb)->sock_close_now = 0; \
        (sb)->sock = s;    \
        (sb)->sk = (s)->sk;      \
        (sb)->sock_create_way = way; \
        (sb)->last_used_jiffies = jiffies;    \
        (sb)->connpd_fd = fd; \
        (sb)->uc = 0; \
        (sb)->sb_prev = NULL; \
        (sb)->sb_next = NULL; \
        (sb)->sb_sprev = NULL; \
        (sb)->sb_snext = NULL; \
        (sb)->sb_trav_prev = NULL; \
        (sb)->sb_trav_next = NULL; \
    } while(0)

#define ATOMIC_SET_SOCK_ATTR(sock, attr)                                \
do {                                                                    \
    struct socket_bucket *p;                                            \
                                                                        \
    SOCKP_LOCK();                                                       \
                                                                        \
    if (!sock->sk)                                                      \
        goto break_unlock;                                              \
                                                                        \
    p = SHASH(sock->sk);                                               \
    for (; p; p = p->sb_snext) {                                        \
        if (SKEY_MATCH(sock->sk, p->sk)) {                        \
            p->attr = attr;                                             \
            break;                                                      \
        }                                                               \
    }                                                                   \
                                                                        \
break_unlock:                                                           \
    SOCKP_UNLOCK();                                                     \
                                                                        \
} while(0)

#define SOCK_IS_RECLAIM(sb) ((sb)->sock_create_way == SOCK_RECLAIM)
#define SOCK_IS_RECLAIM_PASSIVE(sb) (SOCK_IS_RECLAIM(sb) && !cfg_conn_is_positive(&(sb)->address))

#define SOCK_IS_PRECONNECT(sb) ((sb)->sock_create_way == SOCK_PRECONNECT)
#define SOCK_IS_NOT_SPEC_BUT_PRECONNECT(sb) (!cfg_conn_acl_spec_allowd(&(sb)->address) && SOCK_IS_PRECONNECT(sb))

#define SOCK_IS_TIMEOUT(sb) ((jiffies - (sb)->last_used_jiffies) > TIMEOUT * HZ)

#if DEBUG_ON

static unsigned int loop_count = 0;
#define LOOP_COUNT_SAFE_CHECK(ptr) do { \
    if (++loop_count > NR_SOCKET_BUCKET) { \
    printk(KERN_ERR "Loop count overflow, function: %s, line: %d\n", __FUNCTION__, __LINE__);    \
    } \
} while(0)

#define LOOP_COUNT_LOCAL_DEFINE(var_name) unsigned int var_name

#define LOOP_COUNT_SAVE(local) do { \
    local = loop_count; \
} while(0) 

#define LOOP_COUNT_RESTORE(local) do {   \
    loop_count = local;   \
} while(0)

#define LOOP_COUNT_VALUE() (loop_count)
#define LOOP_COUNT_RESET() (loop_count = 0)

#else

#define LOOP_COUNT_SAFE_CHECK(ptr)
#define LOOP_COUNT_LOCAL_DEFINE(var)
#define LOOP_COUNT_SAVE(local)
#define LOOP_COUNT_RESTORE(local)
#define LOOP_COUNT_RESET()

#endif

#if LRU
static struct socket_bucket *get_empty_slot(struct sockaddr *);
#else
static struct socket_bucket *get_empty_slot(void);
#endif

static inline unsigned int _hashfn(struct sockaddr_in *);
static inline unsigned int _shashfn(struct sock *);

static struct {
    struct socket_bucket *hash_table[NR_HASH];
    struct socket_bucket *shash_table[NR_SHASH]; //for sock addr hash table.
    struct socket_bucket *sb_free_p;
    struct socket_bucket *sb_trav_head;
    struct socket_bucket *sb_trav_tail;
    SOCKP_LOCK_T ht_lock;
} ht;

static struct socket_bucket SB[NR_SOCKET_BUCKET];

static inline unsigned int _hashfn(struct sockaddr_in *address)
{
    return (unsigned)((*address).sin_port ^ (*address).sin_addr.s_addr) % NR_HASH;
}

static inline unsigned int _shashfn(struct sock *sk)
{
    return (unsigned long)sk % NR_SHASH;
}

SOCK_SET_ATTR_DEFINE(sock, sock_close_now)
{
    ATOMIC_SET_SOCK_ATTR(sock, sock_close_now);
}

/**
 *Apply a unused sock->sk from socket pool.
 */
struct sock *apply_sk_from_sockp(struct sockaddr *address)
{
    struct socket_bucket *p;
    struct sock *sk;

    SOCKP_LOCK();

    conn_add_connected_all_count(address);

    p = HASH(address);
    for (; p; p = p->sb_next) { 

        LOOP_COUNT_SAFE_CHECK(p);

        if (KEY_MATCH(address, &p->address)) {

            if (p->sock_in_use 
                    || !SOCK_ESTABLISHED(p->sock) 
                    || SOCK_IS_RECLAIM_PASSIVE(p))
                continue;

            p->uc++; //inc used count
            p->sock_in_use = 1; //set "in use" tag.
            sk = p->sock->sk;
            p->sock->sk = NULL; //remove reference to avoid to destroy the sk.

            REMOVE_FROM_HLIST(HASH(address), p);
            
            conn_add_connected_hit_count(address);
            
            LOOP_COUNT_RESET();
           
            SOCKP_UNLOCK();

            return sk;
        }
    }

    LOOP_COUNT_RESET();
    
    SOCKP_UNLOCK();

    return NULL;
}

/**
 *To scan all sock pool to close the expired or all sockets. The caller is kconnpd.
 */
void shutdown_sock_list(shutdown_way_t shutdown_way)
{
    struct socket_bucket *p; 

    BUG_ON(!INVOKED_BY_CONNP_DAEMON());

    SOCKP_LOCK();
    
    p = ht.sb_trav_head;
    for (; p; p = p->sb_trav_next) {

        LOOP_COUNT_SAFE_CHECK(p);

        if ((shutdown_way == SHUTDOWN_ALL) || p->sock_close_now)
            goto shutdown;

        if (!SK_ESTABLISHING(p->sk)) {
           cfg_conn_set_passive(&p->address); //may be passive socket 
           goto shutdown;
        }

        if (SOCK_IS_NOT_SPEC_BUT_PRECONNECT(p)
                || SOCK_IS_RECLAIM_PASSIVE(p) 
                || (SOCK_IS_RECLAIM(p) && SOCK_IS_TIMEOUT(p))
                || (SOCK_IS_PRECONNECT(p) 
                    && p->sock_in_use 
                    && SOCK_IS_TIMEOUT(p))) 
            goto shutdown;

        //Luckly, selected as idle conn.
        if (conn_spec_check_close_flag(&p->address))
            goto shutdown;

        if (!p->sock_in_use)
            conn_add_idle_count(&p->address);

        conn_add_all_count(&p->address);

        continue;

shutdown:
        {
            LOOP_COUNT_LOCAL_DEFINE(local_loop_count);
            LOOP_COUNT_SAVE(local_loop_count);

            LOOP_COUNT_RESET();

            if (IN_HLIST(HASH(&p->address), p))
                REMOVE_FROM_HLIST(HASH(&p->address), p);
            if (IN_SHLIST(SHASH(p->sk), p))
                REMOVE_FROM_SHLIST(SHASH(p->sk), p);
            REMOVE_FROM_TLIST(p);

            PUT_SB(p);

            connpd_close_pending_fds_in(p->connpd_fd);

            LOOP_COUNT_RESTORE(local_loop_count);
        }
    }

    LOOP_COUNT_RESET();
    
    SOCKP_UNLOCK();
}

/**
 *Free a socket which is returned by 'apply_sk_from_sockp'
 */
struct socket_bucket *free_sk_to_sockp(struct sock *sk)
{
    struct socket_bucket *p, *sb = NULL;

    SOCKP_LOCK();

    p = SHASH(sk);
    for (; p; p = p->sb_snext) {

        LOOP_COUNT_SAFE_CHECK(p);
        
        if (SKEY_MATCH(sk, p->sk)) {

            if (!p->sock_in_use) {//can't release it repeatedly!
                printk(KERN_ERR "Free socket error!\n");
                break;
            }

            p->sock_in_use = 0; //clear "in use" tag.
            p->last_used_jiffies = jiffies;

            INSERT_INTO_HLIST(HASH(&p->address), p);

            sock_graft(sk, p->sock);

            sb = p;
            
            break;
        }

    }

    LOOP_COUNT_RESET();

    SOCKP_UNLOCK();

    return sb;
}

/**
 *Get a empty slot from sockp;
 */
#if LRU
static struct socket_bucket *get_empty_slot(struct sockaddr *addr)
#else
static struct socket_bucket *get_empty_slot(void)
#endif
{
    struct socket_bucket *p; 
#if LRU
    struct socket_bucket *lru = NULL;
    unsigned int uc = ~0;
#endif

    p = ht.sb_free_p;

    do {

        LOOP_COUNT_SAFE_CHECK(p);

        if (!p->sb_in_use) {
            ht.sb_free_p = p->sb_free_next;
            LOOP_COUNT_RESET();
            return p;
        }

#if LRU
        /*connpd_fd: -1, was not attached to connpd*/
        if (!p->sock_in_use 
                && !KEY_MATCH(addr, &p->address) 
                && p->connpd_fd >= 0 
                && p->uc <= uc) { 
            lru = p;
            uc = p->uc;
        }
#endif

        p = p->sb_free_next;

    } while (p != ht.sb_free_p);

    LOOP_COUNT_RESET();

#if LRU
    if (lru) {

        if (connpd_close_pending_fds_in(lru->connpd_fd) < 0)
            return NULL;

        ht.sb_free_p = lru->sb_free_next;

        if (IN_HLIST(HASH(&lru->address), lru))
            REMOVE_FROM_HLIST(HASH(&lru->address), lru);
        if (IN_SHLIST(SHASH(lru->sk), lru))
            REMOVE_FROM_SHLIST(SHASH(lru->sk), lru);
        if (IN_TLIST(lru))
            REMOVE_FROM_TLIST(lru);

        return lru;

    } 
#endif

    return NULL;
}

/**
 *Insert a new socket to sockp.
 */
struct socket_bucket *insert_sock_to_sockp(struct sockaddr *address, 
        struct socket *s, int connpd_fd, sock_create_way_t create_way)
{
    struct socket_bucket *empty = NULL;

    SOCKP_LOCK();

#if LRU
    if (!(empty = get_empty_slot(address))) 
        goto unlock_ret;
#else
    if (!(empty = get_empty_slot())) 
        goto unlock_ret;
#endif

    INIT_SB(empty, s, connpd_fd, create_way);

    SOCKADDR_COPY(&empty->address, address);

    INSERT_INTO_HLIST(HASH(&empty->address), empty);
    INSERT_INTO_SHLIST(SHASH(empty->sk), empty);
    INSERT_INTO_TLIST(empty);

unlock_ret:
    SOCKP_UNLOCK();

    return empty;
}

int sockp_init()
{
    struct socket_bucket *sb_tmp;

    memset((void *)SB, 0, sizeof(SB));
    memset((void *)&ht, 0, sizeof(ht));

    //init sockp freelist.
    ht.sb_free_p = sb_tmp = SB;

    while (sb_tmp < SB + NR_SOCKET_BUCKET) {
        sb_tmp->sb_free_prev = sb_tmp - 1;
        sb_tmp->sb_free_next = sb_tmp + 1;
        sb_tmp++;
    }

    sb_tmp--;
    SB[0].sb_free_prev = sb_tmp;
    sb_tmp->sb_free_next = SB;

    SOCKP_LOCK_INIT();
    
    return 1;
}

/*
 *destroy the sockp and the hash table.
 */
void sockp_destroy(void)
{
    SOCKP_LOCK_DESTROY();
}

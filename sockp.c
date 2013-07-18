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
#define SHASH(address_ptr, s) ht.shash_table[_shashfn((struct sockaddr_in *)(address_ptr), (struct socket *)s)]

#define KEY_MATCH_CAST(address_ptr1, address_ptr2) ((address_ptr1)->sin_port == (address_ptr2)->sin_port && (address_ptr1)->sin_addr.s_addr == (address_ptr2)->sin_addr.s_addr)
#define KEY_MATCH(address_ptr1, address_ptr2) KEY_MATCH_CAST((struct sockaddr_in *)address_ptr1, (struct sockaddr_in *)address_ptr2)
#define SKEY_MATCH(address_ptr1, sock_ptr1, address_ptr2, sock_ptr2) (KEY_MATCH(address_ptr1, address_ptr2) && (sock_ptr1 == sock_ptr2))

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
        sb->sb_in_use = 1;  \
        sb->sock_in_use = 0;    \
        sb->sock = s;    \
        sb->sock_create_way = way; \
        sb->last_used_jiffies = jiffies;    \
        sb->connpd_fd = fd; \
        sb->uc = 0; \
        sb->sb_prev = NULL; \
        sb->sb_next = NULL; \
        sb->sb_sprev = NULL; \
        sb->sb_snext = NULL; \
        sb->sb_trav_prev = NULL; \
        sb->sb_trav_next = NULL; \
    } while(0)

#define SOCK_IS_RECLAIM(sb) ((sb)->sock_create_way == SOCK_RECLAIM)
#define SOCK_IS_RECLAIM_PASSIVE(sb) (SOCK_IS_RECLAIM(sb) && !cfg_conn_is_positive(&(sb)->address))

#define SOCK_IS_PRECONNECT(sb) ((sb)->sock_create_way == SOCK_PRECONNECT)
#define SOCK_IS_NOT_SPEC_BUT_PRECONNECT(sb) (!cfg_conn_acl_spec_allowd(&(sb)->address) && SOCK_IS_PRECONNECT(sb))


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
static inline unsigned int _shashfn(struct sockaddr_in *, struct socket *);

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

static inline unsigned int _shashfn(struct sockaddr_in *address, struct socket *s)
{
    return (unsigned)((*address).sin_port ^ (*address).sin_addr.s_addr ^ (unsigned long)s) % NR_SHASH;
}

/**
 *Apply a existed socket from socket pool.
 */
struct socket *apply_socket_from_sockp(struct sockaddr *address)
{
    struct socket_bucket *p;

    SOCKP_LOCK();

    for (p = HASH(address); p; p = p->sb_next) { 

        LOOP_COUNT_SAFE_CHECK(p);

        if (KEY_MATCH(address, &p->address)) {
            if (p->sock_in_use 
                    || !SOCK_ESTABLISHED(p->sock) 
                    || SOCK_IS_RECLAIM_PASSIVE(p))
                continue;

            p->uc++; //inc used count
            p->sock_in_use = 1; //set "in use" tag.

            REMOVE_FROM_HLIST(HASH(address), p);

            LOOP_COUNT_RESET();
           
            SOCKP_UNLOCK();

            return p->sock;
        }
    }

    LOOP_COUNT_RESET();
    
    SOCKP_UNLOCK();

    return NULL;
}


void sockp_get_fds(struct list_head *fds_list)
{
    struct socket_bucket *p; 
    struct fd_entry *tmp;

    SOCKP_LOCK();

    for (p = ht.sb_trav_head; p; p = p->sb_trav_next) {

        LOOP_COUNT_SAFE_CHECK(p);

        if (p->connpd_fd < 0)
            continue;

        tmp = (typeof(*tmp) *)lkmalloc(sizeof(typeof(*tmp)));
        if (!tmp) 
            break;

        tmp->fd = p->connpd_fd;
        list_add_tail(&tmp->siblings, fds_list);  
    }

    LOOP_COUNT_RESET();

    SOCKP_UNLOCK();
}

/**
 *To scan all sock pool to close the expired or all sockets. The caller is kconnpd.
 */
void shutdown_sock_list(shutdown_way_t shutdown_way)
{
    struct socket_bucket *p; 

    SOCKP_LOCK();

    for (p = ht.sb_trav_head; p; p = p->sb_trav_next) {

        LOOP_COUNT_SAFE_CHECK(p);

        if (shutdown_way == SHUTDOWN_ALL) //shutdown all repeatly!
            goto shutdown;

        if (p->sock_in_use) {
            conn_add_all_count(&p->address, 1);
            continue;
        }

        if (!SOCK_ESTABLISHED(p->sock)) {
            cfg_conn_set_passive(&p->address);
            goto shutdown;
        }

        if (SOCK_IS_NOT_SPEC_BUT_PRECONNECT(p)
                || SOCK_IS_RECLAIM_PASSIVE(p) 
                || (SOCK_IS_RECLAIM(p)
                    && (jiffies - p->last_used_jiffies > TIMEOUT * HZ))) 
            goto shutdown;

        //luckly, selected as idle conn.
        if (conn_spec_check_close_flag(&p->address))
            goto shutdown;

        conn_add_idle_count(&p->address, 1);
        conn_add_all_count(&p->address, 1);

        continue;

shutdown:
        {
            LOOP_COUNT_LOCAL_DEFINE(local_loop_count);
            LOOP_COUNT_SAVE(local_loop_count);

            if (IN_HLIST(HASH(&p->address), p))
                REMOVE_FROM_HLIST(HASH(&p->address), p);
            if (IN_SHLIST(SHASH(&p->address, p->sock), p))
                REMOVE_FROM_SHLIST(SHASH(&p->address, p->sock), p);
            REMOVE_FROM_TLIST(p);

            PUT_SB(p);

            orig_sys_close(p->connpd_fd);

            LOOP_COUNT_RESTORE(local_loop_count);
        }
    }

    LOOP_COUNT_RESET();
    
    SOCKP_UNLOCK();
}

/**
 *Free a socket which is returned by 'apply_socket_from_sockp'
 */
struct socket_bucket *free_socket_to_sockp(struct sockaddr *address, struct socket *s)
{
    struct socket_bucket *p, *sb = NULL;

    SOCKP_LOCK();

    for (p = SHASH(address, s); p; p = p->sb_snext) {

        LOOP_COUNT_SAFE_CHECK(p);
        
        if (SKEY_MATCH(address, s, &p->address, p->sock)) {
            if (!p->sock_in_use) {//can't release it repeatedly!
                printk(KERN_ERR "Free socket error!\n");
                break;
            }
            sb = p;

            sb->sock_in_use = 0; //clear "in use" tag.
            sb->last_used_jiffies = jiffies;

            INSERT_INTO_HLIST(HASH(address), sb);
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
        if (connpd_close_pending_fds_push(lru->connpd_fd) < 0)
            return NULL;

        ht.sb_free_p = lru->sb_free_next;

        if (IN_HLIST(HASH(&lru->address), lru))
            REMOVE_FROM_HLIST(HASH(&lru->address), lru);
        if (IN_SHLIST(SHASH(&lru->address, lru->sock), lru))
            REMOVE_FROM_SHLIST(SHASH(&lru->address, lru->sock), lru);
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
struct socket_bucket *insert_socket_to_sockp(struct sockaddr *address, 
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
    INSERT_INTO_SHLIST(SHASH(&empty->address, s), empty);
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

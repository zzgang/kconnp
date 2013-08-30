#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/spinlock.h>
#include "sys_call.h"
#include "util.h"
#include "cfg.h"
#include "sockp.h"
#include "connp.h"
#include "connpd.h"

rwlock_t connp_rwlock; //global connp read/write lock;

static void do_conn_spec_check_close_flag(void *data);
static void do_conn_inc_all_count(void *data);
static void do_conn_inc_idle_count(void *data);
static void do_conn_inc_connected_all_count(void *data);
static void do_conn_inc_connected_hit_count(void *data);

static inline int insert_socket_to_connp(struct sockaddr *, struct socket *);
static inline int insert_into_connp(struct sockaddr *, struct socket *);

static inline void deferred_destroy(void);

static int conn_close_flag; 
static void do_conn_spec_check_close_flag(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;

    if (conn_node->conn_ip != 0 && conn_node->conn_port != 0) {
        conn_close_flag = conn_node->conn_close_now;
        conn_node->conn_close_now = 0; //clear the close flag.
    }
}

int conn_spec_check_close_flag(struct sockaddr *address)
{
   unsigned int ip;
   unsigned short int port;

   ip = ((struct sockaddr_in *)address)->sin_addr.s_addr;
   port = ((struct sockaddr_in *)address)->sin_port;

   conn_close_flag = 0;

   cfg_allowd_iport_node_for_each_call(ip, port, do_conn_spec_check_close_flag); 

   return conn_close_flag;
}

static void do_conn_inc_all_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;

    ++conn_node->conn_all_count;
}

static void do_conn_inc_idle_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;
    
    ++conn_node->conn_idle_count;
}

static void do_conn_inc_connected_all_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;
    
    lkm_atomic_add(&conn_node->conn_connected_all_count, 1);
}

static void do_conn_inc_connected_hit_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;

    lkm_atomic_add(&conn_node->conn_connected_hit_count, 1);
}

int conn_inc_count(struct sockaddr *addr, int count_type)
{
   unsigned int ip;
   unsigned short int port;
   void (*conn_inc_count_func)(void *data) = NULL;

   ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
   port = ((struct sockaddr_in *)addr)->sin_port;

   if (count_type == ALL_COUNT)
       conn_inc_count_func = do_conn_inc_all_count;
   else if (count_type == IDLE_COUNT)
       conn_inc_count_func = do_conn_inc_idle_count;
   else if (count_type == CONNECTED_ALL_COUNT)
       conn_inc_count_func = do_conn_inc_connected_all_count;
   else if (count_type == CONNECTED_HIT_COUNT)
       conn_inc_count_func = do_conn_inc_connected_hit_count;

   cfg_allowd_iport_node_for_each_call(ip, port, conn_inc_count_func); 

   return 1;
}

static inline int insert_socket_to_connp(struct sockaddr *servaddr, 
        struct socket *sock)
{
    int connpd_fd;

    connpd_fd = connpd_get_unused_fd();
    if (connpd_fd < 0)
        return 0;

    task_fd_install(CONNP_DAEMON_TSKP, connpd_fd, sock->file);
    file_count_inc(sock->file); //add file reference count.

    if (!insert_sock_to_sockp(servaddr, sock, connpd_fd, SOCK_RECLAIM)) {
        connpd_close_pending_fds_in(connpd_fd);
        return 0;
    }

    return 1;
}

static inline int insert_into_connp(struct sockaddr *servaddr, struct socket *sock)
{
    int fc;

    fc = file_count_read(sock->file);
    if (fc != 1)
        return 0;

    //To free
    if (free_sk_to_sockp(sock->sk)) {
        sock->sk = NULL; //Remove reference to avoid to destroy the sk.
        return 1;
    }
    
    //To insert
    if (insert_socket_to_connp(servaddr, sock))
        return 1;

    return 0;
}

int insert_into_connp_if_permitted(int fd)
{
    struct socket *sock;
    struct sockaddr address;
    int err;

    connp_rlock();

    if (!CONNP_DAEMON_EXISTS() || INVOKED_BY_CONNP_DAEMON())
        goto ret_fail;

    if (!is_sock_fd(fd))
        goto ret_fail;

    sock = getsock(fd);
    if (!sock || !IS_TCP_SOCK(sock) || !IS_CLIENT_SOCK(sock))
        goto ret_fail;

    err = getsockservaddr(sock, &address);
    if (err)
        goto ret_fail;

    if (address.sa_family != AF_INET)
        goto ret_fail;

    if (!cfg_conn_is_positive(&address))
        goto sock_close;

    if (!SOCK_ESTABLISHED(sock)) {
        cfg_conn_set_passive(&address); //may be passive sock.
        goto sock_close;
    }

    err = insert_into_connp(&address, sock);
    
    connp_runlock();
    return err;

sock_close:
    set_sock_close_now(sock, 1);
    notify(CONNP_DAEMON_TSKP); //wake up connpd to nonconnection collection.

ret_fail:
    connp_runlock();
    return 0;
}

int fetch_conn_from_connp(int fd, struct sockaddr *address)
{
    struct socket *sock;
    struct socket_bucket *sb;
    int ret = 0; 

    connp_rlock(); 

    if (!CONNP_DAEMON_EXISTS()) {
        ret = 0;
        goto ret_unlock;
    }

    if (!is_sock_fd(fd)) {
        ret = 0;
        goto ret_unlock;
    }

    sock = getsock(fd);
    if (!sock 
            || !IS_TCP_SOCK(sock) 
            || !IS_UNCONNECTED_SOCK(sock)) {
        ret = 0;
        goto ret_unlock;
    }

    if (address->sa_family != AF_INET 
            || !cfg_conn_acl_allowd(address)) {
        ret = 0;
        goto ret_unlock;
    }
    
    conn_inc_connected_all_count(address);

    if ((sb = apply_sk_from_sockp(address))) {
        
        sock_graft(sb->sk, sock);

        SET_SOCK_STATE(sock, SS_CONNECTED);

        if (CONN_IS_NONBLOCK(sock->file)) 
            ret = CONN_NONBLOCK;
        else
            ret = CONN_BLOCK;
        
        conn_inc_connected_hit_count(address); 
    }

    SET_CLIENT_FLAG(sock);

ret_unlock:
    connp_runlock();
    return ret;
}

void connp_sys_exit_prepare()
{
    struct fd_entry *pos, *tmp;

    LIST_HEAD(fds_list);
    TASK_GET_FDS(current, &fds_list);
    list_for_each_entry_safe(pos, tmp, &fds_list, siblings) {
        insert_into_connp_if_permitted(pos->fd);
        lkmfree(pos);
    } 
}

static inline void deferred_destroy(void) 
{
    int time_going = 1 * HZ;//1s

    wait_for_timeout(time_going);
}

int connp_init()
{
    connp_rwlock_init();

    if (!cfg_init()) {
        printk(KERN_ERR "Error: cfg_init error!\n");
        return 0;
    }

    if (!sockp_init()) {
        cfg_destroy();
        printk(KERN_ERR "Error: sockp_init error!\n");
        return 0;
    }

    if (!connpd_init()) {
        sockp_destroy();
        cfg_destroy();
        printk(KERN_ERR "Error: create connp daemon thread error!\n");
        return 0;
    }

    if (!replace_syscalls()) {
        connpd_destroy();
        sockp_destroy();
        cfg_destroy();
        printk(KERN_ERR "Error: replace_syscalls error!\n");
        return 0;
    }

    return 1;
}


void connp_destroy()
{
    restore_syscalls();
    connpd_destroy();
    sockp_destroy();
    cfg_destroy();
    deferred_destroy();//make sure all threads exit the kconnp routines.
}

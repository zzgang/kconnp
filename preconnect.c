#include <linux/net.h>
#include <linux/socket.h>
#include "cfg.h"
#include "preconnect.h"
#include "util.h"
#include "sys_call.h"
#include "connp.h"

/*
 *Scan cfg entries to find the spare conns.
 *
 *If the spare counts of conns exceeds the MAX_SPARE_CONNECTIONS, shutdown the conns.
 *If the spare counts of conns lower than the MIN_SPARE_CONNECTIONS, create the conns.
 */

static inline void do_preconnect(void *data);
static inline void conn_init_count(void *data);

static int do_create_connect(struct sockaddr_in *);

static inline void conn_init_count(void *data)
{
    struct conn_node_t *conn_node;
    
    conn_node = (typeof(conn_node))data;
    conn_node->conn_all_count = 0;
    conn_node->conn_idle_count = 0;
}

static inline void do_preconnect(void *data)
{
    struct conn_node_t *conn_node;
    struct sockaddr_in address;
    unsigned int idle_count;
    int i;

    conn_node = (typeof(conn_node))data;

    if (conn_node->conn_ip == 0 || conn_node->conn_port == 0)
        return;

    idle_count = conn_node->conn_idle_count;    
 
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = conn_node->conn_ip;
    address.sin_port = conn_node->conn_port;

    //set close flag for one group conns.
    if (idle_count > MAX_SPARE_CONNECTIONS) {
        conn_node->conn_close_now = 1;
        return;
    }
    
    //do preconnect
    for (i = MIN_SPARE_CONNECTIONS - idle_count; i > 0; i--)
        if (!do_create_connect(&address))
            return;

    return;
}

static int do_create_connect(struct sockaddr_in *address)
{
    int fd;
    struct socket *sock;
     
    fd = lkm_create_tcp_connect(address);
    if (fd < 0)
        return 0;

    sock = getsock(fd); 
   
    if (!insert_socket_to_sockp((struct sockaddr *)address, sock, fd, 
                SOCK_PRECONNECT)) {
        orig_sys_close(fd);
        return 0;
    } 

    return fd;
}

void scan_spare_conns_preconnect()
{
    cfg_allowed_entries_for_each_call(do_preconnect);
    cfg_allowed_entries_for_each_call(conn_init_count);
}

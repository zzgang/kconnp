#include <linux/net.h>
#include <linux/socket.h>
#include "cfg.h"
#include "preconnect.h"
#include "lkm_util.h"
#include "sys_call.h"
#include "connp.h"

/*
 *Scan cfg entries to find the spare conns.
 *
 *If the spare counts of conns exceeds the MAX_SPARE_CONNECTIONS, shutdown the conns.
 *If the spare counts of conns lower than the MIN_SPARE_CONNECTIONS, create the conns.
 */

static void do_preconnect(void *data);
static void conn_init_count(void *data);

static void do_create_connects(struct sockaddr_in *, int nums);

static void conn_init_count(void *data)
{
    struct conn_node_t *conn_node;
    
    conn_node = (typeof(conn_node))data;
    conn_node->conn_all_count = 0;
    conn_node->conn_idle_count = 0;
}

static void do_preconnect(void *data)
{
    struct conn_node_t *conn_node;
    struct sockaddr_in address;
    unsigned int idle_count;
    int preconnect_nums;

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
    preconnect_nums = MIN_SPARE_CONNECTIONS - idle_count;
    do_create_connects(&address, preconnect_nums);

    return;
}

static void do_create_connects(struct sockaddr_in *servaddr, int nums)
{
    int fd;
    struct socket *sock;
    struct sockaddr cliaddr;
    int i;

    for (i = 0; i < nums; i++) {

        fd = lkm_create_tcp_connect(servaddr);
        if (fd < 0)
            break;

        sock = getsock(fd); 
        if (!sock)
            break;
            
        if (!getsockcliaddr(sock, &cliaddr))
            break;
        
        if (insert_sock_to_sockp(&cliaddr, 
                    (struct sockaddr *)servaddr,
                    sock, fd, 
                    SOCK_PRECONNECT, 
                    NULL) != KCP_OK) {
            orig_sys_close(fd);
            break;
        } 
    }

    return;
}

void scan_spare_conns_preconnect()
{
    cfg_allowed_entries_for_each_call(do_preconnect);
    cfg_allowed_entries_for_each_call(conn_init_count);
}

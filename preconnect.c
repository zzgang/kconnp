#include <linux/net.h>
#include <linux/socket.h>
#include "cfg.h"
#include "preconnect.h"
#include "util.h"
#include "sys_call.h"

/*
 *Scan cfg entries to find the spare conns.
 *
 *If the spare counts of conns exceeds the MAX_SPARE_CONNECTIONS, shutdown the conns.
 *If the spare counts of conns lower than the MIN_SPARE_CONNECTIONS, create the conns.
 */

static int do_preconnect(void *data);
static int init_conn_count(void *data);
static int do_create_connect(struct sockaddr_in *);

static int init_conn_count(void *data)
{
    struct conn_node_t *conn_node;
    
    conn_node = (typeof(conn_node))data;
    conn_node->conn_all_count = 0;
    conn_node->conn_idle_count = 0;
    
    return 1;
}

static int do_preconnect(void *data)
{
    struct conn_node_t *conn_node;
    struct sockaddr_in address;
    unsigned int idle_count;
    int i;

    conn_node = (typeof(conn_node))data;
    idle_count = conn_node->conn_idle_count;    
 
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = conn_node->conn_ip;
    address.sin_port = conn_node->conn_port;
    
    //do preconnect
    for (i = MIN_SPARE_CONNECTIONS - idle_count; i > 0; i--)
        if (!do_create_connect(&address))
            return 0;

    return 1;
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
    cfg_allowed_entries_for_each_call_directly(init_conn_count);
}


static int g_count = 0;
static int do_add_conn_all_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;

    conn_node->conn_all_count += g_count;
    return conn_node->conn_all_count;
}

static int iport_spec_exists = 0;
static int iport_spec_conn_idle_count = 0;
static int do_add_conn_idle_count(void *data)
{
    struct conn_node_t *conn_node = (typeof(conn_node))data;
    
    conn_node->conn_idle_count += g_count;

    if (conn_node->conn_ip != 0 && conn_node->conn_port != 0) {
        iport_spec_exists = 1;
        iport_spec_conn_idle_count = conn_node->conn_idle_count;
    }

    return g_count;
}

int add_conn_count(struct sockaddr *addr, int count, int count_type)
{
   int (*add_conn_count_func)(void *data);

   g_count = count;

   if (count_type == ALL_COUNT)
       add_conn_count_func = do_add_conn_all_count;
   else if (count_type == IDLE_COUNT)
       add_conn_count_func = do_add_conn_idle_count;
   else
       return 0;

   cfg_allowd_iport_node_for_each_call(addr, add_conn_count_func); 

   g_count = 0;

   if (count_type == IDLE_COUNT && iport_spec_exists) {
       iport_spec_exists = 0;
       return iport_spec_conn_idle_count;
   }

   return count;
}

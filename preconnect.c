#include "cfg.h"
#include "preconnect.h"

/*
 *Scan cfg entries to find the spare conns.
 *
 *If the spare counts of conns exceeds the MAX_SPARE_CONNECTIONS, shutdown the conns.
 *If the spare counts of conns lower than the MIN_SPARE_CONNECTIONS, create the conns.
 */

static int do_preconnect(void *data);
static int do_connect(struct sockaddr_in *);


static int do_preconnect(void *data)
{
    struct conn_node_t *conn_node;
    struct sockaddr_in address;
    unsigned int idle_count;
    int i;

    conn_node = (typeof(conn_node))data;
    address.sin_addr.s_addr = conn_node->conn_ip;
    address.sin_port = conn_node->conn_port;
    idle_count = conn_node->conn_idle_count;    
    
    //initial again.
    conn_node->conn_all_count = 0;
    conn_node->conn_idle_count = 0;

    //do preconnect
    for (i = MIN_SPARE_CONNECTIONS - idle_count; i > 0; i--)
        if (!do_connect(&address))
            return 0;

    return 1;
}

static int do_connect(struct sockaddr_in *address)
{
    return 1;
}

void scan_spare_conns_preconnect()
{
    cfg_allowed_entries_for_each_call(do_preconnect);
}

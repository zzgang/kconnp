#ifndef _CFG_H
#define _CFG_H

#include <linux/socket.h>
#include <linux/proc_fs.h>
#include "connp.h"

#define CFG_BASE_DIR_NAME "kconnp"

struct cfg_entry {
    /*attributes*/
    char *f_name; /*cfg file name*/
    struct proc_dir_entry *cfg_proc_file;  
    unsigned int raw_len; /*the data length read from the procfile*/
    char *raw_ptr; /*cfg raw data pointer*/ 
    void *cfg_ptr; /*handle the cfg storage*/

    /*cfg funcs*/
    int (*init)(struct cfg_entry *); 
    void (*destroy)(struct cfg_entry *); 
    int (*reload)(struct cfg_entry *); 
};

struct iport_t {
    unsigned int ip;
    unsigned short int port;
};

struct conn_node_t {
    struct iport_t iport_node;
#define conn_ip iport_node.ip
#define conn_port iport_node.port
    struct conn_attr_t conn_attrs;
#define conn_close_way conn_attrs.close_way
#define conn_all_count conn_attrs.stats.all_count
#define conn_idle_count conn_attrs.stats.idle_count
};

struct iport_str_t {
    int line; //the line NO! where the iport located of the cfg proc file.
    char *ip_str;
    char *port_str;
    struct iport_str_t *next;
};

struct iports_str_list_t {
    struct iport_str_t *list;
    int count;
};

struct iport_pos_t {
    int ip_start;
    int ip_end;
    int port_start;
    int port_end;
};

extern struct conn_node_t *iport_in_allowd_list(struct sockaddr *);
extern struct conn_node_t *iport_in_denied_list(struct sockaddr *);

#define ACL_CHECK 0x0
#define ACL_SPEC_CHECK 0x1
#define POSITIVE_CHECK 0x2
#define PASSIVE_SET 0x3

#define cfg_conn_acl_allowd(addr) cfg_conn_op(addr, ACL_CHECK)
#define cfg_conn_acl_spec_allowd(addr) cfg_conn_op(addr, ACL_SPEC_CHECK)
#define cfg_conn_is_positive(addr) cfg_conn_op(addr, POSITIVE_CHECK)
#define cfg_conn_set_passive(addr) cfg_conn_op(addr, PASSIVE_SET)

static inline int cfg_conn_op(struct sockaddr *address, int op_type)
{
    struct conn_node_t *conn_node;

    if (iport_in_denied_list(address))
        return 0;
   
    conn_node = iport_in_allowd_list(address); 
    if (!conn_node)
        return 0;

    switch (op_type) {
        case ACL_CHECK:
            return (conn_node ? 1 : 0);
        case ACL_SPEC_CHECK:
            return (conn_node->conn_ip != 0 && conn_node->conn_port != 0);
        case POSITIVE_CHECK:
            return (conn_node->conn_close_way == CLOSE_POSITIVE);
        case PASSIVE_SET:
            conn_node->conn_close_way = CLOSE_PASSIVE;
        default:
            return 0;
    }

    return 1;
}

extern int cfg_init(void);
extern void cfg_destroy(void);
extern void cfg_allowed_entries_for_each_call(int (*call_func)(void *data));

#endif

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
    time_t mtime;
    rwlock_t cfg_rwlock;

    /*proc r/w funcs*/
    int (*proc_read)(char *buffer,
                    char **buffer_location,
                            off_t offset, int buffer_length, int *eof, void *data);
    int (*proc_write)(struct file *file, const char *buffer, unsigned long count, 
            void *data);

    /*cfg funcs*/
    int (*init)(struct cfg_entry *); 
    void (*destroy)(struct cfg_entry *); 

    int (*entity_init)(struct cfg_entry *);
    void (*entity_destroy)(struct cfg_entry *);
    int (*entity_reload)(struct cfg_entry *); 
};

struct iport_t {
    //ip and port must be first elements
    unsigned int ip;
    unsigned short int port;
    unsigned int flags;
};

struct iport_raw_t {
    unsigned int ip;
    unsigned short int port;
};

struct conn_node_t {
    struct iport_raw_t iport_node;
#define conn_ip iport_node.ip
#define conn_port iport_node.port
    struct conn_attr_t conn_attrs;
#define conn_flags conn_attrs.flags
#define conn_close_way conn_attrs.close_way
#define conn_keep_alive conn_attrs.keep_alive
#define conn_close_now conn_attrs.close_now
#define conn_all_count conn_attrs.stats.all_count
#define conn_idle_count conn_attrs.stats.idle_count
#define conn_connected_all_count conn_attrs.stats.connected_all_count
#define conn_connected_hit_count conn_attrs.stats.connected_hit_count
};

struct iport_str_t {
    int line; //the line NO! where the iport located of the cfg proc file.

    char *ip_str;
    char *port_str;
    char *flags_str;

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

    int flags_start;
    int flags_end;
};

#define ACL_CHECK               0x0
#define ACL_SPEC_CHECK          0x1
#define POSITIVE_CHECK          0x2
#define PASSIVE_SET             0x3
#define KEEP_ALIVE_SET          0x4
#define KEEP_ALIVE_GET          0x5

#define cfg_conn_acl_allowd(addr) cfg_conn_op(addr, ACL_CHECK, NULL)
#define cfg_conn_acl_spec_allowd(addr) cfg_conn_op(addr, ACL_SPEC_CHECK, NULL)
#define cfg_conn_is_positive(addr) cfg_conn_op(addr, POSITIVE_CHECK, NULL)
#define cfg_conn_set_passive(addr) cfg_conn_op(addr, PASSIVE_SET, NULL)
#define cfg_conn_set_keep_alive(addr, val) cfg_conn_op(addr, KEEP_ALIVE_SET, val)
#define cfg_conn_get_keep_alive(addr, val) cfg_conn_op(addr, KEEP_ALIVE_GET, val)

extern int cfg_conn_op(struct sockaddr *addr, int op_type, void *val);

extern void cfg_allowed_entries_for_each_call(void (*call_func)(void *data));

extern void cfg_allowd_iport_node_for_each_call(unsigned int ip, unsigned short int port ,void (*call_func)(void *data));

extern int cfg_init(void);
extern void cfg_destroy(void);

#endif

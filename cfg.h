#ifndef _CFG_H
#define _CFG_H

#include <linux/socket.h>
#include <linux/proc_fs.h>
#include "connp.h"
#include "hash.h"
#include "kconnp.h"

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    int (*proc_read)(char __user *buffer, char **buffer_location, off_t offset, 
            int buffer_length, int *eof, void *data);
    int (*proc_write)(struct file *file, const char __user *buffer, unsigned long count, 
            void *data);
#else
    struct file_operations *proc_fops;
    int (*proc_read)(struct seq_file *seq, void *offset);
    ssize_t (*proc_write)(struct file *file, const char __user *buffer, size_t count, 
            loff_t *pos);
#endif

    /*cfg funcs*/
    int (*init)(struct cfg_entry *); 
    void (*destroy)(struct cfg_entry *); 

    int (*proc_file_init)(struct cfg_entry *); 
    void (*proc_file_destroy)(struct cfg_entry *); 

    int (*entity_init)(struct cfg_entry *);
    void (*entity_destroy)(struct cfg_entry *);
    int (*entity_reload)(struct cfg_entry *); 
};

struct cfg_dir {
    struct cfg_entry global;
#define gl global
#define gl_ptr global.cfg_ptr
#define gl_rwlock global.cfg_rwlock
    struct cfg_entry allowed_list;
#define al allowed_list
#define al_ptr allowed_list.cfg_ptr
#define al_rwlock allowed_list.cfg_rwlock
    struct cfg_entry denied_list;
#define dl denied_list
#define dl_ptr denied_list.cfg_ptr
#define dl_rwlock denied_list.cfg_rwlock
    struct cfg_entry prim_list;
#define pl prim_list
#define pl_ptr prim_list.cfg_ptr
#define pl_rwlock prim_list.cfg_rwlock
    struct cfg_entry stats_info;
#define st stats_info
#define st_ptr stats_info.raw_ptr
#define st_len stats_info.raw_len
#define st_rwlock stats_info.cfg_rwlock
};

extern struct cfg_dir *cfg;

typedef struct pos { //start and end pos
    int start;
    int end;
} pos_t;

struct item_str_t {
    int line; //the line NO! where the cfg item located in the global cfg proc file.

    kconnp_str_t name;
    kconnp_str_t value;

    struct item_str_t *next;
};

struct items_str_list_t {
    struct item_str_t *list;
    struct item_str_t *tail;
    int count;
};

struct item_pos_t {
    pos_t name_pos;
#define name_start name_pos.start
#define name_end name_pos.end
    pos_t value_pos;
#define value_start value_pos.start
#define value_end value_pos.end
};

typedef enum {
    INTEGER = 1,
    STRING
} node_type;

struct item_node_t {
    //item node
    kconnp_str_t name;

    kconnp_value_t value;
#define v_strlen value.str.len
#define v_str value.str.data
#define v_lval value.lval
    
    void *data;

    int (*cfg_item_set_node)(struct item_node_t *node, kconnp_str_t *str); 
};
#define MAX_PRIMITIVE_LEN 64
#define MAX_SN_PADDING_ZERO_LEN 33 /*real max length is (MAX_SN_PADDING_NULL_LEN - 1)*/
struct iport_t {
    //Ip and port must be first elements
    unsigned int ip;
    unsigned short int port;
    unsigned int flags;
    struct { 
        char data[MAX_SN_PADDING_ZERO_LEN];
        unsigned int len;
    } sn;
};

struct iport_raw_t {
    unsigned int ip;
    unsigned short int port;
};

struct conn_node_t {
    struct iport_t iport_node;
#define conn_ip iport_node.ip
#define conn_port iport_node.port
#define conn_flags iport_node.flags
#define conn_sn iport_node.sn

    /*direct access*/
    struct item_node_t *prim_node; 

    struct conn_attr_t conn_attrs;
#define conn_close_way conn_attrs.close_way_attrs.close_way
#define conn_close_way_last_set_jiffies conn_attrs.close_way_attrs.last_set_jiffies
#define conn_keep_alive conn_attrs.keep_alive
#define conn_close_now conn_attrs.close_now
#define conn_all_count conn_attrs.stats.all_count
#define conn_idle_count conn_attrs.stats.idle_count
#define conn_connected_hit_count conn_attrs.stats.connected_hit_count
#define conn_connected_miss_count conn_attrs.stats.connected_miss_count
};

struct iport_str_t {
    int line; //the line NO! where the iport located in the cfg proc file.

    char *sn_str;
    char *ip_str;
    char *port_str;
    char *flags_str;

    struct iport_str_t *next;
};

struct iports_str_list_t {
    struct iport_str_t *list;
    struct iport_str_t *tail;
    int count;
};

struct iport_pos_t {
    pos_t sn_pos;
#define sn_start sn_pos.start
#define sn_end sn_pos.end
    pos_t ip_pos;
#define ip_start ip_pos.start
#define ip_end ip_pos.end
    pos_t port_pos;
#define port_start port_pos.start
#define port_end port_pos.end
    pos_t flags_pos;
#define flags_start flags_pos.start
#define flags_end flags_pos.end
};

#define ACL_CHECK               0x0
#define ACL_SPEC_CHECK          0x1
#define POSITIVE_CHECK          0x2
#define PASSIVE_SET             0x3
#define KEEP_ALIVE_SET          0x4
#define KEEP_ALIVE_GET          0x5
#define CHECK_PRIMITIVE         0x6

#define cfg_conn_acl_allowed(addr) cfg_conn_op(addr, ACL_CHECK, NULL)
#define cfg_conn_acl_spec_allowed(addr) cfg_conn_op(addr, ACL_SPEC_CHECK, NULL)
#define cfg_conn_is_positive(addr) cfg_conn_op(addr, POSITIVE_CHECK, NULL)
#define cfg_conn_set_passive(addr) cfg_conn_op(addr, PASSIVE_SET, NULL)
#define cfg_conn_set_keep_alive(addr, val) cfg_conn_op(addr, KEEP_ALIVE_SET, val)
#define cfg_conn_get_keep_alive(addr, val) cfg_conn_op(addr, KEEP_ALIVE_GET, val)
#define cfg_conn_check_primitive(addr, val) cfg_conn_op(addr, CHECK_PRIMITIVE, val)

extern int cfg_conn_op(struct sockaddr *addr, int op_type, void *val);

extern void cfg_allowed_entries_for_each_call(void (*call_func)(void *data));

extern void cfg_allowed_iport_node_for_each_call(unsigned int ip, unsigned short int port ,void (*call_func)(void *data));

extern int cfg_init(void);
extern void cfg_destroy(void);

static inline long cfg_item_get_value(struct cfg_entry *ce, const char *name, int len, kconnp_value_t *value, node_type type) 
{
    struct item_node_t *item_node;
    int ret;
    
    read_lock(&ce->cfg_rwlock);
    
    if (!ce->cfg_ptr) { //init default value.
        if (value)
            memset(value, 0, sizeof(kconnp_value_t));
        ret = 0;
        goto ret_unlock;
    }

    if (hash_find((struct hash_table_t *)ce->cfg_ptr, 
                name, len, 
                (void **)&item_node)) {

        switch (type) {
            case STRING:
                if (value) {
                    value->str.data = lkmalloc(item_node->v_strlen);
                    if (!value->str.data) {
                        ret = -1;
                        goto ret_unlock;
                    }
                    memcpy(value->str.data, item_node->v_str, item_node->v_strlen); 
                    value->str.len = item_node->v_strlen;
                    ret = 1;
                } else 
                    ret = -1;
                break;
            case INTEGER:
                if (value) {
                    value->lval = item_node->v_lval;
                    ret = 1;
                } else 
                    ret = item_node->v_lval;
                break;
            default:
                ret = -1;
                break;
        }

    } else {
       printk(KERN_ERR 
               "The item name %s is not found in file /proc/%s/%s\n", 
               name, CFG_BASE_DIR_NAME, ce->f_name);
       ret = -1;
    }

ret_unlock:
    read_unlock(&ce->cfg_rwlock);

    return ret;
}

#define GN(name) cfg_item_get_value(&cfg->global, name, sizeof(name)-1, NULL, INTEGER)
#define GVS(name, vp) cfg_item_get_value(&cfg->global, name, sizeof(name)-1, vp, STRING)

#define lkm_proc_mkdir(dname) proc_mkdir(dname, NULL)
#define lkm_proc_rmdir(dname) remove_proc_entry(dname, NULL)

#define lkm_proc_remove(fname, parent) remove_proc_entry(fname, parent)

#endif

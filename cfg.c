#include <linux/string.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include "connp.h"
#include "lkm_util.h"
#include "hash.h"
#include "cfg.h"

#define CFG_GLOBAL_FILE                        "kconnp.conf"
#define CFG_ALLOWED_IPORTS_FILE     		   "iports.allow"
#define CFG_DENIED_IPORTS_FILE                 "iports.deny"
#define CFG_COMMUNICATION_PRIMITIVES_FILE      "primitives.deny"
#define CFG_CONN_STATS_INFO_FILE               "stats.info"

#define DUMP_INTERVAL 5 //seconds

#define cfg_entries_walk_func_check(func_name)    \
    ({    \
        int __check_ret = 1;    \
        struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;  \
        for (p = entry; \
                p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++) {\
            if (!p->func_name(p)) {  \
                __check_ret = 0;        \
                break;                  \
            } \
        } \
        __check_ret;    \
    })

#define cfg_entries_walk_func_no_check(func_name) \
    do {    \
        struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;  \
        for (p = entry; \
                p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++)\
            p->func_name(p);   \
    } while (0)

#define NEW_ITEM_STR_NODE(item_str, item_pos)                                       \
    do {                                                                            \
        item_str = lkmalloc(sizeof(struct item_str_t));                             \
        if (!(item_str))                                                            \
            return 0;                                                               \
        (item_str)->name.len = (item_pos)->name_end - (item_pos)->name_start + 1;   \
        (item_str)->name.data = lkmalloc((item_str)->name.len + 1/*padding '\0'*/); \
        if (!(item_str)->name.data)                                                 \
            return 0;                                                               \
        if ((item_pos)->value_start < 0)                                            \
            break;                                                                  \
        (item_str)->value.len = (item_pos)->value_end - (item_pos)->value_start + 1;\
        (item_str)->value.data = lkmalloc((item_str)->value.len + 1);               \
        if (!(item_str)->value.data) {                                              \
            lkmfree((item_str)->name.data);                                         \
            return 0;                                                               \
        }                                                                           \
    } while (0)                                                                 

#define INIT_ITEM_STR_NODE(item_str, ce, item_pos, line_pass)       \
    do {                                                            \
        memcpy((item_str)->name.data,                               \
                ce->raw_ptr + (item_pos)->name_start,               \
                (item_str)->name.len);                              \
        if ((item_str)->value.data) {                               \
            memcpy((item_str)->value.data,                          \
                    ce->raw_ptr + (item_pos)->value_start,          \
                    (item_str)->value.len);                         \
        }                                                           \
        (item_str)->line = line_pass;                               \
    } while (0)

#define INSERT_INTO_ITEMS_LIST(items_list, item)    \
    do {                                            \
        if (!(items_list)->list)                    \
            (items_list)->list = item;              \
        if ((items_list)->tail)                     \
            (items_list)->tail->next = item;        \
        (items_list)->tail = item;                  \
        (items_list)->count++;                      \
    } while (0)

#define DESTROY_ITEM_STR_NODE(item_str)         \
    do {                                        \
        lkmfree(item_str->name.data);           \
        lkmfree(item_str->value.data);          \
        lkmfree(item_str);                      \
    } while (0)                                 \

#define INIT_ITEM_POS(item_pos)                 \
    do {                                        \
        (item_pos)->name_start = -1;            \
        (item_pos)->name_end = -1;              \
        (item_pos)->value_start = -1;           \
        (item_pos)->value_end = -1;             \
    } while (0)

#define INIT_IPORT_POS(iport_pos)           \
    do {                                    \
        (iport_pos)->sn_start = -1;         \
        (iport_pos)->sn_end = -1;           \
        (iport_pos)->ip_start = -1;         \
        (iport_pos)->ip_end = -1;           \
        (iport_pos)->port_start = -1;       \
        (iport_pos)->port_end = -1;         \
        (iport_pos)->flags_start = -1;      \
        (iport_pos)->flags_end = -1;        \
    } while (0)

#define NEW_IPORT_STR_NODE(iport_str, sn_strlen, ip_strlen, port_strlen, flags_strlen) \
    do {                                                        \
        iport_str = lkmalloc(sizeof(struct iport_str_t));       \
        if (!iport_str)                                         \
            return 0;                                           \
        (iport_str)->sn_str = lkmalloc(sn_strlen);              \
        if (!(iport_str)->sn_str) {                             \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        (iport_str)->ip_str = lkmalloc(ip_strlen);              \
        if (!(iport_str)->ip_str) {                             \
            lkmfree((iport_str)->sn_str);                       \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        (iport_str)->port_str = lkmalloc(port_strlen);          \
        if (!(iport_str)->port_str) {                           \
            lkmfree((iport_str)->ip_str);                       \
            lkmfree((iport_str)->sn_str);                       \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        if (flags_strlen) {                                     \
            (iport_str)->flags_str = lkmalloc(flags_strlen);    \
            if (!(iport_str)->flags_str) {                      \
                lkmfree((iport_str)->port_str);                 \
                lkmfree((iport_str)->ip_str);                   \
                lkmfree((iport_str)->sn_str);                   \
                lkmfree(iport_str);                             \
                return 0;                                       \
            }                                                   \
        }                                                       \
    } while (0)  

#define INIT_IPORT_STR_NODE(iport_str,                                      \
        sn_str_pass, sn_strlen,                                             \
        ip_str_pass, ip_strlen,                                             \
        port_str_pass, port_strlen,                                         \
        flags_str_pass, flags_strlen,                                       \
        line_pass)                                                          \
    do {                                                                    \
        memcpy((iport_str)->sn_str, sn_str_pass, sn_strlen);                \
        memcpy((iport_str)->ip_str, ip_str_pass, ip_strlen);                \
        memcpy((iport_str)->port_str, port_str_pass, port_strlen);          \
        if ((iport_str)->flags_str)                                         \
            memcpy((iport_str)->flags_str, flags_str_pass, flags_strlen);   \
        (iport_str)->line = line_pass;                                      \
    } while (0)

#define DESTROY_IPORT_STR_NODE(iport_str)                           \
    do {                                                            \
        lkmfree((iport_str)->sn_str);                               \
        lkmfree((iport_str)->ip_str);                               \
        lkmfree((iport_str)->port_str);                             \
        if ((iport_str)->flags_str)                                 \
            lkmfree((iport_str)->flags_str);                        \
        lkmfree(iport_str);                                         \
    } while (0)

#define INSERT_INTO_IPORTS_LIST(iports_list, iport) \
    INSERT_INTO_ITEMS_LIST(iports_list, iport) 

#define NEW_IPORT_STR_SCAN_NODE(iport_str, iport_pos)                           \
    NEW_IPORT_STR_NODE(iport_str,                                               \
            (iport_pos)->sn_end - (iport_pos)->sn_start + 2, /*padding '\0'*/   \
            (iport_pos)->ip_end - (iport_pos)->ip_start + 2, /*padding '\0'*/   \
            (iport_pos)->port_end - (iport_pos)->port_start + 2,/*padding '\0'*/\
            ((iport_pos)->flags_end >= 0 && (iport_pos)->flags_start >= 0)      \
            ? ((iport_pos)->flags_end - (iport_pos)->flags_start + 2) : 0)  

#define INIT_IPORT_STR_SCAN_NODE(iport_str, ce, iport_pos, line)    \
    INIT_IPORT_STR_NODE(iport_str,                                  \
            (ce)->raw_ptr + (iport_pos)->sn_start,                  \
            (iport_pos)->sn_end - (iport_pos)->sn_start + 1,        \
            (ce)->raw_ptr + (iport_pos)->ip_start,                  \
            (iport_pos)->ip_end - (iport_pos)->ip_start + 1,        \
            (ce)->raw_ptr + (iport_pos)->port_start,                \
            (iport_pos)->port_end - (iport_pos)->port_start + 1,    \
            (ce)->raw_ptr + (iport_pos)->flags_start,               \
            (iport_pos)->flags_end - (iport_pos)->flags_start + 1,  \
            line)


/*Global cfg funcs*/
static int item_line_scan(struct cfg_entry *, int *pos, int *line, 
        struct item_pos_t *);
static int item_line_parse(struct item_str_t *, struct cfg_entry *);
static void items_str_list_free(struct items_str_list_t *);
static int cfg_items_data_scan(struct items_str_list_t *, struct cfg_entry *);
static int cfg_items_data_parse(struct items_str_list_t *, struct cfg_entry *);

/*iports list cfg funcs*/
static int ip_aton(const char *, struct in_addr *); //For IPV4
static int iport_line_scan(struct cfg_entry *, 
        int *pos, int *line, 
        struct iport_pos_t *);
static int iport_line_parse(struct iport_str_t *, 
        char *flags_str, char *port_str, char *ip_or_prefix, 
        int *ip_range_start, int *ip_range_end,
        char *sn_str);
static void iports_str_list_free(struct iports_str_list_t *);
static int cfg_iports_data_scan(struct iports_str_list_t *, struct cfg_entry *);
static int cfg_iports_data_parse(struct iports_str_list_t *, 
        struct iports_str_list_t *, struct cfg_entry *);

static inline struct cfg_entry *cfg_get_ce(void *);

static int cfg_iports_entity_init(struct cfg_entry *);
static void cfg_iports_entity_destroy(struct cfg_entry *);
static int cfg_iports_entity_reload(struct cfg_entry *);

static int cfg_white_list_init(struct cfg_entry *);
static void cfg_white_list_destroy(struct cfg_entry *);

static int cfg_white_list_entity_init(struct cfg_entry *);
static void cfg_white_list_entity_destroy(struct cfg_entry *);
static int cfg_white_list_entity_reload(struct cfg_entry *);

static int cfg_stats_info_entity_init(struct cfg_entry *);
static void cfg_stats_info_entity_destroy(struct cfg_entry *);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int cfg_proc_read(char *buffer, char **buffer_location,
                        off_t offset, int buffer_length, int *eof, void *data);
static int cfg_proc_write(struct file *file, const char *buffer, unsigned long count,
                        void *data);
#else

static int cfg_proc_read(struct seq_file *seq, void *offset);
static ssize_t cfg_proc_write(struct file *file, const char __user *buffer, size_t count,
        loff_t *pos);
#endif

static int cfg_entry_init(struct cfg_entry *); 
static void cfg_entry_destroy(struct cfg_entry *); 

static int cfg_proc_file_init(struct cfg_entry *); 
static void cfg_proc_file_destroy(struct cfg_entry *); 

static int cfg_prims_entity_init(struct cfg_entry *); 
static void cfg_items_entity_destroy(struct cfg_entry *); 
static int cfg_items_entity_reload(struct cfg_entry *); 
static int cfg_global_entity_init(struct cfg_entry *); 

static int cfg_item_set_int_node(struct item_node_t *node, kconnp_str_t *str);
static int cfg_item_set_str_node(struct item_node_t *node, kconnp_str_t *str);


static inline void *iport_in_list_check_or_call(unsigned int ip, unsigned short int port,  struct cfg_entry *, void (*call_func)(void *data));

static struct cfg_dir cfg_dentry = { //initial the cfg directory.
    .global = {
        .f_name = CFG_GLOBAL_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_global_entity_init,
        .entity_destroy = cfg_items_entity_destroy,
        .entity_reload = cfg_items_entity_reload
    },
    .allowed_list = { 
        .f_name = CFG_ALLOWED_IPORTS_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_iports_entity_init,
        .entity_destroy = cfg_iports_entity_destroy,
        .entity_reload = cfg_iports_entity_reload
    },
    .denied_list = {
        .f_name = CFG_DENIED_IPORTS_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_iports_entity_init,
        .entity_destroy = cfg_iports_entity_destroy,
        .entity_reload = cfg_iports_entity_reload
    },
    .prim_list = { //communication primitives
        .f_name = CFG_COMMUNICATION_PRIMITIVES_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_prims_entity_init,
        .entity_destroy = cfg_items_entity_destroy,
        .entity_reload = cfg_items_entity_reload
    },
    .stats_info = {
        .f_name = CFG_CONN_STATS_INFO_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = NULL,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_stats_info_entity_init,
        .entity_destroy = cfg_stats_info_entity_destroy,
        .entity_reload = NULL
    }
};

struct cfg_dir *cfg = &cfg_dentry;

static struct proc_dir_entry *cfg_base_dir;

//white list.
static struct cfg_entry white_list = { //final ACL list.
    .init = cfg_white_list_init,
    .destroy = cfg_white_list_destroy,

    .entity_init = cfg_white_list_entity_init,
    .entity_destroy = cfg_white_list_entity_destroy,
    .entity_reload = cfg_white_list_entity_reload
};
static struct cfg_entry *wl = &white_list;

static struct item_node_t cfg_global_items[] = {
    {
        .name = CONST_STRING("connection_wait_timeout"),
        .v_lval = 30,
        .cfg_item_set_node = cfg_item_set_int_node,
    },
    {
        .name = CONST_STRING("max_connections"),
        .v_lval = 1000,
        .cfg_item_set_node = cfg_item_set_int_node,
    },
    {
        .name = CONST_STRING("max_requests_per_connection"),
        .v_lval = 0,
        .cfg_item_set_node = cfg_item_set_int_node,
    },
    {
        .name = CONST_STRING("min_spare_connections_per_iport"),
        .v_lval = 10,
        .cfg_item_set_node = cfg_item_set_int_node,
    },
    {
        .name = CONST_STRING("max_spare_connections_per_iport"),
        .v_lval = 20,
        .cfg_item_set_node = cfg_item_set_int_node,
    },
    {CONST_STRING_NULL, }
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
/* Arguments
 * =========
 * 1. The buffer where the data is to be inserted, if
 *    you decide to use it.
 * 2. A pointer to a pointer to characters. This is
 *    useful if you don't want to use the buffer
 *    allocated by the kernel.
 * 3. The current position in the file
 * 4. The size of the buffer in the first argument.
 * 5. Write a "1" here to indicate EOF.
 * 6. A pointer to data (useful in case one common
 *    read for multiple /proc/... entries)
 *
 * Usage and Return Value
 * ======================
 * A return value of zero means you have no further
 * information at this time (end of file). A negative
 * return value is an error condition.
 */
static int cfg_proc_read(char *buffer, char **buffer_location,
        off_t offset, int buffer_length, int *eof, void *data)
{
    int read_count = 0;
    struct cfg_entry *ce;

    ce = cfg_get_ce(data);
    if (!ce) 
        return -EINVAL;

    read_lock(&ce->cfg_rwlock);

    if (offset >= ce->raw_len) { //has read all data.
        *eof = 1;
        
        goto out_ret;
   }

    read_count = buffer_length > (ce->raw_len - offset) 
        ? (ce->raw_len - offset) : buffer_length;

    memcpy(buffer, ce->raw_ptr + offset, read_count);

out_ret:
    read_unlock(&ce->cfg_rwlock);
    return read_count; 
}

/*
 * This function is called with the /proc file is written
 */
static int cfg_proc_write(struct file *file, const char *buffer, unsigned long count,
        void *data)
{
    struct cfg_entry *ce;
    char *old_raw_ptr = NULL;
    int old_raw_len = 0;

    if (!count) 
        return 0; 

    ce = cfg_get_ce(data);
    if (!ce)
        return -EINVAL;
    
    if (count > PAGE_SIZE) {
        printk(KERN_ERR 
                "Error: The cfg iports file /etc/%s exceeds the max size %lu bytes!",
                ce->f_name, PAGE_SIZE);
        return -EINVAL;
    }

    write_lock(&ce->cfg_rwlock);

    if (ce->raw_ptr) {
        /*Remove ldcfg for safety*/
        old_raw_ptr = ce->raw_ptr;
        old_raw_len = ce->raw_len;
    }

    ce->raw_ptr = lkmalloc(count);
    if (!ce->raw_ptr) {
        write_unlock(&ce->cfg_rwlock);
        return -ENOMEM;
    }

    ce->raw_len = count;

    /* Write data to the buffer */
    if (copy_from_user(ce->raw_ptr, buffer, count)) {
        lkmfree(ce->raw_ptr);
        ce->raw_ptr = old_raw_ptr; //Restore
        ce->raw_len = old_raw_len;
        
        write_unlock(&ce->cfg_rwlock);
        return -EFAULT;
    }
    
    write_unlock(&ce->cfg_rwlock);

    if (old_raw_ptr) {
        lkmfree(old_raw_ptr);
    }
   
    ce->entity_reload(ce); //Reload proc cfg.

    return count;
}

#else

static int cfg_proc_read(struct seq_file *seq, void *offset)
{
    struct cfg_entry *ce;
    
    ce = cfg_get_ce(seq->private);
    if (!ce) 
        return -EINVAL;

    read_lock(&ce->cfg_rwlock);
    seq_write(seq, ce->raw_ptr, ce->raw_len);
    read_unlock(&ce->cfg_rwlock);

    return 0; 
}

static ssize_t cfg_proc_write(struct file *file, const char __user *buffer, size_t count,
        loff_t *pos)
{
    struct cfg_entry *ce;
    char *old_raw_ptr = NULL;
    int old_raw_len = 0;

    if (!count) 
        return 0; 

    ce = cfg_get_ce(PDE_DATA(file_inode(file)));
    if (!ce)
        return -EINVAL;

    if (count > PAGE_SIZE) {
        printk(KERN_ERR 
                "Error: The cfg iports file /etc/%s exceeds the max size %lu bytes!",
                ce->f_name, PAGE_SIZE);
        return -EINVAL;
    }

    write_lock(&ce->cfg_rwlock);

    if (ce->raw_ptr) {
        /*Remove ldcfg for safety*/
        old_raw_ptr = ce->raw_ptr;
        old_raw_len = ce->raw_len;
    }

    ce->raw_ptr = lkmalloc(count);
    if (!ce->raw_ptr) {
        write_unlock(&ce->cfg_rwlock);
        return -ENOMEM;
    }

    ce->raw_len = count;

    /* Write data to the buffer */
    if (copy_from_user(ce->raw_ptr, buffer, count)) {
        lkmfree(ce->raw_ptr);
        ce->raw_ptr = old_raw_ptr; //Restore
        ce->raw_len = old_raw_len;

        write_unlock(&ce->cfg_rwlock);
        return -EFAULT;
    }

    write_unlock(&ce->cfg_rwlock);

    if (old_raw_ptr) {
        lkmfree(old_raw_ptr);
    }

    ce->entity_reload(ce); //Reload proc cfg.

    return count;
}

#endif

/*
 *revalidate the data ptr
 */
static inline struct cfg_entry *cfg_get_ce(void *data)
{
    struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;

    for (p = entry; 
            p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++){
        if (p == data)
            return p;
    }

    return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)

static int cfg_proc_open(struct inode *inode, struct file *file)
{
    void *data = PDE_DATA(inode);
    struct cfg_entry *ce = cfg_get_ce(data);
    if (!ce) {
        return -EINVAL;
    }

    return single_open(file, cfg_proc_read, data);
}

#endif

static inline struct proc_dir_entry *lkm_proc_create(
          const char *fname, umode_t mode, struct proc_dir_entry *parent,
          struct cfg_entry *ce)
{ 
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)

    ce->cfg_proc_file = create_proc_entry(fname, mode, parent);
    if (!ce->cfg_proc_file) 
        return NULL;

    ce->cfg_proc_file->data = (void *)ce;
    ce->cfg_proc_file->read_proc = ce->proc_read;
    ce->cfg_proc_file->write_proc = ce->proc_write;
    ce->cfg_proc_file->uid = 0;
    ce->cfg_proc_file->gid = 0;

#else

    ce->proc_fops = lkmalloc(sizeof(struct file_operations));

    ce->proc_fops->owner = THIS_MODULE;
    ce->proc_fops->open = cfg_proc_open;
    ce->proc_fops->read = seq_read;
    ce->proc_fops->write = ce->proc_write;
    ce->proc_fops->llseek = seq_lseek;
    ce->proc_fops->release = single_release;
    
    ce->cfg_proc_file = proc_create_data(fname, mode, parent, ce->proc_fops, ce);

#endif

return ce->cfg_proc_file;
}

static int cfg_proc_file_init(struct cfg_entry *ce)
{
    ce->cfg_proc_file = lkm_proc_create(ce->f_name, S_IFREG|S_IRUGO, 
            cfg_base_dir, ce);

    if (!ce->cfg_proc_file) {
        printk(KERN_ERR
                "Error: Could not initialize /etc/%s",
                ce->f_name);
        return 0;
    }

    ce->raw_len = 0;
    ce->raw_ptr = NULL;
    ce->cfg_ptr = NULL;
    ce->mtime = 0;

    rwlock_init(&ce->cfg_rwlock);

    return 1;
}

static void cfg_proc_file_destroy(struct cfg_entry *ce)
{
    if (ce->cfg_proc_file)
        lkm_proc_remove(ce->f_name, cfg_base_dir);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (ce->proc_fops) 
        lkmfree(ce->proc_fops);
#endif
}

static int cfg_entry_init(struct cfg_entry *ce)
{
    if (!ce->proc_file_init(ce))
        return 0;

    if (!ce->entity_init(ce)) {
        ce->proc_file_destroy(ce);
        return 0;
    }

    return 1;
}

static void cfg_entry_destroy(struct cfg_entry *ce)
{
    ce->entity_destroy(ce);
    ce->proc_file_destroy(ce);
}

static inline void item_str_node_dtor_func(void *data) 
{
    struct item_node_t *item;

    if (!data) 
        return;
    item = (struct item_node_t *)data;
    if (item->cfg_item_set_node == cfg_item_set_str_node) {
        if (item->v_str)
            lkmfree(item->v_str);
    }
}

static inline void item_dtor_func(void *data) 
{
    if (data) {
        item_str_node_dtor_func(data); 
        lkmfree(data);   
    }
}

static int item_line_scan(struct cfg_entry *ce, int *pos, int *line,
        struct item_pos_t *item_pos) 
{
    char c;
    int delimeter_found = 0;
    int comment_line_start = 0;

    (*line)++;

    while (*pos < ce->raw_len /*the last line*/
            && (c = ce->raw_ptr[(*pos)++]) != '\n') {

        if (comment_line_start) /*strip comments*/
            continue;

        if (c == '#') { /*set comment start flag*/
            comment_line_start = 1;
            continue;
        }
        
        if (c == ' ' || c == '\t') {

            if (item_pos->name_start < 0) 
                continue;   

            if (!delimeter_found) {
                delimeter_found = 1;
                continue;
            }

            if (delimeter_found && item_pos->value_start < 0) 
                continue;
        }

        if ((c >= '0' && c <= '9') 
                || (c >= 'a' && c <= 'z') 
                || (c >= 'A' && c <= 'Z') 
                || c == '_' || c == ',' || c == '"' || c == '.' || c == '\\'
                || c == ' ' || c == '\t') {

            if (item_pos->name_start < 0) 
                item_pos->name_start = *pos - 1;

            if (!delimeter_found)
                item_pos->name_end = *pos - 1;

            if (delimeter_found && (item_pos->value_start < 0))
                item_pos->value_start = *pos - 1;

            if (delimeter_found)
                item_pos->value_end = *pos - 1;

        } else 
            goto out_err;
    }

    //strip the most right space chars.

    if (item_pos->value_start < 0) 
        goto out_ret;

    for (c = ce->raw_ptr[item_pos->value_end];
            c == ' ' || c == '\t'; 
            c = ce->raw_ptr[--item_pos->value_end]);

out_ret:
    return item_pos->name_start >= 0 ? 1/*Non-null line*/ : 0;

out_err:
    printk(KERN_ERR 
            "Error: Scan cfg items error on line %d in file /etc/%s", 
            *line, ce->f_name);
    return -1; //Scan error!
}

/**
 *Simple items scanner.
 *
 *Returns:
 * -1: error, 0: no cfg entries, >0: success.
 */
static int cfg_items_data_scan(struct items_str_list_t *items_str_list, 
        struct cfg_entry *ce)
{
    int pos = 0;
    int line = 0;
    int res;
    struct item_str_t *item_str;
    struct item_pos_t item_pos;

    while (pos < ce->raw_len) {

        INIT_ITEM_POS(&item_pos); 

        res = item_line_scan(ce, &pos, &line, &item_pos);
        if (res < 0) //Scan error.
            return -1;
        if (!res) //Line scan done but needn't.
            continue;

        NEW_ITEM_STR_NODE(item_str, &item_pos);
        INIT_ITEM_STR_NODE(item_str, ce, &item_pos, line);
        INSERT_INTO_ITEMS_LIST(items_str_list, item_str);
    }

    return items_str_list->count;
}

/**
 *Simple item line parser.
 *
 *Returns:
 *0: node parse error, 1: node parse success.
 *
 */
static int item_line_parse(struct item_str_t *item_str, struct cfg_entry *ce)
{
    int i, escape_character_count, quotations_not_matches;
    char c;

    //parse item name str.
    for (i = 0; i < item_str->name.len; i++) {
        c = item_str->name.data[i];
        if (!((c >= '0' && c <= '9')
                || (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || c == '_' || c == '.'))
            goto out_err;
    }

    if (!item_str->value.data) // null value
        return 1;

    //parse item value str.
    escape_character_count = 0;
    quotations_not_matches = 0;
    for (i = 0; i < item_str->value.len; i++) {
        c = item_str->value.data[i]; 
        if (c == '\\') 
            ++escape_character_count;
        else {
            /*quotations*/
            if (c == '"' && (escape_character_count % 2 == 0)) {
                if (i != 0 && (i != item_str->value.len - 1)) 
                    goto out_err;

                if (quotations_not_matches) 
                    quotations_not_matches--;
                else
                    quotations_not_matches++;
            }
            escape_character_count = 0;
        }
    }
    if (quotations_not_matches) 
        goto out_err;
    if (escape_character_count % 2 != 0) 
        goto out_err;

    return 1; 

out_err:
    printk(KERN_ERR
            "Error: Parse cfg items error on line %d in file /etc/%s", 
            item_str->line, ce->f_name);
    return 0;
}

/**
 *Simple items parser.
 *
 *Returns:
 * -1: error, 0: no cfg entries, >0: success.
 */
static int cfg_items_data_parse(struct items_str_list_t *items_str_list, 
        struct cfg_entry *ce)
{
    struct item_str_t *p;

    p = items_str_list->list;

    for (; p; p = p->next) {
        int res;
        res = item_line_parse(p, ce);
        if (!res)
            return -1;
    }

    return items_str_list->count;
}

static void items_str_list_free(struct items_str_list_t * items_str_list)
{
    struct item_str_t *p, *q;

    p = items_str_list->list;

    while (p) {
        q = p->next;
        DESTROY_ITEM_STR_NODE(p);
        p = q;
    }
}

static int cfg_item_set_str_node(struct item_node_t *node, kconnp_str_t *str)
{
    char *c, *n, *src, *dest;
    int len = 0;

    if (!str->data)
        return 0;

    src = lkmalloc(str->len + 1);
    if (!src) {
        printk(KERN_ERR "No more memory!");
        return 0;
    }

    dest = lkmalloc(str->len + 1);
    if (!dest) {
        lkmfree(src);
        printk(KERN_ERR "No more memory!");
        return 0;
    }
    
    memcpy(src, str->data, str->len);

    c = src; 
    if (*c == '"') { //Strip the first and last quotations
        *c = '\0';
        src[str->len - 1] = '\0';
        c++;
    }
    
    for (; c && *c; c++) {
        if (*c != '\\') {
            dest[len++] = *c;
        } else { //Check next char
            n = c + 1;
            switch (*n) {
                case '\\':
                    dest[len++] = '\\';
                    break;
                case 'r':
                    dest[len++] = '\r';
                    break;
                case 'n':
                    dest[len++] = '\n';
                    break;
                case 't':
                    dest[len++] = '\t';
                    break;
                default:
                    dest[len++] = *n;
                    break;
            }
            c++;
        }
    }

    node->v_str = dest;
    node->v_strlen = len;

    lkmfree(src);

    return 1;
}

static int cfg_item_set_int_node(struct item_node_t *node, kconnp_str_t *str)
{
    if (str->len > 0) {
        node->v_lval = simple_strtol(str->data, NULL, 10); 
        if (node->v_lval < 0) 
            return 0;
    } else 
        return 0;

    return 1;
}
/*
static int cfg_item_set_bool_node(struct item_node_t *node, kconnp_str_t *str)
{
    if (str->data)
        return 0;

    node->v_lval = 1;
    return 1;
}
*/

static int cfg_global_entity_init(struct cfg_entry *ce)
{
    struct items_str_list_t items_str_list = {NULL, 0};
    struct item_node_t *p;
    struct item_str_t *q;
    int res, ret = 1;

    if ((res = cfg_items_data_scan(&items_str_list, ce)) <= 0) {
        if (res < 0)  //error
            ret = 0;
        goto out_free;
    }

    if ((res = cfg_items_data_parse(&items_str_list, ce)) <= 0) {
        if (res < 0) //error
            ret = 0;
        goto out_free;
    }

    if (!_hash_init((struct hash_table_t **)&ce->cfg_ptr, 0, 
            hash_func_times33, item_str_node_dtor_func)) {
        ret = 0;
        goto out_free;
    }
    
    for (p = cfg_global_items; p->name.data; p++) {

        if (!hash_add((struct hash_table_t *)ce->cfg_ptr, 
                p->name.data, p->name.len, 
                p, 0)) {
            goto out_hash;
        }
    }
    
    q = items_str_list.list;
    for (; q; q = q->next) {
        struct item_node_t *item_node;
        if (hash_find((struct hash_table_t *)ce->cfg_ptr, 
                    (const char *)q->name.data, q->name.len, 
                    (void **)&item_node)) {
            if (!item_node->cfg_item_set_node(item_node, &q->value)) {
                printk(KERN_ERR 
                        "Error: Invalid cfg item value on line %d in file /etc/%s", 
                        q->line, ce->f_name);
                ret = 0;
                goto out_hash;
            }
        } else {
            printk(KERN_ERR 
                    "Error: Unrecognized cfg item on line %d in file /etc/%s", 
                    q->line, ce->f_name);
            ret = 0;
            goto out_hash;
        }
    }
out_free:
    items_str_list_free(&items_str_list);
    return ret;

out_hash:
    ret = 0;
    hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
    goto out_free;
}

static int cfg_prims_entity_init(struct cfg_entry *ce)
{
    struct items_str_list_t items_str_list = {NULL, 0};
    struct item_str_t *q;
    struct hash_bucket_t *pos;
    struct conn_node_t *conn_node;
    struct item_node_t *prim_node;
    int res, ret = 1;


    if (!wl->cfg_ptr) //check white list
        return 1;

    if ((res = cfg_items_data_scan(&items_str_list, ce)) <= 0) {
        if (res < 0)  //error
            ret = 0;
        goto out_free;
    }

    if ((res = cfg_items_data_parse(&items_str_list, ce)) <= 0) {
        if (res < 0) //error
            ret = 0;
        goto out_free;
    }

    if (!_hash_init((struct hash_table_t **)&ce->cfg_ptr, 0, 
            hash_func_times33, item_dtor_func)) {
        ret = 0;
        goto out_free;
    }

    q = items_str_list.list;
    for (; q; q = q->next) {
        int found = 0;

        hash_for_each(wl->cfg_ptr, pos) {

            conn_node = (struct conn_node_t *)hash_value(pos);

            if ((q->name.len == conn_node->conn_sn.len) 
                    && !memcmp(q->name.data, conn_node->conn_sn.data, q->name.len)) {

                prim_node = lkmalloc(sizeof(struct item_node_t)); 
                if (!prim_node) {
                    printk(KERN_ERR "No more memory!");
                    ret = 0;
                    goto out_hash;
                }

                prim_node->cfg_item_set_node = cfg_item_set_str_node;

                if (q->value.len > MAX_PRIMITIVE_LEN || 
                        !prim_node->cfg_item_set_node(prim_node, &q->value)) {
                    printk(KERN_ERR 
                            "Error: Invalid primitives on line %d in file /etc/%s", 
                            q->line, ce->f_name);
                    lkmfree(prim_node);
                    ret = 0;
                    goto out_hash;
                }

                if (!hash_set((struct hash_table_t *)ce->cfg_ptr, 
                            (const char *)q->name.data, q->name.len,
                            (void *)prim_node, 0)) {
                    ret = 0;
                    goto out_hash;
                }

                found = 1;
            } 
        }

        if (!found) {
            printk(KERN_ERR 
                    "Error: Unrecognized service name on line %d in file /etc/%s", 
                    q->line, ce->f_name);
            ret = 0;
            goto out_hash;
        }
    }
    
    //init the prim_node ptr of iport white list to improve performance.
    hash_for_each(wl->cfg_ptr, pos) {
        
        conn_node = (struct conn_node_t *)hash_value(pos);

        if(hash_find((struct hash_table_t *)ce->cfg_ptr, 
                    (const char *)conn_node->conn_sn.data, conn_node->conn_sn.len, 
                    (void **)&prim_node)) {

            conn_node->prim_node = prim_node;
        }
    }

out_free:
    items_str_list_free(&items_str_list);
    return ret;

out_hash:
    ret = 0;
    hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
    goto out_free;
}

void cfg_items_entity_destroy(struct cfg_entry *ce)
{
    if (ce->raw_ptr) {
        lkmfree(ce->raw_ptr);
        ce->raw_ptr = NULL;
    }

    if (ce->cfg_ptr) 
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
}

int cfg_items_entity_reload(struct cfg_entry *ce)
{
    int ret;

    write_lock(&ce->cfg_rwlock);

    if (ce->cfg_ptr)    
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);

    ret = ce->entity_init(ce);

    write_unlock(&ce->cfg_rwlock);

    return ret;
}

static int cfg_stats_info_entity_init(struct cfg_entry *ce)
{
    ce->raw_ptr = lkmalloc(PAGE_SIZE);
    if (!ce->raw_ptr)
        return 0;

    ce->raw_len = 0;

    return 1;
}

static void cfg_stats_info_entity_destroy(struct cfg_entry *ce)
{
    if (ce->raw_ptr)
        lkmfree(ce->raw_ptr);

    ce->raw_len = 0;
}



/**
 *Converts an (Ipv4) ip from int to an standard dotted-decimal format string.
 */
static char *ip_ntoa(unsigned int ip)
{
    static char ip_str[16]; 
    char *p = (char *)&ip;

    
    sprintf(ip_str, "%u.%u.%u.%u", (unsigned char)(*p), (unsigned char)(*(p+1)), 
            (unsigned char)(*(p+2)), (unsigned char)(*(p+3)));

    return ip_str;
}

/**
 *Convert IPV4 ip str to int.
 */
static int ip_aton(const char *ip_str, struct in_addr *iaddr)
{
    const char *c;
    char ip_str_num[4] = {0, }; //Max 3 chars.
    int i = 0, j = 0, dot_count = 0, ip_strlen;
    char *p = (char *)&iaddr->s_addr;

    ip_strlen = strlen(ip_str);

    for (c = ip_str, j = 1; *c; c++, j++) {
        long ip_n;

        if ((*c < '0' || *c > '9') && *c != '.') //0-9 or .
            return 0;

        if (*c >= '0' && *c <= '9')
            ip_str_num[i++] = *c;

        if (*c == '.' || j == ip_strlen) { //Extract ip part. 
            //Tail check.
            if (j == ip_strlen) { //Format: num.num.num.num
                if (dot_count != 3) 
                    return 0; //Error.
            } else {
                if (dot_count > 3) 
                    return 0;
            }

            if (i < 1 || i > 3) {//The length of ip part between dots.
                return 0;
            }

            ip_n = simple_strtol(ip_str_num, NULL, 10);
            if (ip_n > 255) 
                return 0;

            *p++ = (char)ip_n;
            
            //re-initial.
            memset(ip_str_num, 0, sizeof(ip_str_num));             
            i = 0;
           
            if (*c == '.') {
                dot_count++;
                continue;
            }
        }
    }
    
    return 1;
}

/*
 *Simple iport line scanner.
 *
 *Params:
 * 1.the cfg entry pointer.
 * 2.the current pos to scan.
 * 3.the current line to scan.
 * 4.store the iport pos.
 *
 *Allowed iport characters: 0-9 . * : [] - () A-Z a-z _ |
 *
 *Returns:
 * -1: line scan error, 0: line scan done, 1: line scan success.
 */
static int iport_line_scan(struct cfg_entry *ce, 
        int *pos, int *line, 
        struct iport_pos_t *iport_pos)
{
    char c;
    int comment_line_start = 0;
    int valid_chars_count = 0;
    int success = 0;
    int after_colon = 0;
    int flags_begin = 0;

    (*line)++;

    while (*pos < ce->raw_len /*the last line*/
            && (c = ce->raw_ptr[(*pos)++]) != '\n') {

        if (c == ' ' || c == '\t') {//strip blank char.
            continue;
        }

        if (comment_line_start) /*strip comments*/
            continue;

        if (c == '#') { /*set comment start flag*/
            comment_line_start = 1;
            continue;
        }

        if ((c >= '0' && c <= '9')  //valid char
                || c == '.' || c == '*' || c == ':'
                || c == '[' || c == ']' || c == '-'
                || (c >= 'a' && c <= 'z')
                || (c >= 'A' && c <= 'Z')
                || c == '_'
                || c == '(' || c == ')' || c == '|') {

            valid_chars_count++;

            if (c == ':') { //delimeter of ip and port.
                after_colon += 1;
                continue;
            }

            if (c == '(') { //flags start tag.
                flags_begin = 1;
                continue;
            }

            /*Get iport pos*/
            if (!after_colon && iport_pos->sn_start < 0) 
                iport_pos->sn_start = *pos - 1;
            if (after_colon == 1 && iport_pos->sn_end < 0)
                iport_pos->sn_end = *pos - 3;

            if (after_colon == 1 && iport_pos->ip_start < 0)
                iport_pos->ip_start = *pos - 1;
            if (after_colon == 2 && iport_pos->ip_end < 0)
                iport_pos->ip_end = *pos - 3;

            if (after_colon == 2 && iport_pos->port_start < 0)
                iport_pos->port_start = *pos - 1;
            if (after_colon == 2 && !flags_begin)  //port part
                iport_pos->port_end = *pos - 1;

            if (flags_begin && iport_pos->flags_start < 0)
                iport_pos->flags_start = *pos - 1;
            if (flags_begin && c == ')') //flags end tag.
                iport_pos->flags_end = *pos - 2; 
            else  //make sure the last valid char is ')'
                iport_pos->flags_end = -1;
        } else
            goto out_err;
    }

    if (!valid_chars_count)
        return 0;
    
    success = iport_pos->sn_end >= 0 && iport_pos->sn_start >= 0
        && iport_pos->ip_end >= 0 && iport_pos->ip_start >= 0 
        && iport_pos->port_end >= 0 && iport_pos->port_start >= 0
        && (flags_begin ? 
                (iport_pos->flags_end >= 0 && iport_pos->flags_start >= 0) : 1);

    if (!success)
        goto out_err;
    return success;

out_err: 
    printk(KERN_ERR 
            "Error: Scan iports cfg error on line %d in file /etc/%s", 
            *line, ce->f_name);
    return -1; //Scan error!
}

/**
 *Simple iports scanner.
 *
 *Returns:
 * -1: error, 0: no cfg entries, >0: success.
 */
static int cfg_iports_data_scan(struct iports_str_list_t *iports_str_scanning_list, 
        struct cfg_entry *ce)
{
    int pos = 0;
    int line = 0;
    int res;
    struct iport_pos_t iport_pos;
    struct iport_str_t *iport_str;

    while (pos < ce->raw_len) {
        INIT_IPORT_POS(&iport_pos);

        res = iport_line_scan(ce, &pos, &line, &iport_pos);
        if (res < 0) //Scan error.
            return -1;
        if (!res) //Line scan done but needn't.
            continue;

        NEW_IPORT_STR_SCAN_NODE(iport_str, &iport_pos);
        INIT_IPORT_STR_SCAN_NODE(iport_str, ce, &iport_pos, line);
        INSERT_INTO_IPORTS_LIST(iports_str_scanning_list, iport_str);
    }

    return iports_str_scanning_list->count;
}

/**
 *Simple iport line parser.
 *
 *Returns:
 *0: node parse error, 1: node parse success.
 *
 */
static int iport_line_parse(struct iport_str_t *iport_str, 
        char *flags_str, char *port_str, char *ip_str_or_prefix,
        int *ip_range_start, int *ip_range_end,
        char *sn_str)
{
    char *c;
    int sn_strlen, ip_strlen, port_strlen, flags_strlen;
    char ip_range_str[2][4] = {{0, }, {0, }};
    char ip_fourth_str[4] = {0, };
    int i = 0, j = 0, k = 0, n = 0, dot_count = 0, flags_sum = 0;
    int range_start = 0, range_end = 0, range_dash = 0;
   
    sn_strlen = strlen(iport_str->sn_str);
    ip_strlen = strlen(iport_str->ip_str);
    port_strlen = strlen(iport_str->port_str);
    flags_strlen = iport_str->flags_str ? strlen(iport_str->flags_str) : 0;

    /*Parse flags str*/
    if (!flags_strlen)
        goto parse_going;
   
    c = iport_str->flags_str; 
    for (; c && *c; c++) {
        
        if (*c == ' ' || *c == '\t') //strip blank char
            continue;
    
        if (*c != '|' && (*c < 'A' || *c > 'Z')) //valid flags: A|B|C|D...
            return 0;
        
        if (*c == '|')
            flags_sum -= 1;
        else 
            flags_sum += 1;
    
        if (flags_sum < 0)
            return 0;
    }

    if (flags_sum <= 0)
        return 0;
    
    strcpy(flags_str, iport_str->flags_str);

parse_going:
    /*Parse port str*/
    c = iport_str->port_str;
    for (; c && *c; c++) { //Parse port.
        if (*c < '0' || *c > '9')
            return 0; //error
    }
    strcpy(port_str, iport_str->port_str);

    /*Parse ip str*/ 
    c = iport_str->ip_str;
    for (; c && *c; c++) {
        if (*c == '*' && ip_strlen != 1)
            return 0;
 
        if (dot_count < 3)
            ip_str_or_prefix[n++] = *c;
        
        if (*c == '.') {
            dot_count++;

            if (dot_count == 3) //strip the third dot for the next step.
                continue; 

            if (dot_count > 3)
                return 0;
        }
        
        /*Parse the last ip part, Eg: [0-9]*/
        if (dot_count == 3) {
            if (range_end)   // Assure ']' is the last char.
                return 0;

            if (*c == '[') {
                range_start = 1;
                continue;
            }

            if (!range_start) {
                if (k > 3)
                    return 0;
                ip_fourth_str[k++] = *c;
            }

            if (*c == '-') {
                if (i <= 0)
                    return 0;
                range_dash = 1;
                continue;
            }

            if (range_start && !range_dash) {
                if (i >= 3 /*max 3 nums*/ || *c < '0' || *c > '9') 
                    return 0;
                ip_range_str[0][i++] = *c;
            }

            if (*c == ']') {
                if (j <= 0) 
                    return 0;
                range_end = 1;
                continue;
            }

            if (range_dash && !range_end) {
                if (j >= 3 || *c < '0' || *c > '9')
                    return 0;
                ip_range_str[1][j++] = *c;
            }

            continue;
        }
    }

    if (strcmp(ip_str_or_prefix, "*") && dot_count != 3) //End parse ip str.
        return 0;
    
    if (!range_start) //no [ - ]
        strcat(ip_str_or_prefix, ip_fourth_str);
    else if(strlen(ip_range_str[0]) && strlen(ip_range_str[1])) {
        char ip_fourth_str_tmp[2][4] = {{0, }, {0, }};

        strcpy(ip_fourth_str_tmp[0], ip_fourth_str);
        strcat(ip_fourth_str_tmp[0], ip_range_str[0]);

        strcpy(ip_fourth_str_tmp[1], ip_fourth_str);
        strcat(ip_fourth_str_tmp[1], ip_range_str[1]);

        *ip_range_start = simple_strtol(ip_fourth_str_tmp[0], NULL, 10);
        *ip_range_end = simple_strtol(ip_fourth_str_tmp[1], NULL, 10);

        if (*ip_range_end <= *ip_range_start) //error
            return 0;
    } else
        return 0; 

    /*parse service name*/
    if (sn_strlen > (MAX_SN_PADDING_ZERO_LEN - 1)) {
        printk(KERN_ERR 
                "The service name length exceeds the max length %d", 
                MAX_SN_PADDING_ZERO_LEN - 1);
        return 0;
    }

    c = iport_str->sn_str;
    if (c && (*c == '_' 
            || (*c >= 'a' && *c <= 'z')
            || (*c >= 'A' && *c <= 'Z'))) {
        c++;
    } else 
        return 0;
    for (; *c; c++) {
        if (*c == '_' || (*c >= 'a' && *c <= 'z')
          || (*c >= 'A' && *c <= 'Z') 
          || (*c >= '0' && *c <= '9')) {
            continue;
        } else {
            return 0;
        }
    }

    strcpy(sn_str, iport_str->sn_str);

    return 1;
}

/**
 *Simple iports parser.
 *
 *Returns:
 * -1: error, 0: no cfg entries, >0: success.
 */
static int cfg_iports_data_parse(struct iports_str_list_t *iports_str_parsing_list,
        struct iports_str_list_t *iports_str_scanning_list, struct cfg_entry *ce) 
{
    struct iport_str_t *p, *iport_str;
    char *sn_str, *ip_str_or_prefix, *port_str;
    char *flags_str;
    int ip_range_start, ip_range_end; //For parsing []
    int res;

    p = iports_str_scanning_list->list;
    for (; p; p = p->next) {
        int sn_strlen, ip_strlen, port_strlen, flags_strlen;

        sn_strlen = strlen(p->sn_str);
        ip_strlen = strlen(p->ip_str);
        port_strlen = strlen(p->port_str);
        flags_strlen = p->flags_str ? strlen(p->flags_str) : 0;
        
        sn_str = lkmalloc(sn_strlen + 1);
        if (!sn_str) {
            return -1;
        }

        ip_str_or_prefix = lkmalloc(ip_strlen + 1); 
        if (!ip_str_or_prefix)
            return -1;

        port_str = lkmalloc(port_strlen + 1); 
        if (!port_str) {
            lkmfree(ip_str_or_prefix);
            return -1;
        }

        if (flags_strlen) {
            flags_str = lkmalloc(flags_strlen + 1);
            if (!flags_str) {
                lkmfree(port_str);
                lkmfree(ip_str_or_prefix);
                return -1;
            }
        } else
            flags_str = NULL;

        ip_range_start = ip_range_end = 0;
        res = iport_line_parse(p, 
                flags_str, port_str, ip_str_or_prefix, 
                &ip_range_start, &ip_range_end,
                sn_str);
        if (!res)  //Parse node error.
            goto out_free;

        if (ip_range_end == 0) {
            
            NEW_IPORT_STR_NODE(iport_str, 
                    strlen(sn_str) + 1,
                    strlen(ip_str_or_prefix) + 1, 
                    strlen(port_str) + 1,
                    flags_strlen ? flags_strlen + 1 : 0);

            INIT_IPORT_STR_NODE(iport_str, 
                    sn_str, strlen(sn_str),
                    ip_str_or_prefix, strlen(ip_str_or_prefix), 
                    port_str, strlen(port_str),
                    flags_str, flags_strlen,
                    p->line);

            INSERT_INTO_IPORTS_LIST(iports_str_parsing_list, iport_str); 

        } else if (ip_range_end > 0) { //For parsing []
            char ip_range_str[4] = {0, };
            int ip_num;
            char *ip_str_tmp;

            for (ip_num = ip_range_start; ip_num <= ip_range_end; ip_num++) {

                sprintf(ip_range_str, "%d", ip_num);

                ip_str_tmp = lkmalloc(ip_strlen + 1);
                strcpy(ip_str_tmp, ip_str_or_prefix);
                strcat(ip_str_tmp, ip_range_str);

                NEW_IPORT_STR_NODE(iport_str, 
                        strlen(sn_str) + 1,
                        strlen(ip_str_tmp) + 1, 
                        strlen(port_str) + 1,
                        flags_strlen ? flags_strlen + 1 : 0);

                INIT_IPORT_STR_NODE(iport_str, 
                        sn_str, strlen(sn_str),
                        ip_str_tmp, strlen(ip_str_tmp), 
                        port_str, strlen(port_str), 
                        flags_str, flags_strlen,
                        p->line);

                INSERT_INTO_IPORTS_LIST(iports_str_parsing_list, iport_str); 

                lkmfree(ip_str_tmp);
            }
        }

out_free:
        lkmfree(sn_str);
        lkmfree(ip_str_or_prefix);
        lkmfree(port_str);
        if (flags_str)
            lkmfree(flags_str);

        if (!res){
            printk(KERN_ERR
                    "Error: Parse iports cfg error on line %d in file /etc/%s", 
                    p->line, ce->f_name);
            return -1;
        }else
            continue;
    }

    return iports_str_parsing_list->count;
}

static void iports_str_list_free(struct iports_str_list_t *iports_str_list)
{
    struct iport_str_t *p, *q;

    p  = iports_str_list->list;

    while (p) {
        q = p->next;
        DESTROY_IPORT_STR_NODE(p);
        p = q;
    }

    lkmfree(iports_str_list);
}

static int cfg_iports_entity_init(struct cfg_entry *ce)
{ 
    struct iports_str_list_t *iports_str_scanning_list;
    struct iports_str_list_t *iports_str_parsing_list;
    struct iport_t iport_node;
    struct iport_str_t *p;
    int res, ret = 1;

    iports_str_scanning_list = lkmalloc(sizeof(struct iports_str_list_t));
    if (!iports_str_scanning_list)
        return 0;

    iports_str_parsing_list = lkmalloc(sizeof(struct iports_str_list_t)); 
    if (!iports_str_parsing_list) {
        lkmfree(iports_str_scanning_list);
        return 0;
    }

    if ((res = cfg_iports_data_scan(iports_str_scanning_list, ce)) <= 0) {
        if (res < 0) //error.
            ret = 0;
        goto out_free;
    }

    if ((res = cfg_iports_data_parse(iports_str_parsing_list, 
                    iports_str_scanning_list, ce)) <= 0) {
        if (res < 0) //error
            ret = 0;
        goto out_free;
    }

    if (!hash_init((struct hash_table_t **)&ce->cfg_ptr, NULL)) {
        ret = 0;
        goto out_free;
    }
    
    p = iports_str_parsing_list->list;
    for (; p; p = p->next) {
        struct in_addr iaddr;
        char *flag;
        
        memset(&iport_node, 0, sizeof(struct iport_t)); 

        //service name init
        strcpy(iport_node.sn.data, p->sn_str);
        iport_node.sn.len = strlen(p->sn_str); 

        //ip init
        if (!strcmp(p->ip_str, "*")) //Wildcard
            iport_node.ip = 0;
        else {
            if (!ip_aton(p->ip_str, &iaddr)) {
                printk(KERN_ERR 
                        "Error: Convert iport str error on line %d in file /etc/%s",
                        p->line, ce->f_name);
                if (ce->cfg_ptr) 
                    hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
                ret = 0;
                goto out_free;
            }
            iport_node.ip = (unsigned int)iaddr.s_addr;
        }

        //port init
        iport_node.port = htons(simple_strtol(p->port_str, NULL, 10));

        //flags init
        for (flag = p->flags_str; flag && *flag; flag++) {

            switch(*flag) {
                case 'S':
                    iport_node.flags |= CONN_STATEFUL;
                    break;
                default:
                    break;
            }

        }

        if (!hash_set((struct hash_table_t *)ce->cfg_ptr, 
                    (const char *)&iport_node, sizeof(struct iport_raw_t), 
                    &iport_node, sizeof(struct iport_t))){
            hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
            ret = 0;
            goto out_free;
        }
    }  

out_free:
    iports_str_list_free(iports_str_scanning_list);
    iports_str_list_free(iports_str_parsing_list);
    return ret; 
}

static void cfg_iports_entity_destroy(struct cfg_entry *ce)
{
    if (ce->raw_ptr) {
        lkmfree(ce->raw_ptr);
        ce->raw_ptr = NULL;
    }

    if (ce->cfg_ptr) 
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
}

static int cfg_iports_entity_reload(struct cfg_entry *ce)
{
    int ret;

    write_lock(&ce->cfg_rwlock);

    if (ce->cfg_ptr)    
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);

    ret = ce->entity_init(ce);

    write_unlock(&ce->cfg_rwlock);

    if (ret) /*reload white list*/
        ret = wl->entity_reload(wl);
 
    return ret;
}

#define iport_in_list(ip, port, ce) iport_in_list_check_or_call(ip, port, ce, NULL)
#define iport_in_allowed_list(ip, port) iport_in_list(ip, port, &cfg->al)
#define iport_in_denied_list(ip, port) iport_in_list(ip, port, &cfg->dl)
#define iport_in_white_list(ip, port) iport_in_list(ip, port, wl)

#define iport_in_list_for_each_call(ip, port, ce, call_func) iport_in_list_check_or_call(ip, port, ce, call_func)

static inline void *iport_in_list_check_or_call(
        unsigned int ip, unsigned short int port, 
        struct cfg_entry *ce, 
        void (*call_func)(void *data))
{
    struct iport_raw_t zip_port, ip_port, **p;
    struct iport_raw_t *iport_list[] = {&ip_port, &zip_port, NULL}; 
    struct hash_table_t *ht_ptr;

    ht_ptr = (struct hash_table_t *)ce->cfg_ptr;

    if (!ht_ptr)
        return NULL;
        
    for (p = &iport_list[0]; *p; p++) 
        memset(*p, 0, sizeof(struct iport_raw_t));

    zip_port.ip = 0;
    zip_port.port = port;

    ip_port.ip = ip;
    ip_port.port = port;

    for (p = &iport_list[0]; (*p); p++) {
        void *tmp;

        if (hash_find(ht_ptr, 
                    (const char *)*p, sizeof(struct iport_raw_t), (void **)&tmp)) {
            if (call_func)
                call_func(tmp);
            else 
                return tmp;
        }
    }

    return NULL;
}

static int cfg_white_list_init(struct cfg_entry *ce)
{
    rwlock_init(&wl->cfg_rwlock);

    return ce->entity_init(ce);
}

static void cfg_white_list_destroy(struct cfg_entry *ce)
{
    ce->entity_destroy(ce);
}

static int cfg_white_list_entity_init(struct cfg_entry *ce)
{
    struct iport_t *iport_node; 
    struct hash_bucket_t *pos;

    if (!cfg->al_ptr)
        return 0;
    
    if (!hash_init((struct hash_table_t **)&wl->cfg_ptr, NULL))
        return 0;

    read_lock(&cfg->al_rwlock);

    hash_for_each(cfg->al_ptr, pos) {

        int in_denied_list;
        struct conn_node_t conn_node; 

        memset(&conn_node, 0, sizeof(struct conn_node_t));
        
        //Special
        conn_node.conn_keep_alive = ULLONG_MAX;

        iport_node = (struct iport_t *)hash_value(pos);
        
        read_lock(&cfg->dl_rwlock);
        in_denied_list = iport_in_denied_list(iport_node->ip, iport_node->port) 
            ? 1 : 0;
        read_unlock(&cfg->dl_rwlock);

        if (in_denied_list)
            continue;
        
        memcpy(&conn_node.conn_sn, &iport_node->sn, sizeof(*(&iport_node->sn)));
        conn_node.conn_ip = iport_node->ip;
        conn_node.conn_port = iport_node->port;
        conn_node.conn_flags = iport_node->flags;
        
        //We regard stateful connection as passive socket to use it only once.
        if (conn_node.conn_flags & CONN_STATEFUL) {
            conn_node.conn_close_way = CLOSE_PASSIVE; 
            conn_node.conn_close_way_last_set_jiffies = ULLONG_MAX;
        }

        if (!hash_set((struct hash_table_t *)wl->cfg_ptr, 
                    (const char *)iport_node, sizeof(struct iport_raw_t), 
                    &conn_node, sizeof(struct conn_node_t))) {
            hash_destroy((struct hash_table_t **)&wl->cfg_ptr);
            read_unlock(&cfg->al_rwlock);
            return 0;
        }

    }

    read_unlock(&cfg->al_rwlock);

    return 1;
}

static void cfg_white_list_entity_destroy(struct cfg_entry *ce)
{
    if (ce->cfg_ptr)
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
}

static int cfg_white_list_entity_reload(struct cfg_entry *ce)
{
    int ret;

    write_lock(&ce->cfg_rwlock);

    ce->entity_destroy(ce);
    ret = ce->entity_init(ce); 

    write_unlock(&ce->cfg_rwlock);

    if (ret) /*reload primitives list*/
        ret = (&cfg->pl)->entity_reload(&cfg->pl);
       

    return ret;
}

int cfg_init()
{
    //Init cfg base dir.
    cfg_base_dir = lkm_proc_mkdir(CFG_BASE_DIR_NAME);
    if (!cfg_base_dir) {
        printk(KERN_ERR "Error: Couldn't create dir /proc/%s", CFG_BASE_DIR_NAME);
        return 0;
    }
    
    //Init cfg entries.
    if (!cfg_entries_walk_func_check(init)) {
        cfg_destroy();
        return 0;
    }

    //Init white list
    wl->init(wl);

    return 1;
}

void cfg_destroy()
{
    //Destroy white list.
    wl->destroy(wl);

    //Destory cfg entries.
    cfg_entries_walk_func_no_check(destroy);

    //Destroy cfg base dir.
    lkm_proc_rmdir(CFG_BASE_DIR_NAME);
}
 
int cfg_conn_op(struct sockaddr *addr, int op_type, void *val)
{
    struct conn_node_t *conn_node;
    unsigned int ip;
    unsigned short int port;
    int ret = 1;

    ip = SOCKADDR_IP(addr);
    port = SOCKADDR_PORT(addr);

    read_lock(&wl->cfg_rwlock);

    conn_node = (struct conn_node_t *)iport_in_white_list(ip, port); 
    if (!conn_node) {
        ret = 0;
        goto unlock_ret;
    }

    switch (op_type) {
        case ACL_CHECK:
            ret = (conn_node ? 1 : 0);
            break;

        case ACL_SPEC_CHECK:
            ret = (conn_node->conn_ip != 0 && conn_node->conn_port != 0);
            break;

        case POSITIVE_CHECK:
            if ((ret = (conn_node->conn_close_way == CLOSE_POSITIVE))) 
                break;

            //Passive permanently check
            if (conn_node->conn_close_way_last_set_jiffies == ULLONG_MAX) {
                ret = 0;
                break;
            }

            //Passive timeout check, may be not a passive socket which was closed passively by accident. 
            if (lkm_jiffies_elapsed_from(conn_node->conn_close_way_last_set_jiffies)
                    > CONN_PASSIVE_TIMEOUT_JIFFIES_THRESHOLD) {
               conn_node->conn_close_way = CLOSE_POSITIVE;
               conn_node->conn_keep_alive = ULLONG_MAX; //reset pemanently.
               conn_node->conn_close_way_last_set_jiffies = lkm_jiffies;
               ret = 1;
            }
            break;

        case PASSIVE_SET:
            conn_node->conn_close_way = CLOSE_PASSIVE;
            if (conn_node->conn_close_way_last_set_jiffies != ULLONG_MAX)
                conn_node->conn_close_way_last_set_jiffies = lkm_jiffies;
            break;

        case KEEP_ALIVE_SET:
            conn_node->conn_keep_alive = *((typeof(conn_node->conn_keep_alive)*)val);
            break;

        case KEEP_ALIVE_GET:
            *((typeof(conn_node->conn_keep_alive)*)val) = conn_node->conn_keep_alive;
            break;

        case CHECK_PRIMITIVE:
            {
                kconnp_str_t __user *b = (kconnp_str_t *)val;

                if (!conn_node->prim_node 
                        || (b->len != conn_node->prim_node->v_strlen)) {
                    ret = 0;
                    break;
                } else {
                    char buf[MAX_PRIMITIVE_LEN];

                    if (b->len > MAX_PRIMITIVE_LEN) {
                        ret = 0;
                        break;
                    }

                    /*mem copy from user to kernel*/
                    if (copy_from_user(buf, b->data, b->len)) {
                        ret = 0;
                        break;
                    }

                    if (!memcmp(buf, conn_node->prim_node->v_str, b->len)) {
                        ret = 1;
                        break;
                    }
                }
            }
            break;

        default:
            ret = 0;
            break;
    }

unlock_ret:
    read_unlock(&wl->cfg_rwlock);
    return ret;
}

void cfg_allowed_entries_for_each_call(void (*call_func)(void *data))
{
    struct conn_node_t *conn_node; 
    struct hash_bucket_t *pos;

    read_lock(&wl->cfg_rwlock);

    if (!wl->cfg_ptr)
        goto unlock_ret;

    hash_for_each(wl->cfg_ptr, pos) {

        conn_node = (struct conn_node_t *)hash_value(pos);
        call_func((void *)conn_node);

    }

unlock_ret:
    read_unlock(&wl->cfg_rwlock);
    return;
}

void cfg_allowed_iport_node_for_each_call(unsigned int ip, unsigned short int port, 
        void (*call_func)(void *data)) 
{
    read_lock(&wl->cfg_rwlock);
    iport_in_list_for_each_call(ip, port, wl, call_func);
    read_unlock(&wl->cfg_rwlock);
}

void conn_stats_info_dump(void)
{
    const char *conn_stat_str_fmt = 
#if BITS_PER_LONG < 64
        "Service: %s:%s:%u, Mode: %s, Hits: %d(%u.0%), Misses: %d(%u.0%)\n";
#else
        "Service: %s:%s:%u, Mode: %s, Hits: %ld(%u.0%), Misses: %ld(%u.0%)\n";
#endif
    struct hash_bucket_t *pos;
    int offset = 0;

    if (NOW_SECS - wl->mtime < DUMP_INTERVAL)
        return;

    write_lock(&cfg->st_rwlock);

    if (cfg->st_ptr) {
        memset(cfg->st_ptr, 0, cfg->st_len);
        cfg->st_len = 0;
    }

    read_lock(&wl->cfg_rwlock); 

    if (!wl->cfg_ptr)
        goto unlock_ret;
    
    hash_for_each((struct hash_table_t *)wl->cfg_ptr, pos) {
        struct conn_node_t *conn_node;
        unsigned int ip;
        unsigned short int port;
#if BITS_PER_LONG < 64
        int all_count, misses_count, hits_count;
#else
        long all_count, misses_count, hits_count;
#endif
        unsigned int misses_percent, hits_percent; 
        char *sn_str;
        char *ip_ptr, ip_str[16] = {0, };
        char mode[16] = {0, };
        char buffer[128] = {0, };
        int l;
        
        conn_node = (struct conn_node_t *)hash_value(pos);

        sn_str = conn_node->conn_sn.data;

        ip = conn_node->conn_ip;
        if (ip == 0) {
            strcpy(ip_str, "*");
            ip_ptr = ip_str;
        } else
            ip_ptr = ip_ntoa(ip);
           
        port = ntohs(conn_node->conn_port);

        if (conn_node->conn_close_way == CLOSE_PASSIVE) 
            strcpy(mode, "PASSIVE");
        else
            strcpy(mode, "POSITIVE");
 
        hits_count = lkm_atomic_read(&conn_node->conn_connected_hit_count);
        misses_count = lkm_atomic_read(&conn_node->conn_connected_miss_count);
        all_count = hits_count + misses_count;

        if (all_count == 0) {
            misses_percent = 0;
            hits_percent = 0;
        } else {
            misses_percent = (misses_count * 100) / all_count;
            hits_percent = 100 - misses_percent;
        }

        l = sprintf(buffer, conn_stat_str_fmt, 
                sn_str, ip_ptr, port, mode, 
                hits_count, hits_percent,
                misses_count, misses_percent);

        if (l > (PAGE_SIZE - cfg->st_len)) {
            goto unlock_ret;
        }
        
        memcpy(cfg->st_ptr + offset, buffer, l); 

        offset += l; 

        cfg->st_len += l;

    }

    wl->mtime = NOW_SECS;

unlock_ret:

    read_unlock(&wl->cfg_rwlock); 

    write_unlock(&cfg->st_rwlock);

    return;
}

#include <linux/string.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include "connp.h"
#include "util.h"
#include "hash.h"
#include "cfg.h"

#define CFG_GLOBAL_FILE             "kconnp.conf"
#define CFG_ALLOWED_IPORTS_FILE     "iports.allow"
#define CFG_DENIED_IPORTS_FILE      "iports.deny"
#define CFG_CONN_STATS_INFO_FILE    "stats.info"

#define DUMP_INTERVAL 5 //Unit: second

#define cfg_entries_walk_func_check(func_name)    \
    ({    \
        int __check_ret = 1;    \
        struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;  \
        for (p = entry; \
                p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++) {\
            if (!p->func_name(p))   \
                __check_ret = 0;          \
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
            continue;                                                               \
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
        memcpy((item_str)->value.data,                              \
                ce->raw_ptr + (item_pos)->value_start,              \
                (item_str)->value.len);                             \
        (item_str)->line = line_pass;                               \
    } while (0)

#define INSERT_INTO_ITEMS_LIST(items_list, item)    \
    do {                                            \
        if ((items_list)->list)                     \
            (item)->next = (items_list)->list;      \
        (items_list)->list = item;                  \
        (items_list)->count++;                      \
    } while (0)

#define DESTROY_ITEM_STR_NODE(item_str)         \
    do {                                        \
        lkmfree(item_str->name.data);           \
        lkmfree(item_str->value.data);          \
        lkmfree(item_str);                      \
    } while (0)                                 \

#define INIT_IPORT_POS(iport_pos)           \
    do {                                    \
        (iport_pos)->ip_start = -1;         \
        (iport_pos)->ip_end = -1;           \
        (iport_pos)->port_start = -1;       \
        (iport_pos)->port_end = -1;         \
        (iport_pos)->flags_start = -1;      \
        (iport_pos)->flags_end = -1;        \
    } while (0)

#define NEW_IPORT_STR_NODE(iport_str, ip_strlen, port_strlen, flags_strlen) \
    do {                                                        \
        iport_str = lkmalloc(sizeof(struct iport_str_t));       \
        if (!iport_str)                                         \
            return 0;                                           \
        (iport_str)->ip_str = lkmalloc(ip_strlen);              \
        if (!(iport_str)->ip_str) {                             \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        (iport_str)->port_str = lkmalloc(port_strlen);          \
        if (!(iport_str)->port_str) {                           \
            lkmfree((iport_str)->ip_str);                       \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        if (flags_strlen) {                                     \
            (iport_str)->flags_str = lkmalloc(flags_strlen);    \
            if (!(iport_str)->flags_str) {                      \
                lkmfree((iport_str)->port_str);                 \
                lkmfree((iport_str)->ip_str);                   \
                lkmfree(iport_str);                             \
                return 0;                                       \
            }                                                   \
        }                                                       \
    } while (0)  

#define INIT_IPORT_STR_NODE(iport_str,                                  \
        ip_str_pass, ip_strlen,                                         \
        port_str_pass, port_strlen,                                     \
        flags_str_pass, flags_strlen,                                   \
        line_pass)                                                      \
    do {                                                                \
        memcpy((iport_str)->ip_str, ip_str_pass, ip_strlen);            \
        memcpy((iport_str)->port_str, port_str_pass, port_strlen);      \
        if ((iport_str)->flags_str && flags_strlen)                     \
            memcpy((iport_str)->flags_str, flags_str_pass, flags_strlen);   \
        (iport_str)->line = line_pass;                                  \
    } while (0)

#define DESTROY_IPORT_STR_NODE(iport_str)   \
    do {                                    \
        lkmfree((iport_str)->ip_str);       \
        lkmfree((iport_str)->port_str);     \
        lkmfree(iport_str);                 \
    } while (0)

#define INSERT_INTO_IPORTS_LIST(iports_list, iport) \
    INSERT_INTO_ITEMS_LIST(iports_list, iport) 

#define NEW_IPORT_STR_SCAN_NODE(iport_str, iport_pos)                           \
    NEW_IPORT_STR_NODE(iport_str,                                               \
            (iport_pos)->ip_end - (iport_pos)->ip_start + 2, /*padding '\0'*/   \
            (iport_pos)->port_end - (iport_pos)->port_start + 2,                \
            ((iport_pos)->flags_end >= 0 && (iport_pos)->flags_start >= 0)      \
            ? ((iport_pos)->flags_end - (iport_pos)->flags_start + 2) : 0)  

#define INIT_IPORT_STR_SCAN_NODE(iport_str, ce, iport_pos, line)    \
    INIT_IPORT_STR_NODE(iport_str,                                  \
            (ce)->raw_ptr + (iport_pos)->ip_start,                  \
            (iport_pos)->ip_end - (iport_pos)->ip_start + 1,        \
            (ce)->raw_ptr + (iport_pos)->port_start,                \
            (iport_pos)->port_end - (iport_pos)->port_start + 1,    \
            (ce)->raw_ptr + (iport_pos)->flags_start,               \
            (iport_pos)->flags_end - (iport_pos)->flags_start + 1,  \
            line)


/*Regular cfg funcs*/
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
        int *ip_range_start, int *ip_range_end);
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

static int cfg_stats_info_entity_init(struct cfg_entry *);
static void cfg_stats_info_entity_destroy(struct cfg_entry *);

static int cfg_white_list_entity_init(struct cfg_entry *);
static void cfg_white_list_entity_destroy(struct cfg_entry *);
static int cfg_white_list_entity_reload(struct cfg_entry *);

static inline void *iport_in_list_check_or_call(unsigned int ip, unsigned short int port,  struct cfg_entry *, void (*call_func)(void *data));

static struct cfg_dir cfg_dentry = { //initial the cfg directory.
    { //global conf
        .f_name = CFG_GLOBAL_FILE,
        
        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_entry_init,
        .destroy = cfg_entry_destroy,

        .proc_file_init = cfg_proc_file_init,
        .proc_file_destroy = cfg_proc_file_destroy,

        .entity_init = cfg_items_entity_init,
        .entity_destroy = cfg_items_entity_destroy,
        .entity_reload = cfg_items_entity_reload
    },
    { //allowed_list
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
    { //denied_list
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
    { //stats info
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
int cfg_proc_read(char *buffer, char **buffer_location,
        off_t offset, int buffer_length, int *eof, void *data)
{
    int read_count;
    struct cfg_entry *ce;

    ce = cfg_get_ce(data);
    if (!ce) 
        return 0;

    read_lock(&ce->cfg_rwlock);

    if (offset >= ce->raw_len) { //has read all data.
        *eof = 1;
        
        read_unlock(&ce->cfg_rwlock);
        return 0;
    }

    read_count = buffer_length > (ce->raw_len - offset) 
        ? (ce->raw_len - offset) : buffer_length;

    memcpy(buffer, ce->raw_ptr + offset, read_count);

    read_unlock(&ce->cfg_rwlock);
    return read_count; 
}


/*
 * This function is called with the /proc file is written
 */
int cfg_proc_write(struct file *file, const char *buffer, unsigned long count,
        void *data)
{
    struct cfg_entry *ce;
    char *old_raw_ptr = NULL;
    int old_raw_len = 0;

    if (!count) 
        return 0; 

    ce = cfg_get_ce(data);
    if (!ce)
        return 0;
    
    if (count > PAGE_SIZE) {
        printk(KERN_ERR 
                "Error: The cfg iports file /proc/%s/%s exceeds the max size %lu bytes!\n",
                CFG_BASE_DIR_NAME, ce->f_name, PAGE_SIZE);
        return 0;
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

int cfg_proc_file_init(struct cfg_entry *ce)
{
    ce->cfg_proc_file = create_proc_entry(ce->f_name, S_IFREG|S_IRUGO, 
            cfg_base_dir);

    if (!ce->cfg_proc_file) {
        printk(KERN_ERR
                "Error: Could not initialize /proc/%s/%s\n",
                CFG_BASE_DIR_NAME, ce->f_name);
        return 0;
    }

    ce->cfg_proc_file->data = (void *)ce; 
    ce->cfg_proc_file->read_proc = ce->proc_read;
    ce->cfg_proc_file->write_proc = ce->proc_write;
    ce->cfg_proc_file->uid = 0;
    ce->cfg_proc_file->gid = 0;

    rwlock_init(&ce->cfg_rwlock);

    return 1;
}

void cfg_proc_file_destroy(struct cfg_entry *ce)
{
    if (ce->cfg_proc_file)
        remove_proc_entry(ce->f_name, cfg_base_dir);
}

int cfg_entry_init(struct cfg_entry *ce)
{
    if (!ce->proc_file_init(ce))
        return 0;

    if (!ce->entity_init(ce)) {
        ce->proc_file_destroy(ce);
        return 0;
    }

    return 1;
}

void cfg_entry_destroy(struct cfg_entry *ce)
{
    ce->entity_destroy(ce);
    ce->proc_file_destroy(ce);
}

static inline void item_dtor_func(void *data) 
{
    struct item_node_t *item;

    item = (struct item_node_t *)data;
    if (item->v_str)
        lkmfree(item->v_str);
}

static int item_line_scan(struct cfg_entry *ce, int *pos, int *line,
        struct item_pos_t *item_pos) 
{
    char c;
    int delimeter_find = 0;
    int comment_line_start = 0;

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
        
        if (c == ' ' || c == '\t') {

            if (item_pos->name_start < 0) 
                continue;   

            if (!delimeter_find) {
                delimeter_find = 1;
                continue;
            }

            if (delimeter_find && item_pos->value_start < 0) 
                continue;
        }

        if ((c >= '0' && c <= '9') 
                || (c >= 'a' && c <= 'z') 
                || (c >= 'A' && c <= 'Z') 
                || c == '_' || c == ',' || c == '"' || c == '.'
                || c == ' ' || c == '\t') {

            if (item_pos->name_start < 0) 
                item_pos->name_start = *pos;

            if (!delimeter_find)
                item_pos->name_end = *pos;

            if (delimeter_find && (item_pos->value_start < 0))
                item_pos->value_start = *pos;

            if (delimeter_find)
                item_pos->value_end = *pos;

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
            "Error: Scan cfg items error on line %d in file /proc/%s/%s\n", 
            *line, CFG_BASE_DIR_NAME, ce->f_name);
    return -1; //Scan error!
}

/**
 *Simple iport scanner.
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
    struct item_pos_t item_pos = {{-1, -1}, {-1, -1}};

    while (pos < ce->raw_len) {
        
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
 *Simple cfg item line parser.
 *
 *Returns:
 *0: node parse error, 1: node parse success.
 *
 */
static int item_line_parse(struct item_str_t *item_str, struct cfg_entry *ce)
{
    int i;
    char c, p, f, l;

    //parse item name str.
    for (i = 0; i < item_str->name.len; i++) {
        c = item_str->name.data[i];
        if (c == '"') 
            goto out_err;
    }

    //parse item value str.
    f = item_str->value.data[0];
    l = item_str->value.data[item_str->value.len - 1];
    if ((f == '"') == (l == '"'))
        goto out_err;

    for (i = 1; i < item_str->value.len - 1; i++) {
        c = item_str->value.data[i]; 
        p = item_str->value.data[i-1];
        
        if (c == '"' && p != '\\')
            goto out_err;
    }

    return 1; 

out_err:
    printk(KERN_ERR
            "Error: Parse cfg items error on line %d in file /proc/%s/%s\n", 
            item_str->line, CFG_BASE_DIR_NAME, ce->f_name);
    return 0;
}

/**
 *Simple iport parser.
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

int cfg_item_set_str_node(struct item_node_t *node, kconnp_str_t *str)
{
    if (str->len > 0) {
        node->v_str = lkmalloc(str->len + 1);
        if (!node->v_str) {
            printk(KERN_ERR "No more memory!\n");
            return 0;
        }
        memcpy(node->v_str, str->data, str->len);
    } else 
        return 0;

    return 1;
}

int cfg_item_set_int_node(struct item_node_t *node, kconnp_str_t *str)
{
    if (str->len > 0)
        node->v_lval = simple_strtol(str->data, NULL, 10); 
    else 
        return 0;

    return 1;
}

int cfg_item_set_bool_node(struct item_node_t *node, kconnp_str_t *str)
{
    node->v_lval = 1;
    return 1;
}

int cfg_items_entity_init(struct cfg_entry *ce)
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
            hash_func_times33, item_dtor_func)) {
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
                        "Error: Invalid cfg item value on line %d in file /proc/%s/%s\n", 
                        q->line, CFG_BASE_DIR_NAME, ce->f_name);
                ret = 0;
                goto out_hash;
            }
        } else {
            printk(KERN_ERR 
                    "Error: Unrecognized cfg item on line %d in file /proc/%s/%s\n", 
                    q->line, CFG_BASE_DIR_NAME, ce->f_name);
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
 *Simple scanner for iport line.
 *
 *Params:
 * 1.the cfg entry pointer.
 * 2.the current pos to scan.
 * 3.the current line to scan.
 * 4.store the iport pos.
 *
 *Allowed iport characters: 0-9 . * : [] - () A-Z |
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
                || (c >= 'A' && c <= 'Z')
                || c == '(' || c == ')' || c == '|') {

            valid_chars_count++;

            if (c == ':') { //delimeter of ip and port.
                after_colon = 1;
                continue;
            }

            if (c == '(') { //flags start tag.
                flags_begin = 1;
                continue;
            }

            /*Get iport pos*/
            if (!after_colon && iport_pos->ip_start < 0)
                iport_pos->ip_start = *pos - 1;
            if (after_colon && iport_pos->ip_end < 0)
                iport_pos->ip_end = *pos - 3; 

            if (after_colon && iport_pos->port_start < 0)
                iport_pos->port_start = *pos - 1;
            if (after_colon && !flags_begin)  //port part
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
    
    success = iport_pos->ip_end >= 0 && iport_pos->ip_start >= 0 
        && iport_pos->port_end >= 0 && iport_pos->port_start >= 0
        && (flags_begin ? 
                (iport_pos->flags_end >= 0 && iport_pos->flags_start >= 0) : 1)
        && (iport_pos->ip_end - iport_pos->ip_start) >= 0
        && (iport_pos->port_end - iport_pos->port_start) >= 0
        && (iport_pos->flags_end - iport_pos->flags_start) >= 0;

    if (!success)
        goto out_err;
    return success;

out_err: 
    printk(KERN_ERR 
            "Error: Scan iports cfg error on line %d in file /proc/%s/%s\n", 
            *line, CFG_BASE_DIR_NAME, ce->f_name);
    return -1; //Scan error!
}

/**
 *Simple iport scanner.
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
        int *ip_range_start, int *ip_range_end)
{
    char *c;
    int ip_strlen, port_strlen, flags_strlen;
    char ip_range_str[2][4] = {{0, }, {0, }};
    char ip_fourth_str[4] = {0, };
    int i = 0, j = 0, k = 0, n = 0, dot_count = 0, flags_sum = 0;
    int range_start = 0, range_end = 0, range_dash = 0;
    
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

    return 1;
}

/**
 *Simple iport parser.
 *
 *Returns:
 * -1: error, 0: no cfg entries, >0: success.
 */
static int cfg_iports_data_parse(struct iports_str_list_t *iports_str_parsing_list,
        struct iports_str_list_t *iports_str_scanning_list, struct cfg_entry *ce) 
{
    struct iport_str_t *p, *iport_str;
    char *ip_str_or_prefix, *port_str;
    char *flags_str;
    int ip_range_start, ip_range_end; //For parsing []
    int res;

    p = iports_str_scanning_list->list;
    for (; p; p = p->next) {
        int ip_strlen, port_strlen, flags_strlen;

        ip_strlen = strlen(p->ip_str);
        port_strlen = strlen(p->port_str);
        flags_strlen = p->flags_str ? strlen(p->flags_str) : 0;

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
                &ip_range_start, &ip_range_end);
        if (!res)  //Parse node error.
            goto out_free;

        if (ip_range_end == 0) {
            
            NEW_IPORT_STR_NODE(iport_str, 
                    strlen(ip_str_or_prefix) + 1, 
                    strlen(port_str) + 1,
                    flags_strlen ? flags_strlen + 1 : 0);

            INIT_IPORT_STR_NODE(iport_str, 
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
                        strlen(ip_str_tmp) + 1, 
                        strlen(port_str) + 1,
                        flags_strlen ? flags_strlen + 1 : 0);

                INIT_IPORT_STR_NODE(iport_str, 
                        ip_str_tmp, strlen(ip_str_tmp), 
                        port_str, strlen(port_str), 
                        flags_str, flags_strlen,
                        p->line);

                INSERT_INTO_IPORTS_LIST(iports_str_parsing_list, iport_str); 

                lkmfree(ip_str_tmp);
            }
        }

out_free:
        lkmfree(ip_str_or_prefix);
        lkmfree(port_str);
        if (flags_str)
            lkmfree(flags_str);

        if (!res){
            printk(KERN_ERR
                    "Error: Parse iports cfg error on line %d in file /proc/%s/%s\n", 
                    p->line, CFG_BASE_DIR_NAME, ce->f_name);
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

        //ip init
        if (strcmp(p->ip_str, "*") == 0) //Wildcard
            iport_node.ip = 0;
        else {
            if (!ip_aton(p->ip_str, &iaddr)) {
                printk(KERN_ERR 
                        "Error: Convert iport str error on line %d in file /proc/%s/%s\n",
                        p->line, CFG_BASE_DIR_NAME, ce->f_name);
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
                    (const char *)&iport_node, sizeof(struct iport_t), 
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

    if (ret)
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

    return ret;
}

int cfg_init()
{
    //Init cfg base dir.
    cfg_base_dir = proc_mkdir(CFG_BASE_DIR_NAME, NULL);
    if (!cfg_base_dir) {
        printk(KERN_ERR "Error: Couldn't create dir /proc/%s\n", CFG_BASE_DIR_NAME);
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
    remove_proc_entry(CFG_BASE_DIR_NAME, NULL);
}
 
int cfg_conn_op(struct sockaddr *addr, int op_type, void *val)
{
    struct conn_node_t *conn_node;
    unsigned int ip;
    unsigned short int port;
    int ret = 1;

    ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
    port = ((struct sockaddr_in *)addr)->sin_port;

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

void cfg_allowd_iport_node_for_each_call(unsigned int ip, unsigned short int port, 
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
        "%s:%u, Mode: %s, Hits: %d(%u.0%), Misses: %d(%u.0%)\n";
#else
        "%s:%u, Mode: %s, Hits: %ld(%u.0%), Misses: %ld(%u.0%)\n";
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
        char *ip_ptr, ip_str[16] = {0, };
        char mode[16] = {0, };
        char buffer[128] = {0, };
        int l;
        
        conn_node = (struct conn_node_t *)hash_value(pos);

        if (conn_node->conn_close_way == CLOSE_PASSIVE) 
            strcpy(mode, "PASSIVE");
        else
            strcpy(mode, "POSITIVE");
 
        ip = conn_node->conn_ip;
        if (ip == 0) {
            strcpy(ip_str, "*");
            ip_ptr = ip_str;
        } else
            ip_ptr = ip_ntoa(ip);
           
        port = ntohs(conn_node->conn_port);
       
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
                ip_ptr, port, 
                mode, 
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

#include <linux/string.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include "util.h"
#include "hash.h"
#include "cfg.h"

#define CFG_ALLOWD_IPORTS_FILE "iports.allow"
#define CFG_DENIED_IPORTS_FILE "iports.deny"

#define cfg_entries_walk_func_check(func_name)    \
    do {    \
        struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;  \
        for (p = entry; \
                p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++) {\
            if (!p->func_name(p))    \
                return 0;   \
        } \
    } while (0)

#define cfg_entries_walk_func_no_check(func_name) \
    do {    \
        struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;  \
        for (p = entry; \
                p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++)\
            p->func_name(p);   \
    } while (0)

#define RESET_IPORT_POS(iport_pos)        \
    do {                                \
        (iport_pos)->ip_start = -1;     \
        (iport_pos)->ip_end = -1;       \
        (iport_pos)->port_start = -1;   \
        (iport_pos)->port_end = -1;     \
    } while (0)


#define NEW_IPORT_STR_NODE(iport_str, ip_strlen, port_strlen)   \
    do {                                                        \
        iport_str = lkmalloc(sizeof(struct iport_str_t));       \
        if (!iport_str)                                         \
            return 0;                                           \
        iport_str->ip_str = lkmalloc(ip_strlen);                \
        if (!iport_str->ip_str) {                               \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
        iport_str->port_str = lkmalloc(port_strlen);            \
        if (!iport_str->port_str) {                             \
            lkmfree(iport_str->ip_str);                         \
            lkmfree(iport_str);                                 \
            return 0;                                           \
        }                                                       \
    } while (0)  

#define INIT_IPORT_STR_NODE(iport_str, ip_str_pass, ip_strlen,      \
        port_str_pass, port_strlen,                                 \
        line_pass)                                                  \
    do {                                                            \
        memcpy((iport_str)->ip_str, ip_str_pass, ip_strlen);        \
        memcpy((iport_str)->port_str, port_str_pass, port_strlen);  \
        (iport_str)->line = line_pass;                              \
    } while (0)

#define DESTROY_IPORT_STR_NODE(iport_str)   \
    do {                                    \
        lkmfree((iport_str)->ip_str);       \
        lkmfree((iport_str)->port_str);     \
        lkmfree(iport_str);                 \
    } while (0)

#define INSERT_INTO_IPORTS_STR_LIST(iports_scan_list, iport_str)    \
    do {                                                            \
        if ((iports_scan_list)->list)                               \
            (iport_str)->next = (iports_scan_list)->list;           \
        iports_scan_list->list = iport_str;                     \
        (iports_scan_list)->count++;                                \
    } while (0)


#define NEW_IPORT_STR_SCAN_NODE(iport_str, iport_pos)                               \
    NEW_IPORT_STR_NODE(iport_str, (iport_pos)->ip_end - (iport_pos)->ip_start + 2,  \
            (iport_pos)->port_end - (iport_pos)->port_start + 2/*one for \0*/)

#define INIT_IPORT_STR_SCAN_NODE(iport_str, ce, iport_pos, line)    \
    INIT_IPORT_STR_NODE(iport_str,                                  \
            (ce)->raw_ptr + (iport_pos)->ip_start,                  \
            (iport_pos)->ip_end - (iport_pos)->ip_start + 1,        \
            (ce)->raw_ptr + (iport_pos)->port_start,                \
            (iport_pos)->port_end - (iport_pos)->port_start + 1,    \
            line)


/*iports list cfg funcs*/
static int ip_aton(const char *, struct in_addr *); //For IPV4
static int iport_line_scan(struct cfg_entry *, int *, int *, struct iport_pos_t *);
static int iport_node_parse(struct iport_str_t *, char *, char *, int *, int *);
static void iports_str_list_free(struct iports_str_list_t *);
static int cfg_iports_data_scan(struct cfg_entry *, struct iports_str_list_t *);
static int cfg_iports_data_parse(struct cfg_entry *, struct iports_str_list_t *, 
        struct iports_str_list_t *);
static inline struct cfg_entry *get_ce(void *);
static int cfg_proc_init(struct cfg_entry *);
static inline void cfg_proc_destroy(struct cfg_entry *);
static int cfg_iports_entity_init(struct cfg_entry *);
static void cfg_iports_entity_destroy(struct cfg_entry *);
static int cfg_iports_list_init(struct cfg_entry *);
static void cfg_iports_list_destroy(struct cfg_entry *);
static int cfg_iports_list_reload(struct cfg_entry *);

static inline struct conn_node_t *iport_in_list_check_or_call(struct sockaddr_in *, struct cfg_entry *, int (*call_func)(void *data));

struct cfg_dir {
    struct cfg_entry allowed_list;
#define al allowed_list
#define al_ptr allowed_list.cfg_ptr
#define al_mtime allowed_list.f_mtime
#define al_init(cfg_entry_ptr) allowed_list.init(cfg_entry_ptr)
#define al_destory(cfg_entry_ptr) allowed_list.destroy(cfg_entry_ptr)
#define al_reload(cfg_entry_ptr) allowed_list.reload(cfg_entry_ptr)
    struct cfg_entry denied_list;
#define dl denied_list
#define dl_ptr denied_list.cfg_ptr
#define dl_mtime denied_list.f_mtime
#define dl_init(cfg_entry_ptr) denied_list.init(cfg_entry_ptr)
#define dl_destory(cfg_entry_ptr) denied_list.destroy(cfg_entry_ptr)
#define dl_reload(cfg_entry_ptr) denied_list.reload(cfg_entry_ptr)
};
static struct cfg_dir cfg_dentry = { //initial the cfg directory.
    { //allowed_list
        .f_name = CFG_ALLOWD_IPORTS_FILE,
        .init = cfg_iports_list_init,
        .destroy = cfg_iports_list_destroy,
        .reload = cfg_iports_list_reload
    },
    { //denied_list
        .f_name = CFG_DENIED_IPORTS_FILE,
        .init = cfg_iports_list_init,
        .destroy = cfg_iports_list_destroy,
        .reload = cfg_iports_list_reload
    }
};

struct cfg_dir *cfg = &cfg_dentry;

static struct proc_dir_entry *cfg_base_dir;

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
int cfg_proc_read(char *buffer,
        char **buffer_location,
        off_t offset, int buffer_length, int *eof, void *data)
{
    int read_count;
    struct cfg_entry *ce;

    ce = get_ce(data);

    if (offset >= ce->raw_len) { //has read all data.
        *eof = 1;
        return 0;
    }

    read_count = buffer_length > (ce->raw_len - offset) 
        ? (ce->raw_len - offset) : buffer_length;

    memcpy(buffer, ce->raw_ptr + offset, read_count);
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

    ce = get_ce(data);
    if (!ce)
        return 0;
    
    if (count > PAGE_SIZE) {
        printk(KERN_ERR 
                "Error: The cfg iports file /proc/%s/%s exceeds the max size %lu bytes!\n",
                CFG_BASE_DIR_NAME, ce->f_name, PAGE_SIZE);
        return 0;
    }

    if (ce->raw_ptr) {
        old_raw_ptr = ce->raw_ptr;
        old_raw_len = ce->raw_len;
    }

    ce->raw_ptr = lkmalloc(count);
    if (!ce->raw_ptr)
        return -ENOMEM;
    ce->raw_len = count;

    /* Write data to the buffer */
    if (copy_from_user(ce->raw_ptr, buffer, count)) {
        lkmfree(ce->raw_ptr);
        ce->raw_ptr = old_raw_ptr; //Restore
        ce->raw_len = old_raw_len;
        return -EFAULT;
    }

    if (old_raw_ptr) {
        lkmfree(old_raw_ptr);
    }
    
    ce->reload(ce); //Reload cfg.

    return count;
}

static inline struct cfg_entry *get_ce(void *data)
{
    struct cfg_entry *p, *entry = (struct cfg_entry *)cfg;

    for (p = entry; 
            p < entry + sizeof(struct cfg_dir) / sizeof(struct cfg_entry); p++){
        if (p == data)
            return p;
    }
    return NULL;
}

static int cfg_proc_init(struct cfg_entry *ce)
{
    ce->cfg_proc_file = create_proc_entry(ce->f_name, S_IFREG|S_IRUGO, 
            cfg_base_dir);

    if (!ce->cfg_proc_file) {
        remove_proc_entry(ce->f_name, cfg_base_dir);
        printk(KERN_ERR
                "Error: Could not initialize /proc/%s/%s\n",
                CFG_BASE_DIR_NAME, ce->f_name);
        return 0;
    }

    ce->cfg_proc_file->data = (void *)ce; 
    ce->cfg_proc_file->read_proc = cfg_proc_read;
    ce->cfg_proc_file->write_proc = cfg_proc_write;
    ce->cfg_proc_file->uid = 0;
    ce->cfg_proc_file->gid = 0;

    return 1;
}

static inline void cfg_proc_destroy(struct cfg_entry *ce)
{
    remove_proc_entry(ce->f_name, cfg_base_dir);
}

static int cfg_iports_list_init(struct cfg_entry *ce)
{
    if (!cfg_proc_init(ce))
        return 0;

    if (!cfg_iports_entity_init(ce))
        return 0;

    return 1;
}

static void cfg_iports_list_destroy(struct cfg_entry *ce)
{
    cfg_proc_destroy(ce);
    cfg_iports_entity_destroy(ce);
}

/**
 *Convert IPV4 ipstr to int.
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
 *Allowed iport characters: 0-9 . * : [] -
 *
 *Returns:
 * -1: line scan error, 0: line scan done, 1: line scan success.
 */
static int iport_line_scan(struct cfg_entry *ce, int *pos, int *line, 
        struct iport_pos_t *iport_pos)
{
    char c;
    int comment_line_start = 0;
    int valid_char_count = 0;
    int success = 0;
    int after_colon = 0;

    (*line)++;

    while (*pos < ce->raw_len /*the last line*/
            && (c = ce->raw_ptr[(*pos)++]) != '\n') {

        if (comment_line_start || c == '#') {/*strip comment by '#'*/
            comment_line_start = 1; 
            continue;
        }

        if (c == ' ' || c == '\t') {//strip blank char.
            continue;
        }

        if ((c >= '0' && c <= '9') || c == '.'  //valid char
                || c == '*' || c == ':'
                || c == '[' || c == ']' || c == '-') {

            valid_char_count++;

            if (c == ':') { //delimeter of ip and port.
                after_colon = 1;
                continue;
            }

            /*Get iport pos*/
            if (!after_colon && iport_pos->ip_start < 0)
                iport_pos->ip_start = *pos - 1;
            if (after_colon && iport_pos->ip_end < 0)
                iport_pos->ip_end = *pos - 3; 
            if (after_colon && ((c < '0' || c > '9') && c != '*')) //Port str
                goto out_fail;
            if (after_colon && iport_pos->port_start < 0)
                iport_pos->port_start = *pos - 1;
            if (after_colon) //Default is port_end pos.
                iport_pos->port_end = *pos - 1;

            success = ((iport_pos->ip_end - iport_pos->ip_start) >= 0) 
                && ((iport_pos->port_end - iport_pos->port_start) >= 0);

        }else
            goto out_fail;
    }
    
    if (!success && valid_char_count > 0) //May not be blank line or comment line.
        goto out_fail;
    return success;

out_fail: 
    printk(KERN_ERR 
            "Error: Scan iports cfg error on line %d in file /proc/%s/%s\n", 
            *line, CFG_BASE_DIR_NAME, ce->f_name);
    return -1; //Scan error!
}

/**
 * Simple iport str scanner.
 */
static int cfg_iports_data_scan(struct cfg_entry *ce, 
        struct iports_str_list_t *iports_str_scanning_list)
{
    int pos = 0;
    int line = 0;
    int res;
    struct iport_pos_t iport_pos;
    struct iport_str_t *iport_str;

    while (pos < ce->raw_len) {
        RESET_IPORT_POS(&iport_pos);
        res = iport_line_scan(ce, &pos, &line, &iport_pos);
        if (res < 0) //Scan error.
            return -1;
        if (!res) // Line scan done but needn't.
            continue;
        NEW_IPORT_STR_SCAN_NODE(iport_str, &iport_pos);
        INIT_IPORT_STR_SCAN_NODE(iport_str, ce, &iport_pos, line);
        INSERT_INTO_IPORTS_STR_LIST(iports_str_scanning_list, iport_str);
    }

    return iports_str_scanning_list->count;
}

/**
 *Simple iport node parser.
 *
 *Returns:
 *0: node parse error, 1: node parse success.
 *
 */
static int iport_node_parse(struct iport_str_t *iport_str, 
        char *port_str, char *ip_str_or_prefix,
        int *ip_range_start, int *ip_range_end)
{
    char *c;
    int ip_strlen, port_strlen;
    char ip_range_str[2][4] = {{0, }, {0, }};
    char ip_fourth_str[4] = {0, };
    int i = 0, j = 0, k = 0, n = 0, dot_count = 0;
    int range_start = 0, range_end = 0, range_dash = 0;
    
    ip_strlen = strlen(iport_str->ip_str);
    port_strlen = strlen(iport_str->port_str);

    /*Parse port str*/
    for (c = iport_str->port_str; *c; c++) { //Parse port.
        if ((*c == '*' && port_strlen != 1) || (*c < '0' || *c > '9'))
            return 0; //error
    }
    strcpy(port_str, iport_str->port_str);

    /*Parse ip str*/ 
    for (c = iport_str->ip_str; *c; c++) {
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
static int cfg_iports_data_parse(struct cfg_entry *ce, 
        struct iports_str_list_t *iports_str_scanning_list, 
        struct iports_str_list_t *iports_str_parsing_list)
{
    struct iport_str_t *p, *iport_str;
    char *ip_str_or_prefix, *port_str;
    int ip_range_start, ip_range_end; //For parsing []
    int res;

    for (p = iports_str_scanning_list->list; p; p = p->next) {
        int ip_strlen, port_strlen;

        ip_strlen = strlen(p->ip_str);
        port_strlen = strlen(p->port_str);

        ip_str_or_prefix = lkmalloc(ip_strlen + 1); 
        if (!ip_str_or_prefix)
            return -1;

        port_str = lkmalloc(port_strlen + 1); 
        if (!port_str) {
            lkmfree(ip_str_or_prefix);
            return -1;
        }

        ip_range_start = ip_range_end = 0;
        res = iport_node_parse(p, port_str, ip_str_or_prefix, 
                &ip_range_start, &ip_range_end);
        if (!res)  //Parse node error.
            goto out_free;

        if (ip_range_end == 0) {
            NEW_IPORT_STR_NODE(iport_str, strlen(ip_str_or_prefix) + 1, 
                    strlen(port_str) + 1);
            INIT_IPORT_STR_NODE(iport_str, 
                    ip_str_or_prefix, strlen(ip_str_or_prefix), 
                    port_str, strlen(port_str), p->line);
            INSERT_INTO_IPORTS_STR_LIST(iports_str_parsing_list, iport_str); 
        } else if (ip_range_end > 0) { //For parsing []
            char ip_range_str[4] = {0, };
            int ip_num;
            char *ip_str_tmp;

            for (ip_num = ip_range_start; ip_num <= ip_range_end; ip_num++) {
                sprintf(ip_range_str, "%d", ip_num);
                ip_str_tmp = lkmalloc(ip_strlen + 1);
                strcpy(ip_str_tmp, ip_str_or_prefix);
                strcat(ip_str_tmp, ip_range_str);
                NEW_IPORT_STR_NODE(iport_str, strlen(ip_str_tmp) + 1, 
                        strlen(port_str) + 1);
                INIT_IPORT_STR_NODE(iport_str, ip_str_tmp, strlen(ip_str_tmp), 
                        port_str, strlen(port_str), p->line);
                INSERT_INTO_IPORTS_STR_LIST(iports_str_parsing_list, iport_str); 
                lkmfree(ip_str_tmp);
            }
        }

out_free:
        lkmfree(ip_str_or_prefix);
        lkmfree(port_str);

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
    struct conn_node_t conn_node;
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

    if ((res = cfg_iports_data_scan(ce, iports_str_scanning_list)) <= 0) {
        if (res < 0) //Error.
            ret = 0;
        goto out_free;
    }

    if ((res = cfg_iports_data_parse(ce, iports_str_scanning_list, 
                    iports_str_parsing_list)) <= 0) {
        if (res < 0) //error
            ret = 0;
        goto out_free;
    }

    if (!hash_init((struct hash_table_t **)&ce->cfg_ptr, NULL)) {
        ret = 0;
        goto out_free;
    }
    
    for (p = iports_str_parsing_list->list; p; p = p->next) {
        struct in_addr iaddr;
        
        memset(&conn_node, 0, sizeof(struct conn_node_t)); 

        if (strcmp(p->ip_str, "*") == 0) //Wildcard
            conn_node.conn_ip = 0;
        else {
            if (!ip_aton(p->ip_str, &iaddr)) {
                printk(KERN_ERR 
                        "Error: Convert iport str error on line %d in file /proc/%s/%s\n",
                        p->line, CFG_BASE_DIR_NAME, ce->f_name);
                hash_destroy((struct hash_table_t **)&ce->cfg_ptr);
                ret = 0;
                goto out_free;
            }
            conn_node.conn_ip = (unsigned int)iaddr.s_addr;
        }

        if (strcmp(p->port_str, "*") == 0) //Wildcard
            conn_node.conn_port = 0;
        else
            conn_node.conn_port = htons(simple_strtol(p->port_str, NULL, 10));

        if (!hash_set((struct hash_table_t *)ce->cfg_ptr, 
                    (const char *)&conn_node.iport_node, sizeof(struct iport_t), 
                    &conn_node, sizeof(struct conn_node_t))){
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

static int cfg_iports_list_reload(struct cfg_entry *ce)
{
    if (ce->cfg_ptr)    
        hash_destroy((struct hash_table_t **)&ce->cfg_ptr);

    return cfg_iports_entity_init(ce);
}

#define iport_in_list(addr, ce) iport_in_list_check_or_call(addr, ce, NULL)
#define iport_in_list_for_each_call(addr, ce, call_func) iport_in_list_check_or_call(addr, ce, call_func)
static inline struct conn_node_t *iport_in_list_check_or_call(struct sockaddr_in *addr, struct cfg_entry *ce, int (*call_func)(void *data))
{
    struct iport_t zip_port, ip_zport, ip_port, **p;
    struct iport_t *iport_list[] = {&ip_port, &ip_zport, &zip_port, NULL}; 
    struct hash_table_t *ht_ptr = (struct hash_table_t *)ce->cfg_ptr;
   
    for (p = &iport_list[0]; *p; p++) 
        memset(*p, 0, sizeof(struct iport_t));

    zip_port.ip = 0;
    zip_port.port = addr->sin_port;

    ip_zport.ip = addr->sin_addr.s_addr;
    ip_zport.port = 0;

    ip_port.ip = addr->sin_addr.s_addr;
    ip_port.port = addr->sin_port;

    for (p = &iport_list[0]; *p; p++) {
        struct conn_node_t *tmp;

        if (hash_find(ht_ptr, 
                    (const char *)*p, sizeof(struct iport_t), (void **)&tmp)) {
            if (call_func)
                call_func(tmp);
            else
                return tmp;
        }
    }
    
    return NULL;
}

struct conn_node_t *iport_in_allowd_list(struct sockaddr *address)
{
    if (!cfg->al.cfg_ptr) //if allowed list is null, none allowed.
        return NULL;

    return iport_in_list((struct sockaddr_in *)address, &cfg->al);
}

struct conn_node_t *iport_in_denied_list(struct sockaddr *address)
{
    if (!cfg->dl.cfg_ptr)
        return NULL;

    return iport_in_list((struct sockaddr_in *)address, &cfg->dl);
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
    cfg_entries_walk_func_check(init);

    return 1;
}

void cfg_destroy()
{
    //Destory cfg entries
    cfg_entries_walk_func_no_check(destroy);
    //Destroy cfg base dir.
    remove_proc_entry(CFG_BASE_DIR_NAME, NULL);
}

void do_cfg_allowed_entries_for_each_call(int (*call_func)(void *data), int type)
{
    struct conn_node_t *conn_node; 
    struct hash_bucket_t *pos;

    hash_for_each(cfg->al_ptr, pos) {
        conn_node = hash_value(pos);
        //printk(KERN_ERR "conn close way: %d\n", conn_node->conn_close_way);
        if (type == CALL_DIRECTLY) {
            if (!call_func((void *)conn_node))
                continue;
        } else if (type == CALL_CHECK) {
            struct sockaddr_in address;
            if (conn_node->conn_ip == 0 || conn_node->conn_port == 0)
                continue;

            address.sin_addr.s_addr = conn_node->conn_ip;
            address.sin_port = conn_node->conn_port;

            if (!iport_in_denied_list((struct sockaddr *)&address));
                if (!call_func((void *)conn_node))
                    continue;
        }
    }
}

void cfg_allowd_iport_node_for_each_call(struct sockaddr *addr, 
        int (*call_func)(void *data)) 
{
    iport_in_list_for_each_call((struct sockaddr_in *)addr, &cfg->al, call_func);
}

#include <linux/string.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include "connp.h"
#include "util.h"
#include "hash.h"
#include "cfg.h"

#define CFG_ALLOWD_IPORTS_FILE "iports.allow"
#define CFG_DENIED_IPORTS_FILE "iports.deny"
#define CFG_CONN_STATS_INFO_FILE "stats.info"

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
static void cfg_proc_destroy(struct cfg_entry *);

static int cfg_proc_read(char *buffer, char **buffer_location, 
        off_t offset, int buffer_length, int *eof, void *data);
static int cfg_proc_write(struct file *file, const char *buffer, unsigned long count,
        void *data);


static int cfg_iports_entity_init(struct cfg_entry *);
static void cfg_iports_entity_destroy(struct cfg_entry *);
static int cfg_iports_entity_reload(struct cfg_entry *);

static int cfg_iports_list_init(struct cfg_entry *);
static void cfg_iports_list_destroy(struct cfg_entry *);


static int cfg_stats_info_init(struct cfg_entry *);
static void cfg_stats_info_destroy(struct cfg_entry *);

static int cfg_white_list_entity_init(struct cfg_entry *);
static void cfg_white_list_entity_destroy(struct cfg_entry *);
static int cfg_white_list_entity_reload(struct cfg_entry *);


static inline void *iport_in_list_check_or_call(unsigned int ip, unsigned short int port,  struct cfg_entry *, void (*call_func)(void *data));

struct cfg_dir {
    struct cfg_entry allowed_list;
#define al allowed_list
#define al_ptr allowed_list.cfg_ptr
#define al_rwlock allowed_list.cfg_rwlock
    struct cfg_entry denied_list;
#define dl denied_list
#define dl_ptr denied_list.cfg_ptr
#define dl_rwlock denied_list.cfg_rwlock
    struct cfg_entry stats_info;
#define st stats_info
#define st_ptr stats_info.raw_ptr
#define st_len stats_info.raw_len
#define st_rwlock stats_info.cfg_rwlock
};

static struct cfg_dir cfg_dentry = { //initial the cfg directory.
    { //allowed_list
        .f_name = CFG_ALLOWD_IPORTS_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,

        .init = cfg_iports_list_init,
        .destroy = cfg_iports_list_destroy,

        .entity_init = cfg_iports_entity_init,
        .entity_destroy = cfg_iports_entity_destroy,
        .entity_reload = cfg_iports_entity_reload
    },
    { //denied_list
        .f_name = CFG_DENIED_IPORTS_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = cfg_proc_write,
        
        .init = cfg_iports_list_init,
        .destroy = cfg_iports_list_destroy,

        .entity_init = cfg_iports_entity_init,
        .entity_destroy = cfg_iports_entity_destroy,
        .entity_reload = cfg_iports_entity_reload
    },
    { //stats info
        .f_name = CFG_CONN_STATS_INFO_FILE,

        .proc_read = cfg_proc_read,
        .proc_write = NULL,

        .init = cfg_stats_info_init,
        .destroy = cfg_stats_info_destroy
    }
};
static struct cfg_dir *cfg = &cfg_dentry;

static struct proc_dir_entry *cfg_base_dir;

//white list.
static struct cfg_entry white_list = { //final allowed list.
    .entity_init = cfg_white_list_entity_init,
    .entity_destroy = cfg_white_list_entity_destroy,
    .entity_reload = cfg_white_list_entity_reload
};
static struct cfg_entry *wl = &white_list;

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
    int read_count;
    struct cfg_entry *ce;

    ce = get_ce(data);
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
static int cfg_proc_write(struct file *file, const char *buffer, unsigned long count,
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
   
    if (ce->entity_reload(ce)) //Reload proc cfg.
        wl->entity_reload(wl);

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

static void cfg_proc_destroy(struct cfg_entry *ce)
{
    if (ce->cfg_proc_file)
        remove_proc_entry(ce->f_name, cfg_base_dir);
}

static int cfg_iports_list_init(struct cfg_entry *ce)
{
    if (!cfg_proc_init(ce))
        return 0;

    if (!ce->entity_init(ce)) {
        cfg_proc_destroy(ce);
        return 0;
    }

    return 1;
}

static int cfg_stats_info_init(struct cfg_entry *ce)
{
    return cfg_proc_init(ce);
}

static void cfg_iports_list_destroy(struct cfg_entry *ce)
{
    ce->entity_destroy(ce);
    cfg_proc_destroy(ce);
}

static void cfg_stats_info_destroy(struct cfg_entry *ce)
{
    if (ce->raw_ptr)
        lkmfree(ce->raw_ptr);

    cfg_proc_destroy(ce);
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
        
        memset(&iport_node, 0, sizeof(struct iport_t)); 

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

        if (strcmp(p->port_str, "*") == 0) //Wildcard
            iport_node.port = 0;
        else
            iport_node.port = htons(simple_strtol(p->port_str, NULL, 10));

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
    struct iport_t zip_port, ip_zport, ip_port, **p;
    struct iport_t *iport_list[] = {&ip_port, &ip_zport, &zip_port, NULL}; 
    struct hash_table_t *ht_ptr;

    ht_ptr = (struct hash_table_t *)ce->cfg_ptr;

    if (!ht_ptr)
        return NULL;
        
    for (p = &iport_list[0]; *p; p++) 
        memset(*p, 0, sizeof(struct iport_t));

    zip_port.ip = 0;
    zip_port.port = port;

    ip_zport.ip = ip;
    ip_zport.port = 0;

    ip_port.ip = ip;
    ip_port.port = port;

    for (p = &iport_list[0]; (*p); p++) {
        void *tmp;

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

        iport_node = (struct iport_t *)hash_value(pos);
        
        read_lock(&cfg->dl_rwlock);
        in_denied_list = iport_in_denied_list(iport_node->ip, iport_node->port) 
            ? 1 : 0;
        read_unlock(&cfg->dl_rwlock);

        if (in_denied_list)
            continue;
        
        conn_node.conn_ip = iport_node->ip;
        conn_node.conn_port = iport_node->port;

        if (!hash_set((struct hash_table_t *)wl->cfg_ptr, 
                    (const char *)iport_node, sizeof(struct iport_t), 
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

    //white list init
    rwlock_init(&wl->cfg_rwlock);
    wl->entity_init(wl);

    return 1;
}

void cfg_destroy()
{
    //White list destory
    wl->entity_destroy(wl);

    //Destory cfg entries
    cfg_entries_walk_func_no_check(destroy);

    //Destroy cfg base dir.
    remove_proc_entry(CFG_BASE_DIR_NAME, NULL);
}
 
int cfg_conn_op(struct sockaddr *addr, int op_type)
{
    struct conn_node_t *conn_node;
    int ret = 1;
    unsigned int ip;
    unsigned short int port;

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
            ret = (conn_node->conn_close_way == CLOSE_POSITIVE);
            break;
        case PASSIVE_SET:
            conn_node->conn_close_way = CLOSE_PASSIVE;
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
    const char *conn_stat_str_fmt = "%s:%u, Mode: %s, Hits: %lu(%d.0%), Misses: %lu(%d.0%)\n";
    char *buffer;
    struct hash_bucket_t *pos;
    int offset = 0;

    write_lock(&cfg->st_rwlock);

    if (cfg->st_ptr) {
        cfg->st_len = 0;
        lkmfree(cfg->st_ptr);
    }

    cfg->st_ptr = lkmalloc(PAGE_SIZE);
   
    read_lock(&wl->cfg_rwlock); 

    if (!wl->cfg_ptr)
        goto unlock_ret;
    
    hash_for_each((struct hash_table_t *)wl->cfg_ptr, pos) {
        struct conn_node_t *conn_node;
        unsigned int ip;
        unsigned short int port;
        unsigned long all_count, misses_count, hits_count;
        unsigned int misses_percent, hits_percent; 
        char mode[32];
        char ip_str[16], *ip_ptr;
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
        
        all_count = lkm_atomic_read(&conn_node->conn_connected_all_count);
        hits_count = lkm_atomic_read(&conn_node->conn_connected_hit_count);
        misses_count = all_count - hits_count;

        if (all_count == 0) {
            misses_percent = 0;
            hits_percent = 0;
        } else {
            misses_percent = (misses_count * 100) / all_count;
            hits_percent = 100 - misses_percent;
        }

        buffer = lkmalloc(128);
        
        l = sprintf(buffer, conn_stat_str_fmt, ip_ptr, port, mode, 
                hits_count, hits_percent,
                misses_count, misses_percent);

        if (l > (PAGE_SIZE - cfg->st_len)) {
            lkmfree(buffer);
            goto unlock_ret;
        }
        
        memcpy(cfg->st_ptr + offset, buffer, l); 

        offset += l; 

        cfg->st_len += l;

        lkmfree(buffer);
    }

unlock_ret:
    read_unlock(&wl->cfg_rwlock); 
    write_unlock(&cfg->st_rwlock);
    return;
}

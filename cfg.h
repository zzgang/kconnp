#ifndef _CFG_H
#define _CFG_H

#include <linux/socket.h>
#include <linux/proc_fs.h>

#define CFG_BASE_DIR_NAME "kconnp"

struct cfg_entry {
    /*attributes*/
    char *f_name; /*cfg file name*/
    struct proc_dir_entry *cfg_proc_file;  
    unsigned int raw_len; /*the data lenth read from the procfile*/
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

struct iport_str_t {
    int line; //the line no where the iport located of the cfg proc file.
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

extern int iport_in_allowd_list(struct sockaddr *address);
extern int iport_in_denied_list(struct sockaddr *address);
extern int cfg_init(void);
extern void cfg_destroy(void);

#endif

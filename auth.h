#ifndef __AUTH_H
#define __AUTH_H

#include "kconnp.h"
#include "lkm_util.h"

typedef enum {
    AUTH_NEW,
    AUTH_PROCESSING,
    AUTH_FAIL,
    AUTH_SUCCESS
} auth_status_t;

struct auth_stage {
    char type; //auth call r/w/i
    kconnp_str_t info; //auth info.
    struct auth_stage *next;
};

extern int check_if_ignore_auth_procedure(int fd, const char __user *buf, size_t len, 
        char io_type);

static inline void auth_procedure_destroy(struct auth_stage *procedure_head)
{
    struct auth_stage *p, *q;

    p = procedure_head;

    while(p) {
        if (p->info.data) 
            lkmfree(p->info.data);
        printk(KERN_ERR "cfg_destory type: %d", p->type);
        q = p->next;
        lkmfree(p);
        p = q;
    }
}

#endif

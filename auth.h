#ifndef __AUTH_H
#define __AUTH_H

#include "kconnp.h"

typedef enum {
    AUTH_NEW,
    AUTH_PROCESSING,
    AUTH_FAIL,
    AUTH_SUCCESS
} auth_status_t;

struct auth_stage {
    char type; //auth call r/w/i
    kconnp_str_t data; //auth info.
    struct auth_stage *next;
};

extern int auth_procedure_process(struct sockaddr *, kconnp_str_t *, char io_type);

static inline auth_procedure_destroy(struct auth_stage *procedure_head)
{
    struct auth_stage *p, *q;

    p = procedure_head;

    while(p) {
        if (p->data.data) 
            lkmfree(p->data.data);
        q = p;
        lkmfree(p);
        p = p->next;
    }
}

#endif

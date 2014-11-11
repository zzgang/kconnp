#ifndef _STACK_H_
#define _STACK_H_

#include "lkm_util.h"

#define WITHOUT_MUTEX 0
#define WITH_MUTEX 1

struct stack_t {
    //attrs
    char *eles;
    int ele_size; //one ele size
    int ele_size_align; //one ele size after align
    int list_size; //stack capacity
    int elements;
    int sp;
    spinlock_t *s_lock;

    //funcs
    int (*create)(struct stack_t **s, int list_size, int ele_size, int mutex);
    int (*clone)(struct stack_t **d, struct stack_t *s);

    char *(*in)(struct stack_t *s, void *ele);
    char *(*out)(struct stack_t *s);

    void (*destroy)(struct stack_t **s);
};

static inline int stack_init(struct stack_t **s, int list_size, int ele_size, int mutex);
static inline int stack_clone(struct stack_t **d, struct stack_t *s);

static inline char *stack_push(struct stack_t *s, void *ele);
static inline char *stack_pop(struct stack_t *s);

static inline void stack_destroy(struct stack_t **s);

#define stack_is_empty(s) (s->sp == -1)
#define stack_is_full(s) (s->sp == (s->list_size - 1))

static inline int stack_init(struct stack_t **s, int list_size, int ele_size, int mutex)
{
    int ele_size_align;
    
    if (list_size <= 0 || ele_size <= 0) {
        *s = NULL;
        return 0;
    }

    *s = lkmalloc(sizeof(struct stack_t));
    if (!*s)
        return 0;

    ele_size_align = BYTES_ALIGN(ele_size);

    (*s)->eles = lkmalloc(list_size * ele_size_align);
    if (!(*s)->eles) {
        lkmfree(*s);
        *s = NULL;
        return 0;
    }
    
    (*s)->list_size = list_size;
    (*s)->ele_size = ele_size;
    (*s)->ele_size_align = ele_size_align;
    (*s)->elements = 0;
    (*s)->sp = -1;
    (*s)->s_lock = NULL;
   
    (*s)->create = stack_init;
    (*s)->clone = stack_clone; 

    (*s)->in = stack_push;
    (*s)->out = stack_pop;

    (*s)->destroy = stack_destroy;
    
    if (mutex) {
        (*s)->s_lock = (spinlock_t *)lkmalloc(sizeof(spinlock_t));
        spin_lock_init((*s)->s_lock);
    }

    return 1;
}

static inline int stack_clone(struct stack_t **d, struct stack_t *s)
{
    if (!s)
        return 0;

    return stack_init(d, s->list_size, s->ele_size, s->s_lock ? WITH_MUTEX : WITHOUT_MUTEX);
}

static inline char *stack_push(struct stack_t *s, void *ele)
{
    if (!s)
        return NULL;

    if (s->s_lock)
        spin_lock(s->s_lock);

    if (stack_is_full(s))
        goto ret_fail;

    ++s->sp;
    ++s->elements;

    memcpy(s->eles + (s->sp * s->ele_size_align), ele, s->ele_size);
    
out:
    if (s->s_lock)
        spin_unlock(s->s_lock);
    return ele;
ret_fail:
    ele = NULL;
    goto out;
}

static inline char *stack_pop(struct stack_t *s)
{
    void *ele;

    if (!s)
        return NULL;

    if (s->s_lock)
        spin_lock(s->s_lock);

    if (stack_is_empty(s))
        goto ret_fail;
    
    ele = s->eles + (s->sp * s->ele_size_align);
    
    --s->sp;
    --s->elements;

out:
    if (s->s_lock)
        spin_unlock(s->s_lock);
    return ele;
ret_fail:
    ele = NULL;
    goto out;
}

static inline void stack_destroy(struct stack_t **s)
{
    if (*s && (*s)->s_lock) 
        lkmfree((*s)->s_lock);

    if (*s && (*s)->eles)
        lkmfree((*s)->eles); 

    if (*s)
        lkmfree(*s);

    *s = NULL;
}

#endif

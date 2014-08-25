#ifndef _ARRAY_H_
#define _ARRAY_H_

#include "lkm_util.h"

struct array_t {
    //attrs
    char *eles;
    int ele_size; //one ele real size
    int ele_size_align; //one ele size after align
    int elements;

    //funcs
    int (*create)(struct array_t **s, int elements, int ele_size);
    int (*clone)(struct array_t **d, struct array_t *s);

    char *(*get)(struct array_t *s, int idx);
    char *(*set)(struct array_t *s, void *ele, int idx);

    void (*destroy)(struct array_t **s);
     
};

static inline int array_init(struct array_t **s, int elements, int ele_size);
static inline int array_clone(struct array_t **d, struct array_t *s);

static inline char *array_set(struct array_t *s, void *ele, int idx);
static inline char *array_get(struct array_t *s, int idx);

static inline void array_destroy(struct array_t **s);


static inline int array_init(struct array_t **s, int elements, int ele_size)
{
    int ele_size_align;

    if (elements <= 0 || ele_size <= 0) {
        *s = NULL;
        return 0;
    }

    *s = lkmalloc(sizeof(struct array_t));
    if (!*s)
        return 0;

    ele_size_align = BYTES_ALIGN(ele_size);

    (*s)->eles = lkmalloc(elements * ele_size_align);
    if (!(*s)->eles) {
        lkmfree(*s);
        *s = NULL;
        return 0;
    }
    
    (*s)->elements = elements;
    (*s)->ele_size = ele_size;
    (*s)->ele_size_align = ele_size_align;
   
    (*s)->create = array_init;
    (*s)->clone = array_clone; 

    (*s)->set = array_set;
    (*s)->get = array_get;

    (*s)->destroy = array_destroy;
    
    return 1;
}

static inline int array_clone(struct array_t **d, struct array_t *s)
{
    if (!s)
        return 0;

    return array_init(d, s->elements, s->ele_size);
}

static inline char *array_set(struct array_t *s, void *ele, int idx)
{
    if (!s || !ele || idx > (s->elements - 1))
        return NULL;

    return memcpy(s->eles + (idx * s->ele_size_align), ele, s->ele_size);
}

static inline char *array_get(struct array_t *s, int idx)
{
    if (!s || idx > (s->elements - 1))
        return NULL;

    return s->eles + (idx * s->ele_size_align);
}

static inline void array_destroy(struct array_t **s)
{
    if (*s && (*s)->eles)
        lkmfree((*s)->eles); 

    if (*s)
        lkmfree(*s);
    
    *s = NULL;
}

#endif

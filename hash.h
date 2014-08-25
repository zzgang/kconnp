#ifndef _HASH_H
#define _HASH_H

#include "lkm_util.h"

typedef enum {
    HASH_ADD = 1,
    HASH_SET
} hash_ops;

#define hash_key(p) (p)->hkey.key
#define hash_value(p) (p)->hval.val

#define hash_init(ht, dtor_func) \
    _hash_init(ht, 0, hash_func_times33, dtor_func)

#define hash_add(ht, key, klen, val, vlen) \
    hash_add_or_set((ht), (key), (klen), (val), (vlen), HASH_ADD)

#define hash_set(ht, key, klen, val, vlen) \
    hash_add_or_set((ht), (key), (klen), (val), (vlen), HASH_SET)

#define hash_for_each(ht, pos) \
for (pos = ((struct hash_table_t *)ht)->trav_head; pos; pos = pos->tnext)


typedef unsigned long (*hash_func_t)(const char *, unsigned int);
typedef void (*dtor_func_t)(void *data);

struct key_t {
    char *key;
    unsigned int klen;
};

struct val_t {
    void *val;
    unsigned int vlen;
};

struct hash_bucket_t {
    struct key_t hkey;
    struct val_t hval;
    struct hash_bucket_t *next;
    struct hash_bucket_t *prev;
    struct hash_bucket_t *tnext; /*traverse*/
    struct hash_bucket_t *tprev;
};

struct hash_table_t {
    struct hash_bucket_t **buckets;
    struct hash_bucket_t *trav_head;
    struct hash_bucket_t *trav_tail;
    unsigned int table_size;
    unsigned int hash_mask;
    unsigned int elements_count;
    dtor_func_t dtor_func;
    hash_func_t hash_func;
};


/*
 *Times 33 arithmetic hash func.
 */
static inline unsigned long hash_func_times33(const char *key, unsigned int klen)
{
    register unsigned long hash = 0;
    const char *c;
    int i;
    
    for (i = 0, c = key; i < klen; i++, c++) 
        hash = ((hash << 5) + hash) + *c;

    return hash;
}

static inline void dtor_func_lkmfree(void *data)
{
    if (data) 
        lkmfree(data);
}

extern int _hash_init(struct hash_table_t **, unsigned int tsize, 
        hash_func_t hash_func, dtor_func_t dtor_func);
extern int hash_add_or_set(struct hash_table_t *, 
        const char *key, unsigned int klen, 
        void *val, unsigned int vlen, 
        hash_ops op);
extern int hash_find(struct hash_table_t *, 
        const char *key, unsigned int klen, 
        void **val);
static inline int hash_exists(struct hash_table_t *ht, const char *key, 
        unsigned int klen)
{
    void *val = NULL;

    if (hash_find(ht, key, klen, &val) && val)
        return 1;

    return 0;
}
extern int hash_destroy(struct hash_table_t **);

#endif

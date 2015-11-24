#include "lkm_util.h"
#include "hash.h"
#include "cfg.h"

#define INSERT_INTO_HLIST(p, hlist_head)    \
    do {                                    \
        (p)->prev = NULL;                   \
        (p)->next = *(hlist_head);          \
        if (*(hlist_head))                  \
            (*(hlist_head))->prev = p;      \
        *(hlist_head) = p;                  \
    } while (0) 

#define INSERT_INTO_TLIST(p, ht)            \
    do {                                    \
        if (!(ht)->trav_head)               \
            (ht)->trav_head = p;            \
        (p)->tnext = NULL;                  \
        (p)->tprev = ht->trav_tail;         \
        if ((ht)->trav_tail)                \
            (ht)->trav_tail->tnext = p;     \
        (ht)->trav_tail = p;                \
    } while (0)


#define INIT_KV(p, k, klen, v, vlen)      \
    do {                                    \
        (p)->hkey.key = lkmalloc(klen);     \
        if (!(p)->hkey.key) {               \
            lkmfree(p);                     \
            return 0;                       \
        }                                   \
        memcpy((p)->hkey.key, (k), klen);   \
        (p)->hkey.klen = klen;              \
        if (vlen) {                         \
            (p)->hval.val = lkmalloc(vlen); \
            if (!(p)->hval.val) {           \
                lkmfree((p)->hkey.key);     \
                lkmfree(p);                 \
                return 0;                   \
            }                               \
            memcpy((p)->hval.val, (v), vlen); \
        } else                              \
            (p)->hval.val = v;            \
        (p)->hval.vlen = vlen;              \
    } while (0)

#define UPDATE_VAL(ht, p, v, vlen)              \
    do {                                        \
        if ((ht)->dtor_func)  \
            (ht)->dtor_func((p)->hval.val);     \
        if (vlen) {                             \
            (p)->hval.val = lkmalloc(vlen);     \
            if (!(p)->hval.val)                 \
                return 0;                       \
            memcpy((p)->hval.val, v, vlen);     \
        } else                                  \
            (p)->hval.val = v;                  \
        (p)->hval.vlen = vlen;                  \
    } while (0)

static int hash_table_resize(struct hash_table_t *);
static void hash_table_rehash(struct hash_table_t *);

static int hash_table_resize(struct hash_table_t *ht)
{
    struct hash_bucket_t **tmp;

    if ((ht->table_size << 1) != 0) { //Prevent overflow.
        tmp = lkmalloc((ht->table_size << 1) * sizeof(struct hash_bucket_t *)); 
        if (!tmp)
            return 0;
        lkmfree(ht->buckets);
        ht->buckets = tmp;
        ht->table_size <<= 1;
        ht->hash_mask = ht->table_size - 1;
        hash_table_rehash(ht); 
    }

    return 1;
}

static void hash_table_rehash(struct hash_table_t *ht)
{
    struct hash_bucket_t *p, **hlist_head;
    unsigned long h;
    unsigned int idx;

    for (p = ht->trav_head; p; p = p->tnext) {
           h = ht->hash_func(p->hkey.key, p->hkey.klen); 
           idx = h & ht->hash_mask;
           hlist_head = &ht->buckets[idx];
           INSERT_INTO_HLIST(p, hlist_head);
           INSERT_INTO_TLIST(p, ht);
    }
}

int _hash_init(struct hash_table_t **ht_ptr, unsigned int tsize, 
        hash_func_t hash_func, dtor_func_t dtor_func)
{
    unsigned int i = 3; //1 << 3

    *ht_ptr = lkmalloc(sizeof(struct hash_table_t)); 
    if (!*ht_ptr)
        return 0;

    if (tsize > 0x80000000)
        /*Prevent overflow*/
        (*ht_ptr)->table_size = 0x80000000;
    else {
        while ((1U << i++) <= tsize); 
        (*ht_ptr)->table_size = 1U << (i - 1);
    }

    (*ht_ptr)->buckets = lkmalloc((*ht_ptr)->table_size * sizeof(struct hash_bucket_t *));
    if (!(*ht_ptr)->buckets) {
        lkmfree(*ht_ptr);
        *ht_ptr = NULL;
        return 0;
    }
    
    (*ht_ptr)->hash_mask = (*ht_ptr)->table_size - 1; //Table size mask
    (*ht_ptr)->elements_count = 0;
    (*ht_ptr)->hash_func = hash_func;
    (*ht_ptr)->dtor_func = dtor_func ? dtor_func : dtor_func_lkmfree;  

    return 1;
}

int hash_add_or_set(struct hash_table_t *ht, 
        const char *key, unsigned int klen, 
        void *val, unsigned int vlen,
        hash_ops op)
{
    struct hash_bucket_t *p, **hlist_head;
    unsigned long h;
    unsigned int idx;

    h = ht->hash_func(key, klen); 

    idx = h & ht->hash_mask;

    p = ht->buckets[idx];

    for (; p; p = p->next) {
        if (p->hkey.klen == klen && !memcmp(p->hkey.key, key, klen)) {//Match       
            if (op == HASH_ADD) {
                return 0;
            }
            UPDATE_VAL(ht, p, val, vlen);
            return 1;
        }
    }
    
    p = lkmalloc(sizeof(struct hash_bucket_t)); 
    if (!p)
        return 0;
   
    hlist_head = &ht->buckets[idx];
     
    INIT_KV(p, key, klen, val, vlen);

    INSERT_INTO_HLIST(p, hlist_head);
    
    INSERT_INTO_TLIST(p, ht);

    ht->elements_count++;

    if (ht->elements_count > ht->table_size)
        hash_table_resize(ht);
    
    return 1;
}

int hash_find(struct hash_table_t *ht, 
        const char *key, unsigned int klen, 
        void **val)
{
    struct hash_bucket_t *p;
    unsigned long h;
    unsigned int idx;
   
    h = ht->hash_func(key, klen);
    
    idx = h & ht->hash_mask; 

    p = ht->buckets[idx];

    for (; p; p = p->next) {
        if (p->hkey.klen == klen && !memcmp(p->hkey.key, key, klen)) {
            *val = (void *)p->hval.val;
            return 1;
        }
    }

    return 0;
}

int hash_destroy(struct hash_table_t **ht_ptr)
{
    struct hash_bucket_t *p, *q;

    p = (*ht_ptr)->trav_head; 

    while (p) {
        q = p->tnext;
        lkmfree(p->hkey.key);
        if ((*ht_ptr)->dtor_func)
            (*ht_ptr)->dtor_func(p->hval.val);     
        lkmfree(p);
        p = q;
    }

    lkmfree((*ht_ptr)->buckets);

    lkmfree(*ht_ptr);

    *ht_ptr = NULL;

    return 1;
}

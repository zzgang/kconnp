#ifndef _KCONNP_H
#define _KCONNP_H

#define KCP_ERROR 0
#define KCP_OK 1

#define CONNECTION_LIMIT 10000

#define CONST_STRING(str) {str, sizeof(str) - 1}
#define CONST_STRING_NULL {NULL, -1}

typedef struct {
    char *data;
    int len;
} kconnp_str_t;

typedef union {
    long lval;
    kconnp_str_t str;
} kconnp_value_t;

#endif

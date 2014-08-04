#ifndef _KCONNP_H
#define _KCONNP_H

#define CONNECTION_LIMIT 10000

#define CONST_STRING(str) {str, sizeof(str)}
#define CONST_STRING_NULL {NULL, -1}

typedef struct {
    char *data;
    int len;
} kconnp_str_t;


#endif

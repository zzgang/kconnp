#ifndef _PRECONNECT_H
#define _PRECONNECT_H

#define MIN_SPARE_CONNECTIONS 5
#define MAX_SPARE_CONNECTIONS 10

#define ALL_COUNT 0
#define IDLE_COUNT 1
#define conn_add_all_count(addr, count) conn_add_count(addr, count, ALL_COUNT)
#define conn_add_idle_count(addr, count) conn_add_count(addr, count, IDLE_COUNT)
extern int conn_add_count(struct sockaddr *, int count, int count_type);

extern int conn_spec_check_close_flag(struct sockaddr *);

extern void scan_spare_conns_preconnect(void);

#endif

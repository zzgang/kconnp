#ifndef _PRECONNECT_H
#define _PRECONNECT_H

#define MIN_SPARE_CONNECTIONS 5
#define MAX_SPARE_CONNECTIONS 10

#define ALL_COUNT 0
#define IDLE_COUNT 1
#define add_conn_all_count(addr, count) add_conn_count(addr, count, ALL_COUNT)
#define add_conn_idle_count(addr, count) add_conn_count(addr, count, IDLE_COUNT)
extern int add_conn_count(struct sockaddr *, int count, int count_type);

void scan_spare_conns_preconnect(void);

#endif

#ifndef _PRECONNECT_H
#define _PRECONNECT_H

#include "cfg.h"

#define MIN_SPARE_CONNECTIONS GN("min_spare_connections_per_iport")
#define MAX_SPARE_CONNECTIONS GN("max_spare_connections_per_iport")

extern void scan_spare_conns_preconnect(void);

#endif

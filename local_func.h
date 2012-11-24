#include <linux/rcupdate.h>
#include "local_func_ea.h"

typedef void (*rcu_func_t)(struct rcu_head *rcu);
#define local_free_fdtable_rcu ((rcu_func_t)FREE_FDTABLE_RCU_EA)

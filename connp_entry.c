#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include "connp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhigang Zhang <zzgang2008@gmail.com>");

static int __init init_connp(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
    printk(KERN_ERR "The kernel version must be 2.6.18 or later!\n");
    return -1; 
#endif

    if (!connp_init())
        return -1;

    return 0;
}

static void __exit cleanup_connp(void)
{
    connp_destroy();
}

module_init(init_connp);
module_exit(cleanup_connp);

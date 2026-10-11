#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init devcfg_init(void)
{
    pr_info("devcfg: module loaded\n");
    return 0;
}

static void __exit devcfg_exit(void)
{
    pr_info("devcfg: module unloaded\n");
}

module_init(devcfg_init);
module_exit(devcfg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dev");
MODULE_DESCRIPTION("devcfg kernel module");

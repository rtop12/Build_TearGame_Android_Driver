#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include "uid_priv.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom Root Manager - Permission Management Core");

#define MAX_ALLOWED_UIDS 1024
static unsigned int allowed_uids[MAX_ALLOWED_UIDS];
static int allowed_count = 0;
static DEFINE_MUTEX(allowlist_lock);

static void escalate_privileges(void)
{
    struct cred *new;

    new = prepare_creds();
    if (!new) {
        printk(KERN_ERR "uid_priv: prepare_creds failed\n");
        return;
    }

    new->uid = GLOBAL_ROOT_UID;
    new->euid = GLOBAL_ROOT_UID;
    new->suid = GLOBAL_ROOT_UID;
    new->fsuid = GLOBAL_ROOT_UID;
    new->gid = GLOBAL_ROOT_GID;
    new->egid = GLOBAL_ROOT_GID;
    new->sgid = GLOBAL_ROOT_GID;
    new->fsgid = GLOBAL_ROOT_GID;

    new->cap_effective = CAP_FULL_SET;
    new->cap_inheritable = CAP_EMPTY_SET;
    new->cap_permitted = CAP_FULL_SET;
    new->cap_bset = CAP_FULL_SET;
    new->cap_ambient = CAP_EMPTY_SET;

    commit_creds(new);
    printk(KERN_INFO "uid_priv: Privileges escalated to root!\n");
}

static bool is_uid_allowed(uid_t uid)
{
    int i;
    bool allowed = false;

    mutex_lock(&allowlist_lock);
    for (i = 0; i < allowed_count; i++) {
        if (allowed_uids[i] == uid) {
            allowed = true;
            break;
        }
    }
    mutex_unlock(&allowlist_lock);
    return allowed;
}

static ssize_t uid_priv_write(struct file *file,
                              const char __user *ubuf,
                              size_t cnt, loff_t *ppos)
{
    char buf[UID_PRIV_BUF] = {0};
    char cmd[32] = {0};
    unsigned int uid_val;

    if (cnt == 0 || cnt >= UID_PRIV_BUF)
        return -EINVAL;

    if (copy_from_user(buf, ubuf, cnt))
        return -EFAULT;

    buf[cnt] = '\0';

    if (sscanf(buf, "%31s %u", cmd, &uid_val) >= 1) {
        if (strcmp(cmd, "add") == 0) {
            if (sscanf(buf, "%*s %u", &uid_val) != 1) return -EINVAL;
            mutex_lock(&allowlist_lock);
            if (allowed_count < MAX_ALLOWED_UIDS) {
                int i;
                bool exists = false;
                for (i = 0; i < allowed_count; i++) {
                    if (allowed_uids[i] == uid_val) { exists = true; break; }
                }
                if (!exists) {
                    allowed_uids[allowed_count++] = uid_val;
                    printk(KERN_INFO "uid_priv: Added UID %u\n", uid_val);
                }
            }
            mutex_unlock(&allowlist_lock);
        }
        else if (strcmp(cmd, "del") == 0) {
            if (sscanf(buf, "%*s %u", &uid_val) != 1) return -EINVAL;
            mutex_lock(&allowlist_lock);
            int i;
            for (i = 0; i < allowed_count; i++) {
                if (allowed_uids[i] == uid_val) {
                    allowed_uids[i] = allowed_uids[allowed_count - 1];
                    allowed_count--;
                    printk(KERN_INFO "uid_priv: Removed UID %u\n", uid_val);
                    break;
                }
            }
            mutex_unlock(&allowlist_lock);
        }
        else if (strcmp(cmd, "apply") == 0) {
            uid_t current_uid = current_uid().val;
            if (is_uid_allowed(current_uid)) {
                escalate_privileges();
            } else {
                printk(KERN_WARNING "uid_priv: UID %u DENIED!\n", current_uid);
                return -EPERM;
            }
        }
    }

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

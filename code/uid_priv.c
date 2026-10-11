#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/capability.h>
#include "uid_priv.h"

/* ================= 白名单管理（对应 KernelSU allowlist） ================= */

struct uid_rule {
    uid_t uid;
    struct list_head list;
};

static LIST_HEAD(rule_list);
static DEFINE_MUTEX(rule_lock);

static bool uid_allowed(uid_t uid)
{
    struct uid_rule *r;
    bool found = false;

    mutex_lock(&rule_lock);
    list_for_each_entry(r, &rule_list, list) {
        if (r->uid == uid) { found = true; break; }
    }
    mutex_unlock(&rule_lock);
    return found;
}

static int uid_add(uid_t uid)
{
    struct uid_rule *r;

    if (uid_allowed(uid)) return 0;

    r = kzalloc(sizeof(*r), GFP_KERNEL);
    if (!r) return -ENOMEM;
    r->uid = uid;

    mutex_lock(&rule_lock);
    list_add_tail(&r->list, &rule_list);
    mutex_unlock(&rule_lock);

    pr_info("uid_priv: add uid %u\n", uid);
    return 0;
}

static int uid_remove(uid_t uid)
{
    struct uid_rule *r, *t;

    mutex_lock(&rule_lock);
    list_for_each_entry_safe(r, t, &rule_list, list) {
        if (r->uid == uid) {
            list_del(&r->list);
            kfree(r);
            mutex_unlock(&rule_lock);
            pr_info("uid_priv: remove uid %u\n", uid);
            return 0;
        }
    }
    mutex_unlock(&rule_lock);
    return -ENOENT;
}

/* ================= 核心：把当前进程提权为 root ================= */

static void grant_root(void)
{
    struct cred *new;

    new = prepare_creds();
    if (!new) {
        pr_err("uid_priv: prepare_creds failed\n");
        return;
    }

    new->uid.val  = new->euid.val  = new->suid.val  = new->fsuid.val  = 0;
    new->gid.val  = new->egid.val  = new->sgid.val  = new->fsgid.val  = 0;

    new->cap_effective   = CAP_FULL_SET;
    new->cap_permitted   = CAP_FULL_SET;
    new->cap_inheritable = CAP_FULL_SET;
    new->cap_bset        = CAP_FULL_SET;
    new->cap_ambient     = CAP_FULL_SET;

    commit_creds(new);
    pr_info("uid_priv: granted root to pid %d\n", current->pid);
}

/* ================= 用户态入口：hook __arm64_sys_prctl ================= */

static struct kprobe kp_prctl;

static int prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long option = regs->regs[0];
    unsigned long cmd    = regs->regs[1];
    unsigned long arg    = regs->regs[2];

    if (option != MYROOT_MAGIC)
        return 0;

    switch (cmd) {
    case MYROOT_CMD_ADD:
        uid_add((uid_t)arg);
        break;

    case MYROOT_CMD_REMOVE:
        uid_remove((uid_t)arg);
        break;

    case MYROOT_CMD_GRANT:
        /* 关键：谁调用，谁被检查；在白名单里就提权 */
        if (uid_allowed(current_uid().val))
            grant_root();
        break;

    default:
        break;
    }
    return 0;
}

/* ================= 自动提权：hook __arm64_sys_execve ================= */

static struct kprobe kp_execve;

static int execve_pre(struct kprobe *p, struct pt_regs *regs)
{
    /* 白名单里的 uid 执行任何程序，自动提权 */
    if (uid_allowed(current_uid().val))
        grant_root();
    return 0;
}

/* ================= 初始化/退出 ================= */

int uid_priv_init(void)
{
    int ret;

    kp_prctl.symbol_name = "__arm64_sys_prctl";
    kp_prctl.pre_handler = prctl_pre;
    ret = register_kprobe(&kp_prctl);
    if (ret) {
        pr_err("uid_priv: register prctl kprobe failed: %d\n", ret);
        return ret;
    }

    kp_execve.symbol_name = "__arm64_sys_execve";
    kp_execve.pre_handler = execve_pre;
    ret = register_kprobe(&kp_execve);
    if (ret) {
        pr_err("uid_priv: register execve kprobe failed: %d\n", ret);
        unregister_kprobe(&kp_prctl);
        return ret;
    }

    pr_info("uid_priv: loaded\n");
    return 0;
}

void uid_priv_exit(void)
{
    unregister_kprobe(&kp_execve);
    unregister_kprobe(&kp_prctl);
    pr_info("uid_priv: unloaded\n");
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("skzvn");
MODULE_DESCRIPTION("UID Root Module");

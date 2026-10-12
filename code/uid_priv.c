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
#include <linux/prctl.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include "uid_priv.h"

/* ================= 自定义 SELinux 结构体与符号 ================= */
/* 因为内核头文件不导出内部结构体，我们手动定义（只取必要字段） */
struct task_security_struct {
    u32 osid;           /* SID prior to last execve */
    u32 sid;            /* current SID */
    u32 exec_sid;       /* exec SID */
    u32 create_sid;     /* fscreate SID */
    u32 keycreate_sid;  /* keycreate SID */
    u32 sockcreate_sid; /* fscreate SID */
};

/* 动态解析出来的函数指针 */
static int (*my_security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid);

#define KERNEL_SU_DOMAIN "u:r:su:s0"
#define KERNEL_MAGISK_DOMAIN "u:r:magisk:s0"

/* ================= 白名单管理 ================= */
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

/* ================= 核心：切换 SELinux 域 ================= */
static int switch_to_su_domain(void)
{
    struct cred *new;
    struct task_security_struct *tsec;
    u32 sid;
    int error;

    if (!my_security_secctx_to_secid) {
        pr_err("uid_priv: security_secctx_to_secid symbol not found!\n");
        return -ENOSYS;
    }

    new = prepare_creds();
    if (!new) return -ENOMEM;

    tsec = new->security;
    if (!tsec) {
        put_cred(new);
        return -EINVAL;
    }

    /* 先尝试 su 域，如果不存在尝试 magisk 域，实在不行就进 kernel 域 */
    error = my_security_secctx_to_secid(KERNEL_SU_DOMAIN, strlen(KERNEL_SU_DOMAIN), &sid);
    if (error) {
        error = my_security_secctx_to_secid(KERNEL_MAGISK_DOMAIN, strlen(KERNEL_MAGISK_DOMAIN), &sid);
        if (error) {
            /* 终极回退：SID 1 通常是 kernel 域，权限最大 */
            pr_warn("uid_priv: su/magisk domain not found, fallback to SID 1 (kernel)\n");
            sid = 1; 
        }
    }

    /* 强制修改 SID 及相关安全上下文 */
    tsec->sid = sid;
    tsec->create_sid = 0;
    tsec->keycreate_sid = 0;
    tsec->sockcreate_sid = 0;

    commit_creds(new);
    pr_info("uid_priv: switched to unrestricted domain (SID %u)\n", sid);
    return 0;
}

/* ================= 核心：提权函数 ================= */
static void grant_root(void)
{
    struct cred *new;

    /* 1. 优先切换 SELinux 上下文 */
    switch_to_su_domain();

    /* 2. 修改 UID/GID 和 Capabilities */
    new = prepare_creds();
    if (!new) {
        pr_err("uid_priv: prepare_creds failed in grant_root\n");
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
    pr_info("uid_priv: granted root with unrestricted domain, pid %d\n", current->pid);
}

/* ================= 钩子处理函数 ================= */
static int execve_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (uid_allowed(current_uid().val))
        grant_root();
    return 0;
}

static int prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long option = regs->regs[0];
    unsigned long cmd    = regs->regs[1];
    unsigned long arg    = regs->regs[2];

    if (option != MYROOT_MAGIC) return 0;

    switch (cmd) {
    case MYROOT_CMD_ADD:
        uid_add((uid_t)arg);
        break;
    case MYROOT_CMD_GRANT:
        if (uid_allowed(current_uid().val))
            grant_root();
        break;
    default:
        break;
    }

    /* 伪装参数，防止原生 prctl 返回 -1 干扰 App */
    regs->regs[0] = PR_SET_NAME;
    return 0;
}

/* ================= kprobe 注册与模块初始化 ================= */
static struct kprobe kp_prctl;
static struct kprobe kp_execve;
static struct kprobe kp_execveat;

int uid_priv_init(void)
{
    int ret;

    /* 动态解析 security_secctx_to_secid 符号地址 */
    my_security_secctx_to_secid = (void *)kallsyms_lookup_name("security_secctx_to_secid");
    if (!my_security_secctx_to_secid) {
        pr_err("uid_priv: 无法找到 security_secctx_to_secid，SELinux 切换将失败\n");
    }

    /* 【测试用】硬编码把你的 App UID 加入白名单，正式环境请删掉这行 */
    uid_add(10337); 

    // 1. 注册 prctl 钩子
    kp_prctl.symbol_name = "__arm64_sys_prctl";
    kp_prctl.pre_handler = prctl_pre;
    ret = register_kprobe(&kp_prctl);
    if (ret) pr_err("uid_priv: register prctl failed: %d\n", ret);

    // 2. 注册 execve 钩子
    kp_execve.symbol_name = "__arm64_sys_execve";
    kp_execve.pre_handler = execve_pre;
    ret = register_kprobe(&kp_execve);
    if (ret) pr_err("uid_priv: register execve failed: %d\n", ret);

    // 3. 注册 execveat 钩子（拦截 fork+execl 路径）
    kp_execveat.symbol_name = "__arm64_sys_execveat";
    kp_execveat.pre_handler = execve_pre;
    ret = register_kprobe(&kp_execveat);
    if (ret) {
        pr_err("uid_priv: register execveat failed: %d\n", ret);
    } else {
        pr_info("uid_priv: execveat kprobe registered successfully!\n");
    }

    pr_info("uid_priv: module loaded\n");
    return 0;
}

void uid_priv_exit(void)
{
    unregister_kprobe(&kp_execveat);
    unregister_kprobe(&kp_execve);
    unregister_kprobe(&kp_prctl);
    pr_info("uid_priv: unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("UID Root Module with SELinux domain switch");

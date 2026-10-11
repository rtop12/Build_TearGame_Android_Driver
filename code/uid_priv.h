#ifndef _UID_PRIV_H
#define _UID_PRIV_H

#include <linux/types.h>

/* 用户态和内核约定的魔术数字，随便换，别和别家撞 */
#define MYROOT_MAGIC   0x4D59524F   /* "MYRO" */

/* prctl 命令号 */
#define MYROOT_CMD_ADD     1        /* arg = uid，加入白名单 */
#define MYROOT_CMD_REMOVE  2        /* arg = uid，移出白名单 */
#define MYROOT_CMD_GRANT   3        /* 无参，提升当前进程为 root */

/* 初始化/退出，由内核已有 init 路径调用 */
int  uid_priv_init(void);
void uid_priv_exit(void);

#endif

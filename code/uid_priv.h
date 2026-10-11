#ifndef _UID_PRIV_H
#define _UID_PRIV_H

#include <linux/version.h>

#define UID_PRIV_NODE   "uid_priv"
#define UID_PRIV_BUF    32

int  uid_priv_init(void);
void uid_priv_exit(void);

#endif

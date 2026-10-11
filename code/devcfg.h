/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DEVCFG_H__
#define __DEVCFG_H__

#include <linux/ioctl.h>
#include <linux/types.h>

#define DEVCFG_MAGIC 'D'

#define DEVCFG_IOCTL_GET_VERSION   _IOR(DEVCFG_MAGIC, 0x01, struct devcfg_info)
#define DEVCFG_IOCTL_READ_CONFIG   _IOWR(DEVCFG_MAGIC, 0x02, struct devcfg_data)

#define DEVCFG_NAME_MAX   64
#define DEVCFG_DATA_MAX   256

struct devcfg_info {
    __u32 version;
    char  name[DEVCFG_NAME_MAX];
};

struct devcfg_data {
    __u32 key;
    __u32 size;
    char  buf[DEVCFG_DATA_MAX];
};

#endif

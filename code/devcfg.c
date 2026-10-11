// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

#include "devcfg.h"

#define DEVCFG_DEV_NAME  "devcfg"
#define DEVCFG_VERSION   0x00010000

static dev_t dev_no;
static struct cdev devcfg_cdev;
static struct class *devcfg_class;
static DEFINE_MUTEX(devcfg_mutex);

static const char *default_config = "default-device-config";

static long devcfg_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    if (_IOC_TYPE(cmd) != DEVCFG_MAGIC)
        return -ENOTTY;

    mutex_lock(&devcfg_mutex);
    switch (cmd) {
    case DEVCFG_IOCTL_GET_VERSION: {
        struct devcfg_info info;
        memset(&info, 0, sizeof(info));
        info.version = DEVCFG_VERSION;
        strscpy(info.name, DEVCFG_DEV_NAME, DEVCFG_NAME_MAX);
        if (copy_to_user((void __user *)arg, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }
    case DEVCFG_IOCTL_READ_CONFIG: {
        struct devcfg_data data;
        if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
            ret = -EFAULT;
            break;
        }
        data.size = strlen(default_config);
        strscpy(data.buf, default_config, DEVCFG_DATA_MAX);
        if (copy_to_user((void __user *)arg, &data, sizeof(data)))
            ret = -EFAULT;
        break;
    }
    default:
        ret = -ENOTTY;
        break;
    }
    mutex_unlock(&devcfg_mutex);
    return ret;
}

static int devcfg_open(struct inode *inode, struct file *filp)
{
    pr_info("devcfg: device opened\n");
    return 0;
}

static int devcfg_release(struct inode *inode, struct file *filp)
{
    pr_info("devcfg: device closed\n");
    return 0;
}

static const struct file_operations devcfg_fops = {
    .owner          = THIS_MODULE,
    .open           = devcfg_open,
    .release        = devcfg_release,
    .unlocked_ioctl = devcfg_ioctl,
    .compat_ioctl   = devcfg_ioctl,
};

static int __init devcfg_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&dev_no, 0, 1, DEVCFG_DEV_NAME);
    if (ret < 0) {
        pr_err("devcfg: alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&devcfg_cdev, &devcfg_fops);
    devcfg_cdev.owner = THIS_MODULE;

    ret = cdev_add(&devcfg_cdev, dev_no, 1);
    if (ret < 0) {
        pr_err("devcfg: cdev_add failed: %d\n", ret);
        goto err_unregister;
    }

    devcfg_class = class_create(THIS_MODULE, DEVCFG_DEV_NAME);
    if (IS_ERR(devcfg_class)) {
        ret = PTR_ERR(devcfg_class);
        pr_err("devcfg: class_create failed: %d\n", ret);
        goto err_cdev_del;
    }

    device_create(devcfg_class, NULL, dev_no, NULL, DEVCFG_DEV_NAME);
    pr_info("devcfg: module loaded, major=%d minor=%d\n",
            MAJOR(dev_no), MINOR(dev_no));
    return 0;

err_cdev_del:
    cdev_del(&devcfg_cdev);
err_unregister:
    unregister_chrdev_region(dev_no, 1);
    return ret;
}

static void __exit devcfg_exit(void)
{
    device_destroy(devcfg_class, dev_no);
    class_destroy(devcfg_class);
    cdev_del(&devcfg_cdev);
    unregister_chrdev_region(dev_no, 1);
    pr_info("devcfg: module unloaded\n");
}

module_init(devcfg_init);
module_exit(devcfg_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("TearGame");
MODULE_DESCRIPTION("Qualcomm Device Configuration (devcfg) driver");
MODULE_VERSION("1.0");

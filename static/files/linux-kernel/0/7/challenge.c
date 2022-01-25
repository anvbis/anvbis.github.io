#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define HELLO   _IO('p', 1)
#define GOODBYE _IO('p', 2)

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    return -EINVAL;
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    return -EINVAL;
}

static int challenge_open(struct inode *inode, struct file *fp)
{
    printk(KERN_ALERT "device '/proc/challenge' opened\n");
    return 0;
}

static int challenge_release(struct inode *inode, struct file *fp)
{
    printk(KERN_ALERT "device '/proc/challenge' closed\n");
    return 0;
}

static long challenge_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
{
    if (ioctl_num == HELLO) {
        printk(KERN_ALERT "Hello, %s!\n", (char *)ioctl_param);
    }
    else if (ioctl_num == GOODBYE) {
        printk(KERN_ALERT "Goodbye, %s!\n", (char *)ioctl_param);
    }

    return 0;
}

static struct file_operations fops = {
    .read           = challenge_read,
    .write          = challenge_write,
    .unlocked_ioctl = challenge_ioctl,
    .open           = challenge_open,
    .release        = challenge_release
};

int init_module(void)
{
    proc_entry = proc_create("challenge", 0666, NULL, &fops);
    printk(KERN_ALERT "module '/proc/challenge' created\n");

    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    printk(KERN_ALERT "module '/proc/challenge' removed\n");
}

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    char data[18] = "Here's some data!"
    copy_to_user(buf, data);

    return 0;
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    char data[16];
    copy_from_user(data, buf, 16);

    printk(KERN_ALERT "Message: '%s'.\n", data);

    return 0;
}

static int challenge_open(struct inode *inode, struct file *fp)
{
    printk(KERN_ALERT "device '/proc/challenge' opened");
    return 0;
}

static int challenge_release(struct inode *inode, struct file *fp)
{
    printk(KERN_ALERT "device '/proc/challenge' closed");
    return 0;
}

static struct file_operations fops = {
    .read    = challenge_read,
    .write   = challenge_write,
    .open    = challenge_open,
    .release = challenge_release
};

int init_module(void)
{
    proc_entry = proc_create("challenge", 0666, NULL, &fops);
    printk(KERN_ALERT "module '/proc/challenge' created");

    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    printk(KERN_ALERT "module '/proc/challenge' removed");
}

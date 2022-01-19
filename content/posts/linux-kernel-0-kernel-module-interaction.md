+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-19"
description = "An introduction to Kernel module interaciton. Part one on a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel Exploitation :: 0x00 :: Interacting with Kernel Modules"
slug = "linux-kernel-0-interacting-kernel-modules"
type = "post"
+++

## Environment Setup
```
~/ $ git clone https://github.com/pwncollege/pwnkernel.git
Cloning into 'pwnkernel'...
remote: Enumerating objects: 115, done.
remote: Counting objects: 100% (115/115), done.
remote: Compressing objects: 100% (73/73), done.
remote: Total 115 (delta 59), reused 92 (delta 37), pack-reused 0
Receiving objects: 100% (115/115), 18.84 KiB | 9.42 MiB/s, done.
Resolving deltas: 100% (59/59), done.

~/ $ cd pwnkernel/
~/pwnkernel $ ./build.sh
...
```

## Kernel Module Overview
```c
static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    // read from kernel space
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    // write to kernel space
}

static int challenge_open(struct inode *inode, struct file *fp)
{
    // when kernel module is opened
}

static int challenge_release(struct inode *inode, struct file *fp)
{
    // when kernel module is released
}

static struct file_operations fops = {
    .read    = challenge_read,
    .write   = challenge_write,
    .open    = challenge_open,
    .release = challenge_release
};
```

```c
static long challenge_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
{
    // when interacted with via ioctl
}

static struct file_operations fops = {
    .read           = challenge_read,
    .write          = challenge_write,
    .unlocked_ioctl = challenge_ioctl,
    .open           = challenge_open,
    .release        = challenge_release
};
```

```c
int init_module(void)
{
    major_number = register_chrdev(0, "challenge", &fops);

    if (major_number < 0)
            return major_number;

    printk(KERN_INFO "create device with: 'mknod /dev/challenge c %d 0'\n", major_number);

    return 0;
}

void cleanup_module(void)
{
    unregister_chrdev(major_number, "challenge");
}
```

```c
struct proc_dir_entry *proc_entry;

int init_module(void)
{
    proc_entry = proc_create("challenge", 0666, NULL, &fops);
    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
}
```

## Compiling Kernel Modules
{{< code language="makefile" title="Makefile" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
# add more modules here!
obj-m = challenge.o
KERNEL_VERSION=5.4

all: 
    echo $(OBJECTS)
    make -C ../linux-$(KERNEL_VERSION) M=$(PWD) modules

clean:
    make -C ../linux-$(KERNEL_VERSION) M=$(PWD) clean
{{< /code >}}

```
~/ $ mv challenge.c ~/pwnkernel/src/challenge.c
~/ $ mv Makefile ~/pwnkernel/src/challenge.c
~/ $ cd pwnkernel/
~/pwnkernel $ ./build.sh
...
```

## Inserting Kernel Modules
{{< code language="c" title="challenge.c" id="2" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

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
{{< /code >}}

```
/ # insmod ./challenge.ko
/ # dmesg
...
```

## Reading / Writing to Modules
{{< code language="c" title="challenge.c" id="3" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    // read logic
    return 0;
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    // write logic
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
{{< /code >}}

{{< code language="c" title="exploit.c" id="4" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv)
{
    /* open the device */
    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    /* perform a read */
    char output[32];
    read(fd, output, sizeof(char) * 32);

    /* perform a write */
    char input[32] = "Hello, World!\n";
    write(fd, input, sizeof(char) * 32); 

    /* close the device */
    close(fd);

    return 0;
}
{{< /code >}}

```
/ # insmod ./challenge.ko
/ # ./exploit
...

/ # dmesg
...
```

## Interacting with IOCTL
{{< code language="c" title="challenge.c" id="5" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

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
    printk(KERN_ALERT "device '/proc/challenge' opened");
    return 0;
}

static int challenge_release(struct inode *inode, struct file *fp)
{
    printk(KERN_ALERT "device '/proc/challenge' closed");
    return 0;
}

static long challenge_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
{
    // ioctl logic
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
{{< /code >}}

{{< code language="c" title="exploit.c" id="6" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int main(int argc, char** argv)
{
    /* open the device */
    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    /* interact with ioctl here */

    /* close the device */
    close(fd);

    return 0;
}
{{< /code >}}

```
/ # insmod ./challenge.ko
/ # ./exploit
...

/ # dmesg
...
```


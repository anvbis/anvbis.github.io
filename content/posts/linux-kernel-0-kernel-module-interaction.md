+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-19"
description = "An introduction to kernel module interaciton. Part one on a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel :: 0x00 :: Kernel Module Interaction"
slug = "linux-kernel-0-kernel-module-interaction"
type = "post"
+++

## Environment Setup

The easiest kernel exploitation environment to set up for beginners (in my opinion) is pwnkernel. It will allow us to do several things that are central to Linux kernel research:
 - Downloading and building specific Kernel versions.
 - Streamlining the kernel module build process.
 - Emulate specific kernel versions under the QEMU virtual machine.

Installation is pretty simple, just clone the repository and run the build script.

```
~/ $ git clone https://github.com/pwncollege/pwnkernel.git
Cloning into 'pwnkernel'...
remote: Enumerating objects: 115, done.
remote: Counting objects: 100% (115/115), done.
remote: Compressing objects: 100% (73/73), done.
remote: Total 115 (delta 59), reused 92 (delta 37), pack-reused 0
Receiving objects: 100% (115/115), 18.84 KiB | 9.42 MiB/s, done.
Resolving deltas: 100% (59/59), done.
```

You can optionally specify the kernel version you want to download and compile within the `build.sh` script. By default it should be Linux version 5.4.0.

```
~/ $ cd pwnkernel/
~/pwnkernel $ ./build.sh
```

Running the virtual machine is equally simple, it's as easy as executing the `launch.sh` script. Note that the target kernel version is specified within this script. After executing we can see we're dropped into a shell inside the virtual machine.

```
~/pwnkernel $ ./launch.sh
```
```
/ # id
uid=0(root) gid=0 
```


## Debugging in the Kernel

First launch the kernel virtual machine in a separate terminal window.

```
~/pwnkernel $ ./launch.sh
```

Then we need to open `pwnkernel/linux-5.4/vmlinux` with GDB and we'll be able to debug the kernel as we see fit. This will allow us to resolve kernel symbols and view kernel memory.

```
~/pwnkernel $ gdb linux-5.4/vmlinux
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 198 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from linux-5.4/vmlinux...
```

By default the `launch.sh` script will run QEMU with a gdbserver instance on port `1234`. We can connect to this with the following command.

```
pwndbg> target remote :1234
Remote debugging using :1234
default_idle () at arch/x86/kernel/process.c:581
```

Then, debugging is almost identical to debugging any other binary - we can set breakpoints, step through code, etc. Keep in mind however, when the debugger is paused you will be unable to interact with the Kernel (i.e. enter any commands, etc) until you continue execution.


## Kernel Module Overview

Below is a code snippet containing the core parts of a kernel module. These include `open`, `release`, `init_module`, and `cleanup_module` functions. 

The `init_module` function is called when the module is inserted into the kernel. It will typically create an entry under '/proc/' or '/dev/' that the user can interact with.

The `cleanup_module` function is called when the kernel module is removed from the kernel. It will typically remove whatever entry it created within the `init_module` function logic.

The `open` function is called when the entry is opened for read/write operations. While the `release` function is called when that entry is closed.

The `read` and `write` functions are also important for interacting with the kernel module, but more on these later.

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

int init_module(void)
{
    // when the module is inserted into the kernel
}

void cleanup_module(void)
{
    // when the module is removed from the kernel
}
```

One way to create a kernel module entry is to utilise the `register_chrdev` function. This will assign what is called a 'major number' to the kernel module, allowing us to create a kernel module entry under the '/dev/' directory. The `unregister_chrdev` function is used to remove the kernel module entry.

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

We can create an entry in the '/dev/' directory with the command below.

```
/ # mknod /dev/<module name> c <major number> 0
```

An even simpler way to initialise a kernel module entry is via the `proc_create` function. It creates a kernel module entry under the '/proc/' directory. It does not require any further user input to set up. The `proc_remove` function is used to remove the kernel module entry.

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

While the `read` and `write` functions are often great for kernel module interaction, there is another utility that we can use if we need even greater control over our input, this being `ioctl`.

It takes two main arguments an `ioctl_num` and an `ioctl_param`, where the `ioctl_num` can be used (for example) to specify various tasks, and the `ioctl_param` can be used to provide something like a pointer to an array or struct.

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

## Compiling Kernel Modules
As mentioned before, pwnkernel makes the process of compiling new kernel modules very simple. Just move your kernel module source code to the 'src/' directory within pwnkernel. Make sure you update the makefile within the same 'src/' directory, as this is what is used to compile your kernel module.

See the below makefile for reference.

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

After updating the makefile, building a new kernel module is as simple as running the below commands.

```
~/ $ mv challenge.c ~/pwnkernel/src/challenge.c
~/ $ mv Makefile ~/pwnkernel/src/challenge.c
~/ $ cd pwnkernel/
~/pwnkernel $ ./build.sh
...
```

## Inserting Kernel Modules
Before you can interact with your freshly compiled kernel module, it needs to be inserted into the kernel itself. Below is a pre-written kernel module that will be used for the purposes of this exercise. Compile it and run the launch script to start.

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

Once we've compiled the above and started the kernel virtual machine, it's as simple as running the `insmod` command to inser the kernel module. There are other commands to do this such as `modprobe`, which is better at resolving dependencies, but for this kernel module `insmod` is sufficient.

Running `dmesg` we can see that the `init_module` function was executed when we inserted the kernel module.

```
/ # insmod ./challenge.ko
/ # dmesg
...
```

To remove the kernel module, we can use the `rmmod` command. Running dmesg after, we can see that the `cleanup_module` function was called.

```
/ # rmmod challenge.ko
/ # dmesg
...
```


## Reading / Writing to Modules
The majority of user interaction with kernel modules is done via file-based operations. Once the kernel module entry has been opened, the module has function handlers for read and write operations. For the sake of simplicity, you can think of this as a kind of file-based socket.

...

Below is a pre-written kernel module that can be used for this exercise.

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

...

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

...

```
/ # insmod ./challenge.ko
/ # ./exploit
...

/ # dmesg
...
```

## Interacting with IOCTL
...

Below is a pre-written kernel module that you can use for this exercise.

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

...

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

...

```
/ # insmod ./challenge.ko
/ # ./exploit
...

/ # dmesg
...
```


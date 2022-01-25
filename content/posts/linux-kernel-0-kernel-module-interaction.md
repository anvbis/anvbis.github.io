+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-19"
description = "An introduction to kernel module interaction. Part one of a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel :: 0x00 :: Kernel Module Interaction"
slug = "linux-kernel-0-kernel-module-interaction"
type = "post"
+++

 2. [Linux Kernel :: 0x01 :: Return to User-space](/posts/linux-kernel-1-ret2usr)
 3. [Linux Kernel :: 0x02 :: Bypassing SMEP with CR4 Overwrite](/posts/linux-kernel-2-bypassing-smep)
 4. [Linux Kernel :: 0x03 :: Bypassing SMAP with Signal Handlers](/posts/linux-kernel-3-bypassing-smap)
 5. [Linux Kernel :: 0x04 :: Bypassing KPTI](/posts/linux-kernel-4-bypassing-kpti)
 6. [Linux Kernel :: 0x05 :: Stack Pivot in the Kernel](/posts/linux-kernel-5-stack-pivot)
 7. [Linux Kernel :: 0x06 :: Modprobe Path Overwrite](/posts/linux-kernel-6-modprobe-path-overwrite)
 8. [Linux Kernel :: 0x07 :: Bypassing KASLR](/posts/linux-kernel-7-bypassing-kaslr)
 9. [Linux Kernel :: 0x08 :: Return to Direct-mapped Memory](/posts/linux-kernel-8-ret2dir)

## Table of Contents
 1. [Environment Setup](#environment-setup)
 2. [Debugging in the Kernel](#debugging-in-the-kernel)
 3. [Kernel Module Overview](#kernel-module-overview)
 4. [Compiling Kernel Modules](#compiling-kernel-modules)
 5. [Inserting Kernel Modules](#inserting-kernel-modules)
 6. [Interacting with File-based Operations](#interacting-with-file-based-operations)
 7. [Interacting with IOCTL](#interacting-with-ioctl)

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

Note: by defauled pwnkernel launches the emulator without any kernel space protections (e.g. kpti, smap, smep, etc).

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

[challenge.c](/files/linux-kernel/0/5/challenge.c)

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

Once we've compiled the above and started the kernel virtual machine, it's as simple as running the `insmod` command to insert the kernel module. There are other commands to do this such as `modprobe`, which is better at resolving dependencies, but for this kernel module `insmod` is sufficient.

Running `dmesg` we can see that the `init_module` function was executed when we inserted the kernel module.

```
/ # insmod ./challenge.ko
/ # dmesg
...
[    8.437878] challenge: loading out-of-tree module taints kernel.
[    8.445662] module '/proc/challenge' created
```


## Interacting with File-based Operations
The majority of user interaction with kernel modules is done via file-based operations. Once the kernel module entry has been opened, the module has function handlers for read and write operations. For the sake of simplicity, you can think of this as a kind of file-based socket.

Interaction is performed first by opening the module entry. When you read from that open file descriptor the kernel module's `read` handler is called. When you write to the open file descriptor the kernel module's `write` handler is called.

Below is a pre-written kernel module that can be used for this exercise.

[challenge.c](/files/linux-kernel/0/6/challenge.c)

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
    char data[18] = "Here's some data!";
    copy_to_user(buf, data, 18);

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
{{< /code >}}

The below proof-of-concept code will do a few things to demonstrate how read / write actions are handled within the kernel module:
 - It will first open the module entry with read/write access.
 - Then it'll perform a read, reading from the kernel module (calling its `read` handler function).
 - Then it'll perform a write, writing to the kernel module (calling its 'write` handler function).
 - Finally it'll close the file descriptor.

[exploit.c](/files/linux-kernel/0/6/exploit.c)

{{< code language="c" title="exploit.c" id="4" expand="Show" collapse="Hide" isCollapsed="false" >}}
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
    puts(output);

    /* perform a write */
    char input[32] = "Hello, World!";
    write(fd, input, sizeof(char) * 32); 

    /* close the device */
    close(fd);

    return 0;
}
{{< /code >}}

```
~/ $ gcc exploit.c -o exploit -static 
```

Let's start by inserting the kernel module and running our demonstration code. Running `dmesg` afterwards we can see the result of our read / write actions.

```
/ # insmod ./challenge.ko
/ # ./exploit
Here's some data!
```
```
/ # dmesg
...
[   12.547802] challenge: loading out-of-tree module taints kernel.
[   12.557454] module '/proc/challenge' created
[   18.904788] device '/proc/challenge' opened
[   18.909735] Message: 'Hello, World!'.
[   18.911169] device '/proc/challenge' closed
```

## Interacting with IOCTL
As mentioned before, ioctl can provide us with much greater control over the way we interact with the kernel. Below is an example kernel module that will perform different actions depending on the input provided.

Here is a pre-written kernel module that you can use for this exercise.

[challenge.c](/files/linux-kernel/0/7/challenge.c)

{{< code language="c" title="challenge.c" id="5" expand="Show" collapse="Hide" isCollapsed="true" >}}
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
{{< /code >}}

After compiling our kernel module we'll want to check the values of `HELLO` and `GOODBYE`, so we can send them to the module via ioctl. We can see that `HELLO = 0x7001` and `GOODBYE = 0x7002`.

```
~/pwnkernel $ objdump -d src/challenge.ko -M intel
...
000000000000001e <challenge_ioctl>:
  1e:   41 54                   push   r12
  20:   48 c7 c7 00 00 00 00    mov    rdi,0x0
  27:   49 89 d4                mov    r12,rdx
  2a:   55                      push   rbp
  2b:   89 f5                   mov    ebp,esi
  2d:   e8 00 00 00 00          call   32 <challenge_ioctl+0x14>
  32:   81 fd 01 70 00 00       cmp    ebp,0x7001
  38:   75 11                   jne    4b <challenge_ioctl+0x2d>
  3a:   4c 89 e6                mov    rsi,r12
  3d:   48 c7 c7 00 00 00 00    mov    rdi,0x0
  44:   e8 00 00 00 00          call   49 <challenge_ioctl+0x2b>
  49:   eb 27                   jmp    72 <challenge_ioctl+0x54>
  4b:   81 fd 02 70 00 00       cmp    ebp,0x7002
  51:   75 11                   jne    64 <challenge_ioctl+0x46>
  53:   4c 89 e6                mov    rsi,r12
  56:   48 c7 c7 00 00 00 00    mov    rdi,0x0
  5d:   e8 00 00 00 00          call   62 <challenge_ioctl+0x44>
  62:   eb 0e                   jmp    72 <challenge_ioctl+0x54>
  64:   89 ee                   mov    esi,ebp
  66:   48 c7 c7 00 00 00 00    mov    rdi,0x0
  6d:   e8 00 00 00 00          call   72 <challenge_ioctl+0x54>
  72:   31 c0                   xor    eax,eax
  74:   5d                      pop    rbp
  75:   41 5c                   pop    r12
  77:   c3                      ret
...
```

Below is an example interaction with the above kernel module, it'll do several things:
 - First it'll open the kernel module entry with read/write access.
 - Next it'll send the `ioctl_num` for the `HELLO` command, with a string pointer as the `ioctl_param`.
 - Next it'll send the `ioctl_num` for the `HELLO` command, with a string pointer as the `ioctl_param`.
 - Finally it'll close the file descriptor.

[exploit.c](/files/linux-kernel/0/7/exploit.c)

{{< code language="c" title="exploit.c" id="6" expand="Show" collapse="Hide" isCollapsed="false" >}}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define HELLO   0x7001
#define GOODBYE 0x7002

int main(int argc, char** argv)
{
    /* open the device */
    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    /* interact with ioctl here */
    char name[7] = "Anvbis";
    ioctl(fd, HELLO, name); 
    ioctl(fd, GOODBYE, name);

    /* close the device */
    close(fd);

    return 0;
}
{{< /code >}}

```
~/ $ gcc exploit.c -o exploit -static 
```

After running our exploit, and checking `dmesg`, we can see that the kernel printed "Hello, Anvbis!" and "Goodbye, Anvbis!" as per the instructions we sent it via ioctl.

```
/ # insmod ./challenge.ko
/ # ./exploit
```
```
/ # dmesg
...
[   12.187784] device '/proc/challenge' opened
[   12.188714] Hello, Anvbis!
[   12.189492] Goodbye, Anvbis!
[   12.189747] device '/proc/challenge' closed
```


## Appendix
 - [The Linux Kernel Documentation - Kernel Modules](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html)
 - [The Linux Kernel Programming Guide - Talking to Device Files](https://students.mimuw.edu.pl/SO/Linux-doc/lkmpg.pdf)
 - [LinuxDrivers - I/O Control in Linux](https://sysplay.github.io/books/LinuxDrivers/book/Content/Part09.html)
 - [LinuxDrivers - Module Interactions](https://sysplay.github.io/books/LinuxDrivers/book/Content/Part17.html)

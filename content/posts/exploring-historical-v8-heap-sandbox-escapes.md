+++
tags = ["browser","v8","chromium"]
categories = ["Web Browsers", "Javascript Engines", "Chromium"]
description = "In anticipation of the future implementation of CFI on `code_entry_point` fields within function objects, I wanted to explore some patched sandbox escapes that have been found in the past."
date = "2023-01-08"
featuredpath = "date"
linktitle = ""
title = "Exploring Historical V8 Heap Sandbox Escapes"
slug = "exploring-historical-v8-heap-sandbox-escapes"
type = "post"
+++

## Motivation

In anticipation of the future implementation of CFI on `code_entry_point` fields within function objects (the vector by which most publicly known heap sandbox escapes currently occur), I wanted to explore some patched sandbox escapes that have been found in the past.

In this post I'll be looking at the following patches:
 - [\[sandbox\] Remove a number of native allocations from WasmInstanceObject](https://chromium-review.googlesource.com/c/v8/v8/+/3845636)
 - [\[sandbox\] Introduce BoundedSize](https://chromium-review.googlesource.com/c/v8/v8/+/3876823)


## References
 - [\[sandbox\] Remove a number of native allocations from WasmInstanceObject](https://chromium-review.googlesource.com/c/v8/v8/+/3845636)
 - [\[sandbox\] Introduce BoundedSize](https://chromium-review.googlesource.com/c/v8/v8/+/3876823)

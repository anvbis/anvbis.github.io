+++
tags = ["reverse engineering","real world"]
categories = ["Reverse Engineering"]
date = "2022-03-09"
description = "An in-depth exploration of the log4shell vulnerability in Minecraft server 1.18."
featuredpath = "date"
linktitle = ""
title = "Reversing Engineering :: Minecraft Log4Shell Vulnerability"
slug = "minecraft-server-log4shell"
type = "post"
+++

## Table of Contents
 1. [An Introduction to Log4Shell](#an-introduction-to-log4shell)
 2. [Reverse Engineering the Server](#reverse-engineering-the-server)
 3. [Exploring the Vulnerable Code](#exploring-the-vulnerable-code)
 4. [Verifying the Vulnerability](#verifying-the-vulnerability)
 5. [Getting Code Execution](#getting-code-execution)


## An Introduction to Log4Shell
...


## Reverse Engineering the Server
...

```
1.18/ $ unzip server-1.18.jar
...
```

...

```
1.18/ $ ls assets/minecraft/lang 
en_us.json
```

...

```json
{

  ...

  "chat.type.text": "<%s> %s",
  "chat.type.text.narrate": "%s says %s",

  ...

}
```

...

```
1.18/ $ zipgrep "chat.type.text" server-1.18.jar
aea.class:Binary file (standard input) matches
assets/minecraft/lang/en_us.json:  "chat.type.text": "<%s> %s",
assets/minecraft/lang/en_us.json:  "chat.type.text.narrate": "%s says %s",
```

...

```java
public class aea implements aed, ux
{
    ...

    public aea(final MinecraftServer $$0, final pl $$1, final adj $$2) {
        this.e = $$0;
        (this.a = $$1).a(this);
        this.b = $$2;
        $$2.b = this;
        $$2.T().a();
    }

    ...

    private void a(final aef.a $$0) {
        if (this.b.A() == bnp.c) {
            this.a(new rk(new qn("chat.disabled.options").a(p.m), pw.b, ad.b));
            return;
        }
        this.b.C();
        final String $$ = $$0.a();
        if ($$.startsWith("/")) {
            this.a($$);
        }
        else {
            final String $$2 = $$0.b();
            final pz $$3 = $$2.isEmpty() ? null : new qn("chat.type.text", new Object[] { this.b.C_(), $$2 });
            final pz $$4 = new qn("chat.type.text", new Object[] { this.b.C_(), $$ });
            this.e.ac().a($$4, $$2 -> this.b.b($$2) ? $$0 : $$1, pw.a, this.b.cm());
        }
        this.j += 20;
        if (this.j > 200 && !this.e.ac().f(this.b.fp())) {
            this.b(new qn("disconnect.spam"));
        }
    }

    ...

}
```

...

```java
public abstract class MinecraftServer extends aul<yx> implements dl, AutoCloseable
{
    ...

    private afy S;
    
    ...

    public afy ac() {
        return this.S;
    }

    ...
}
```

...

```java
import org.apache.logging.log4j.Logger;

public abstract class afy
{

    ...

    private static final Logger a;

    ...

}
```


## Exploring the Vulnerable Code
...


## Verifying the Vulnerability
...


## Getting Code Execution
...


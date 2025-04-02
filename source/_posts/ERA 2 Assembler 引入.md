---
title: ERA 2 Assembler 引入
date: 2025-04-02 14:24:43
categories:
  - [TUM课程笔记,ERA 计算机体系结构]
tags:
---

我们从C语言的编译开始引入，比如
``` c
int main(int argc, char *argv[])
{
    int c = 0;
    for (int i=0; i<10; i++) { 
        c = c + i;
    }
    printf("Ergebnis ist %i\n",c);
}
```

C语言的源代码经过编译会变成可执行文件

``` shell
gcc count.c -O0 -g -o count
```

我们可以用 `hexdump count` 来查看这个可执行文件，会发现是二进制文件

### 二进制文件包含了什么

* 程序
* 数据的初始值
* 元数据 Metadata

这个二进制文件的格式，取决于操作系统和硬件平台

我们可以使用 `objdump -h count` 来查看二进制文件的内容

这里面输出了section的信息

objdump还可以进行反汇编

``` shell
objdump -h -d count > countobj.txt
```

如果加入 `-S` 参数，还可以和C源代码对照查看汇编指令

### 汇编语言

是和机器相关的编程语言

* 最低的抽象层Niedrigste Abstraktionsbene
* 原始的指令：不支持复杂的数据结构
  可以一对一翻译为二进制代码
* 需要手动管理资源，例如内存元素和数据传输

### 指令的实现

* 直接实现单个指令
* 数据或指令通常有固定的宽度

#### 生成Assembly有三种方式

* 反汇编二进制程序：只能还原很少的信息
* 从编译器生成Assembly：编译器生成汇编文件作为中间步骤（通常是隐藏的）
* 直接写汇编代码

### 汇编语言的平台

* `x86_64` 
* ARM
* RISC-V

### RISC-V

RISC-V是一种开源指令集架构




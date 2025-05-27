---
title: Linux源码深入
date: 2025-05-08 08:20:32
categories: 安全学习笔记
tags: [Linux]
---

















1

## 资料

https://zhuanlan.zhihu.com/p/652024768





























# Plan

### 🔹 第1周：整体启动流程理解 + 环境搭建

**目标：掌握从开机到 shell 的整体流程，有实验环境（QEMU/VM）**

- ✅ 学习 BIOS/UEFI、Bootloader、Kernel、Init 各阶段作用
- ✅ 安装虚拟机（建议使用 QEMU + Ubuntu/Debian）
- ✅ 用 `dmesg` 和 `journalctl -b` 查看一次完整启动日志
- ✅ 推荐资料：
  - Arch Wiki: Boot Process
  - B站/YouTube: “Linux 启动流程讲解”

# 🗓 第1周：Linux 启动流程概览 + 实验环境搭建

> 🎯 **目标**：理解 Linux 启动的五个阶段；掌握基本启动日志分析方法；搭建调试/实验环境。

------

## ✅ 任务一：理解 Linux 启动流程五大阶段

### 📚 学习内容

Linux 从按下电源键到登录 shell，大致分为五个阶段：

1. **BIOS/UEFI 初始化硬件和启动设备**
2. **Bootloader 加载内核（如 GRUB）**
3. **内核初始化（start_kernel）**
4. **初始化用户空间（init/initramfs）**
5. **systemd 启动用户服务和 shell**

### 🔧 操作任务

- 画一张流程图（手画或工具）表示启动过程，标出各阶段职责。

- 阅读 GRUB 配置文件：

  ```
  bash
  
  
  CopyEdit
  cat /boot/grub/grub.cfg | less
  ```

### 🎥 推荐视频

- B站：《Linux 从开机到登录详解》搜索关键词：“Linux 启动流程”
- YouTube/MIT: Operating System Booting Process

------

## ✅ 任务二：熟悉启动日志

### 📚 学习内容

- `dmesg`：查看内核启动消息
- `journalctl -b`：查看 systemd 启动日志

### 🔧 操作任务

```
bashCopyEdit# 查看内核初始化信息
dmesg | less

# 查看本次启动日志
journalctl -b | less

# 筛选内核信息
journalctl -k -b
```

📌 分析内容示例：

- Kernel 版本
- 内存检测信息
- CPU 初始化
- 加载的驱动模块（比如 network, USB）

------

## ✅ 任务三：搭建实验/开发环境

### 推荐方式 A：使用 QEMU 虚拟机（推荐进阶使用）

安装 QEMU + 编译内核后可自定义启动流程（后续使用）

```
bash


CopyEdit
sudo apt install qemu-system-x86 build-essential libncurses-dev flex bison
```

资源：

- QEMU 安装与使用指南

------

### 推荐方式 B：普通虚拟机（初学者推荐）

1. 安装 VirtualBox 或 VMware
2. 下载 Ubuntu/Debian 最小安装镜像
3. 安装后可以练习终端操作、查看 `/proc`, `/sys`

------

## ✅ 任务四：巩固知识 + 自测

### 📖 推荐文章

- Linux Booting Explained
- Arch Wiki：Boot process

### 🧠 自测问题（建议写在笔记里）

1. 什么是 BIOS 和 UEFI？它们的主要作用是什么？
2. 什么是 GRUB？它在启动过程中做了什么？
3. `init` 是什么？和 `systemd` 有什么关系？
4. 用哪些命令可以查看内核日志和系统服务日志？
5. `/boot` 目录里常见的文件是做什么用的？

------

## 🧰 本周工具清单

| 工具              | 用途                  |
| ----------------- | --------------------- |
| `dmesg`           | 查看内核启动信息      |
| `journalctl`      | 查看 systemd 启动日志 |
| `grub.cfg`        | Bootloader 配置       |
| `VirtualBox/QEMU` | 虚拟机实验平台        |
| `draw.io` 或手绘  | 绘制启动流程图        |



------

## 🧩 Bonus（选做）

- 使用 grub 启动参数调试（编辑 `grub.cfg` 或 `grub` 引导界面按 `e` ）

- 安装 `neofetch` 显示系统概况：

  ```
  bashCopyEditsudo apt install neofetch
  neofetch
  ```

------

## 📝 建议记录笔记内容（建议用 Obsidian/Typora 或笔记本）：

- 各阶段职责简述
- 启动日志关键信息标注
- 遇到的问题和解决办法
- 启动流程图草图



- 

------

### 🔹 第2周：Bootloader & GRUB

**目标：了解 Bootloader 如何加载内核，掌握 GRUB 配置和原理**

- ✅ 阅读 GRUB 配置文件（/boot/grub/grub.cfg）
- ✅ 修改 grub 参数（比如添加启动参数）
- ✅ 实验：使用 grub-rescue 启动系统
- ✅ 学习：Multiboot 规范、kernel image 格式（bzImage）

------

### 🔹 第3周：内核启动入口与初始化过程

**目标：理解 Linux 内核从 `start_kernel()` 到 init 进程的启动逻辑**

- ✅ 下载并编译 Linux 内核（建议 5.x 稳定版本）
- ✅ 阅读 `start_kernel()` 函数（`init/main.c`）的调用链
- ✅ 理解：内存管理初始化、中断初始化、时钟初始化
- ✅ 推荐资源：
  - 《深入理解Linux内核》第三版 第2-5章
  - https://elixir.bootlin.com/ 浏览内核源码

------

### 🔹 第4周：init/initramfs & systemd 分析

**目标：掌握用户空间的启动流程，理解 init/systemd 的作用**

- ✅ 学习 initramfs 的结构和解压方式
- ✅ 实验：定制一个简单的 initramfs（可用 busybox）
- ✅ systemd 服务管理命令（`systemctl`, `journalctl` 等）
- ✅ 推荐资源：
  - initramfs HOWTO

------

### 🔹 第5周：设备与硬件管理入门

**目标：理解 Linux 是如何识别、管理硬件设备的**

- ✅ 理解 devfs, sysfs, procfs 的作用
- ✅ 学会用 `lsmod`, `lspci`, `lsusb`, `udevadm`, `dmesg` 查看硬件
- ✅ 学习设备树（Device Tree）的作用（嵌入式重要）
- ✅ 推荐书籍：《Linux 设备驱动开发详解》第一章

------

### 🔹 第6周：中断机制 & 驱动模型

**目标：理解 Linux 中断处理和驱动框架**

- ✅ 阅读中断初始化流程（`arch/x86/kernel/irq.c` 等）
- ✅ 实验：查看 `/proc/interrupts`，了解 IRQ 分配
- ✅ 理解 Linux 的驱动模型（platform_driver、pci_driver等）
- ✅ 推荐资源：
  - LWN: “Anatomy of a Linux interrupt handler”
  - 《深入理解Linux内核》第10章

------

### 🔹 第7周：编写一个简单字符设备驱动

**目标：掌握驱动的基本编写流程和模块加载机制**

- ✅ 学会编写字符设备驱动（实现 open/read/write）
- ✅ 使用 `insmod`、`rmmod`、`modinfo` 管理内核模块
- ✅ 编写 Makefile 使用 `kbuild`
- ✅ 推荐教程：
  - The Linux Kernel Module Programming Guide
  - B站：字符设备驱动编写教学

------

### 🔹 第8周：深入实践 + 总结复盘

**目标：整合所学知识，实践调试工具，形成自己的知识体系**

- ✅ 使用 QEMU + gdb 调试内核启动流程
- ✅ 总结从 BIOS 到 shell 的全过程（写篇博客或画图）
- ✅ 可选挑战：
  - 移植 Linux 到树莓派或开发板
  - 修改内核打印信息，观察变化
  - 给内核加一个参数并解析它

------

## 📘 附加建议（可自由拓展）

- 学习 `perf`, `ftrace`, `eBPF` 等调试工具
- 阅读内核 mailing list、LWN 文章
- 加入社区如 Reddit 的 /r/linux, KernelNewbies 等

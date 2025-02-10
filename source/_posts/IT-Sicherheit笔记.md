---
title: IT Sicherheit笔记
date: 2025-02-10 16:39:14
tags:
---

# IT Sicherheit 笔记

## Systemsicherheit

### 操作系统的任务

* 通过 syscall 控制硬件
* 控制：内存，CPU, E/A, 文件管理
* Modi: Kernal-Mode: 执行特权命令; User-Mode: 执行普通命令



### 操作系统的保护/控制任务

* 标识符Identifikatoren: 进程,文件,文件的安全管理

* 访问控制
* 访问与信息流控制: ACL(访问控制列表), 权限能力，分类
* 安全启动：Secure Boot, Trusted Boot
* 安全运行环境： TEE
* RAM保护机制: Canaries, DEP 数据执行保护, ASLR地址空间布局随机化
* 虚拟化: Isolation, Hypervisor, VM-Monitor

### 内存保护

冯诺依曼架构universelle Interpretierbarkeit：程序指令和数据存储在同一存储器中，具有统一的地址空间。

#### 进程地址空间

![image-20250210170538424](IT-Sicherheit笔记/image-20250210170538424-1739205784583-3.png)

### Buffer Overflow

#### Example 1

``` cpp
void a() {
	bool is_admin;
    char msg[128];
    gets(msg);
}
```

这个时候，`is_admin` 在 msg 的上面，Buffer Overflow的时候是从低地址往高地址overflow，可以覆盖掉 `is_admin`

![image-20250210171343432](IT-Sicherheit笔记/image-20250210171343432-1739205779594-1.png)

#### Return To ShellCode

可以把 `shellcode` (可以打开shell的代码) 作为输入，然后控制返回地址，跳转到这个shellcode的地方开始执行。 

### Stack-Shielding

#### Stack Canary

在返回地址前面加一个随机数，如果随机数被覆盖了就说明有Buffer Overflow

这个保护措施通过GCC加的

![image-20250210171726661](IT-Sicherheit笔记/image-20250210171726661-1739205788859-5.png)Shadow Stack

Shadow-Stack 是一个独立且受保护的内存区域，用于安全存储函数调用的返回地址。它与常规栈相分离，以防止攻击者通过缓冲区溢出等手段篡改返回地址。

### DEP

Data Execution Prevention: 

* CPU-Feature  NX-bit (No-eXecute) 标记为不可运行

### ASLR

Address Space Layout  Randomization地址随机化

因为DEP不能保护Return Oriented Programming (ROP) 

* Linux 在每个程序启动的时候随机化
* Windows 在每次启动系统的时候随机化

但是代码段不会随机化

扩展：

* PIE(Position Independent Executable): 支持代码段随机化
* KASLR: Kernel ASLR对内核地址空间进行随机化，从而进一步提升内核态安全性。

### Virtual-Machine-Monitor (VMM)

目标：

* 将物理硬件资源抽象为虚拟化资源，供虚拟机使用.
* Isolation: 确保各虚拟机（VM）之间相互独立，不受干扰

VMM/Hypervisor:

* 是一种管理虚拟机的软件，负责创建、启动和运行虚拟机。
* 允许不同的操作系统在多个虚拟机中并行运行。
* Hypervisor 实现了虚拟机之间的隔离，防止一个虚拟机对另一个虚拟机的直接干扰或访问。
* Hypervisor 可以控制虚拟机的状态，包括暂停、重启、调整资源配置等。

### Container-Konzept

轻量化的虚拟化，以更高效地运行和管理应用程序。

容器将应用程序运行所需的所有组件打包成一个整体，包括：应用程序代码,相关服务,依赖的库与运行环境

* 容器在用户空间中以 **隔离进程** 的方式运行。
* 与传统虚拟机相比，容器的隔离性较弱，因为它们共享相同的内核。

优点是: 轻量高效，易于部署和维护

### 硬盘加密

保护系统中数据的机密性，特别是当攻击者拥有物理访问权限时。

> 例如，一台包含公司敏感数据的笔记本电脑被盗，攻击者拆下硬盘后，操作系统的保护措施不再生效，数据可能被轻易访问。

通过加密保护数据，只有在用户提供正确的密码（Passphrase）后，才能解密数据并访问。

在计算机关闭时，数据处于加密状态，无法被访问或读取。

#### 种类

* 通过特定应用程序对文件进行加密，例如 PDF 文件加密。
* 文件系统层面进行加密，比如 **fscrypt**（Linux）
* Device Mapper: 在硬盘和文件系统之间进行透明加密，例如 **BitLocker**（Windows）、**dm-crypt/LUKS**（Linux）

### 硬盘加密的局限性

* 在加密过程中，密钥需要始终存储在主存（RAM）中，以便操作系统和应用程序访问。这意味着在系统运行时，密钥始终暴露于内存中。
* Cold Boot Attacks: 即使设备关闭，DRAM（动态随机存取内存）芯片仍会在短时间内保持其数据状态。
* 硬盘加密无法防止恶意软件的入侵 (恶意软件可以在系统运行时监视并记录密码输入或直接访问密钥)

解决方案

* 将加密密钥存储在 CPU 的寄存器中
* AMD SME,Intel MKTME技术可以在硬件级别进行加密操作
* 使用受信执行环境，如 **Intel SGX** 或 **AMD SEV** 为加密操作提供一个安全的运行环境

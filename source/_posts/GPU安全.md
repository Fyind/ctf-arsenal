---
title: GPU安全
date: 2025-06-16 16:43:21
categories: [安全学习笔记]
tags: GPU
---

# Computer Architecture Background

现代计算机是在主板上的。它连接了RAM, 处理器, IO设备,网卡(NIC). 这些设备和CPU的交流是通过不同的bus系统实现的。大多数bus是在 Platform Controller Hub (PCH), 也叫IO Controller Hub. 这个chip是之前南桥的演化，北桥是在CPU芯片内部的。PCH包含了很多控制器接口，比如USB, SATA, 和 PCI (Peripheral Component Interconnect). 对于可以DMA的bus系统，他们的控制器部分是DMAC. PCH与CPU的连接是一个点对点的serial link, 叫DMI(Direct Media Interface). DMI 是被用于高速bus让CPU和IO设备快速交换信息。

## memory space

内存空间是一个地址空间，它可以是主存，或者IO位置 (memory-mapped I/O). 这些IO位置可以是配置寄存器或者设备内部内存。

CPU先给IO Controller发送内存请求, 请求通过PCIe或者DMI到对应的控制器. 设备也可以通过DMA访问映射的地址空间。

## PCI

PCI (Peripheral Component Interconnect)是一个bus主要的系统，bus是以一个广播网络的方式连接其他设备的。在同一时刻只有一个设备可以发送，所以需要一个主设备(bus master)，只有主设备可以通信，如果其它设备要成为主设备必须请求，允许之后才可以。

每一个可以连接PCI的设备都有一个配置空间，它可以被系统配置软件访问。这个地址空间分为预定义的header区域和设备独立的区域。header 可以被OS访问来识别设备和配置设备的行为。

## PCIe

PCIe (PCI Express) 是一个基于包裹的，高速序列点对点连接(PCIe slot设备和PCIe root complex)，

![image-20250617142814615](/home/fyind/snap/typora/96/.config/Typora/typora-user-images/image-20250617142814615.png)

一共有三层: physical, data link,和transaction. Data Link层是用来修正错误的，流控制。transaction层是把用户数据变成transaction layer packets. 每个layer都有自己的header. 后来，Root Complex (RC)从PCH移到了CPU内部。这使得设备和CPU缓存更加近了。于是发展了DCA(Direct Cache Access), DDIO.

### Root Complex

根节点，连接CPU，内存，和IO设备，允许拆分数据包





# GPU Architecture

## GPU Execution Model

GPU 是完全由CPU控制的从属处理器。任何CPU进程都可以通过特权模式的GPU驱动程序，调用GPU内核，启动GPU程序。

CPU对GPU的访问仅通过API比如 NVIDIA CUDA 和 OpenCL . 

## GPU Memory Hierarchy

NVIDIA GPU包含一些 streaming multiprocessors (SMs) 流处理器， 可以运行上千个线程。每个线程可以访问它的私有寄存器，局部内存 on-die scratchpad memory, 和在所有SM共享的全局内存. 全局内存有2层缓存，L1 data cache 是对每个SM私有的，L2是所有SM共有的。

### 指令缓存

NVIDIA GPU有很多级指令缓存，是指令专有的缓存，不在全局内存里面。当一个新的GPU程序运行的时候，GPU driver会flush这些指令缓存。NVIDIA也没有提供API来flush缓存，所以，在运行时写入GPU内核程序不会改变当前运行的程序。

## GPU访问CPU内存

有个API (cudaHostRegister) 可以把一个CPU的内存映射到GPU内核地址空间上。当映射形成的时候，GPU可以直接访问CPU的内存，不需要CPU参与 (DMA). 类似的，GPU也可以通过设置MMIO，访问其他连接到PCIe上的设备，比如(GPUDirectRDMA API 可以让GPU之间互相访问)

GPU内部的page table可以被GPU driver访问，但对CPU OS不可见。

和CPU不同，GPU访问CPU的内存不会经过MMU，所以CPU不会实时检查。当mapping产生的时候，GPU就拿到了访问权限。

## IOMMU

当一个设备通过DMA访问CPU物理内存的时候，他用设备的地址空间。IOMMU会把设备的地址空间map到CPU的物理地址空间。IOTLB Cache会缓存整个IO page table. 在IO page table包含了保护信息，IOMMU会检查每个内存访问是否有足够的权限。IOTLB和IO page table 不一定是一致的。软件必须显式管理IOTLB coherence来, 当它被IO Page Table移除的时候，需要flush缓存。

## Microprocessors and MMIO registers in GPUs

GPU暴露一些寄存器用于MMIO, 它被GPU Driver使用。此外，还有微处理器来管理内部硬件资源。GPU Driver在每次GPU初始化的时候会更新 GPU 微处理器的代码。对此的文档很少。

我们发现GPU MMIO可以让GPU指令缓存作废。通过flush指令缓存可以更新GPU程序。有个微代码攻击利用了NVIDIA Microprocessor可以允许GPU不限制的访问CPU内存。

# Confidential GPU





# Attack

## PixelVault Attack

PixelVault提出了基于GPU的关于RSA,AES加密的security co-processor. PixelVault 把secret key存在GPU内存里，把master key存在GPU寄存器里。

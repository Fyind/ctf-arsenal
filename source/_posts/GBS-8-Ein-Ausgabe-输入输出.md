---
title: GBS 8 Ein/Ausgabe 输入输出
date: 2025-04-01 23:46:22
categories: 
  - TUM课程笔记
  - GBS 操作系统
tags: [Betriebssysteme, Operating System, 操作系统, 输入/输出]
excerpt: "操作系统基础相关笔记"
---




设备大致可以分为2类：
1. **`块设备（Blockorientierte Geräte，block devices）`**：

   - 内容是**可寻址**的（**adressierbar**）；
   - 数据以**固定大小的块**存储（in **Blöcken fester Größe** von 29 Byte bis 216 Byte）；
   - 可以**随机访问**（**Random Access**）每个块；

   例子：蓝光光盘（Blu-ray Disc）、硬盘（HDD）、固态硬盘（SSD）。

1. **`字符设备（Zeichenorientierte Geräte，character device）`**：

   - **串行**数据传输（serieller Datentransfer）：指每次传输一个比特数据，并连续进行以上单次过程的通信方式；
   - **不可寻址**的；
   - 发送和/或接收**字符流**（**Zeichenströme**）；

   例子：鼠标，键盘，打印机。

2. （其他）：

   比如说时钟（生成中断信号 erzeugt Unterbrechungen），显示器等。



拿键盘举例，我们每次敲击按键了之后它都会将这个信息直接传输到电脑，而不是等我们输入了一长串内容之后再将这段内容一起发送给电脑，所以是serieller Datentransfer。而与serieller Datentransfer相对的则是parallele Datenübertragung。

![串行与并行数据传输](https://raw.githubusercontent.com/archer-baiyi/Picture/main/langde-1280px-Serial_and_Parallel_Data_Transmission.svg.png)



E/A System 的**分层结构**：

1. **`控制器（Controller）`**：设备硬件的一部分；作为**CPU和设备之间的接口**。
2. **`中断处理程序（Interrupt-Handler）`**：处理设备的反馈信息（中断）。
3. **`设备驱动程序（Gerätetreiber）`**：执行**与设备相关的控制软件**；驱动程序通过控制器访问设备。
4. **`设备无关软件（Geräteunabhängige Software）`**：分配设备、**数据缓冲**等功能。
5. **`用户级软件（User-Level-Software）`**：用于**输入/输出（E/A）**的库函数，例如**假脱机（Spooling）**。

![image-20250320231752723](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250320231752723.png)

![image-20250320231735315](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250320231735315.png)

以惠普（HP）打印机为例来明确一下每层的具体内容：

1. **控制器**：HP 打印机的主控制芯片

   惠普打印机内部有专门的 **控制芯片**，负责**管理打印作业**、处理数据，并控制墨盒或激光成像单元的工作。

2. **中断处理程序**：负责处理打印机状态反馈（如“缺纸”或“墨盒不足”）的程序

   当打印机遇到 缺纸、卡纸、墨水不足 等问题时，会发送中断信号给计算机，让操作系统暂停当前任务并处理异常。

3. **设备驱动程序**：HP 打印机驱动程序

   点击“打印”时，驱动程序会把文本或图像转换成 HP 打印机能理解的格式（如 PCL、PostScript），然后发送给打印机。

4. **设备无关软件**：Windows/Linux 的打印管理系统

   这层软件不依赖于具体的打印机品牌，而是为所有打印设备提供统一的管理功能，如：

   - 排队管理（多个打印任务排队执行）
   - 数据缓冲（避免 CPU 直接等待打印机完成任务，提高效率）

5. **用户级软件**：用户直接使用的应用程序，它们调用**系统级打印服务**完成任务。例如：Microsoft Word，HP Smart App。

接下来我们看一下每一层的具体功能：



## **控制器（Controller）**



什么是控制器？

输入/输出设备（E/A-Geräte） 由机械组件和电子组件组成，其中电子组件就是设**`设备控制器（Geräte-Controller）`**。它是连接 CPU 和外部设备的桥梁。

Controller besitzt Hardware-Schnittstelle zum Gerät.



控制器包含寄存器（Register），用于与 CPU 进行通信：

- **数据传输**：操作系统（BS）向寄存器写入数据。
- **查询设备状态**：操作系统 读取寄存器内容。
- **附加功能**：控制器提供**数据缓冲区（Datenpuffer）**，用于存储传输中的数据，以提高效率。



**设备控制器（Geräte-Controller）的主要任务：**

- **设备管理**（**Steuerung** der beweglichen Hardware）
- 处理来自驱动的命令（Befehle ausführen）
- 与CPU进行交互（Kommunikation mit CPU）
- **发送中断信号**（Interrupts **melden**）
- **缓冲**数据（Daten **puffern**）





### **交互**

计算机与设备控制器（Controller）**交互**主要有两种方式：

1. **I/O-Ports**：

   早期计算机使用 I/O 指令和I/O 端口与设备通信。

2. **Memory-Mapped I/O**：

   将设备的寄存器直接映射到系统内存地址空间，这样 CPU 可以通过普通的 LOAD/STORE 指令来访问设备。

早期的计算机需要**手动设置**设备地址，使用 **跳线（Jumper）** 或 **DIP 开关**。而现代设备支持 **Plug & Play**，系统能够**自动分配** I/O 端口地址 和 中断（IRQ）。



### **数据交换**

第一种方法：

#### **程序控制 I/O（Programmed I/O）**

CPU会直接控制与设备的交互。

比如说向打印机发送数据需要进行以下**步骤**：

- 将数据复制到内核
- 内核逐个字符发送到打印机
  - 传输字符 $N$
  - 等待打印机确认字符 $N$
  - 继续发送字符 $N+1$

这样做的坏处非常显而易见：**忙等待（Busy Waiting）**。CPU会被卡死在这里不能完成其他的任务。

代码示例：

```c
copy_from_user(buffer, p, count)
for (i = 0; i < count; i++) {
    while (*printer_status_reg != READY);  // 忙等待
    *printer_data_register = p[i];         // 只发送一个字符
}
```



更好的办法：

#### **中断（Interrupts）**

流程如下：

- 设备通过信号通知CPU，表明其I/O操作已完成。

- 中断控制器（Interrupt Controller Chip）识别信号，并通知CPU。

- 操作系统（BS）暂停当前进程，切换到内核模式（Kernel Mode）。

- 在内核中执行中断处理程序（Unterbrechungsbehandlungsroutine）

  设备驱动程序（Gerätetreiber）负责提供中断处理程序（Unterbrechungsbehandlungsroutine），但中断处理的执行由操作系统管理。

- 中断处理程序（Handler） 执行完成后便会通知操作系统。

- 操作系统将等待（wartenden）I/O 的进程恢复到可运行状态（rechenwillig）。



这个**流程**可以分为2部分：

1. 同步系统调用（Systemcall）
   - 传递 I/O 参数，启动 I/O 操作。
   - 调用后，进程进入睡眠状态（等待 I/O 完成），释放 CPU。
2. Interrupt-Handler
   - 逐步处理 I/O 操作。
   - I/O 完成后，唤醒等待的进程。



代码示例：

1\. Systemcall：

```c
copy_from_user(buffer, p, count);  // 从用户空间复制数据到内核
enable_interrupts();               // 允许中断
while (*printer_status_reg != READY); // 轮询等待打印机准备就绪
*printer_data_register = p[0];      // 发送第一个字符到打印机
scheduler();                        // 调度其他进程
```

2\. Interrupt-Handler：

```c
if (count == 0) {  
    unblock_user();  // 唤醒等待的进程
} else {
    *printer_data_register = p[i];  // 发送下一个字符
    count = count - 1;
    i = i + 1;
}
acknowledge_interrupt();  // 确认中断已处理
return_from_interrupt();
```



用这个方法的话CPU 可在 I/O 期间执行其他任务，不需要一直等待。但是会一直触发Interrupt，可能会影响性能。

所以此之上还有一种更好的办法：

#### **直接内存访问（Direct Memory Access, DMA）**

使用 DMA 控制器，**允许直接访问内存**，而**无需 CPU 介入**。可以有效解决通过寄存器作为中间存储器传输数据消耗大量 CPU 计算周期的问题。

传输**流程**：

- CPU 初始化 DMA （Programmiert DMA-Register (Speicher- und Gerätadressen, Parameter)）；
- 磁盘控制器（ Disk-Controller）将数据放入缓冲区（Puffer）；
- DMA 控制器从磁盘（Disk）读取数据，并直接存入主存（RAM）（DMA-Controller initiiert die Übertragung von Disk in RAM）；
- 磁盘控制器（ Disk-Controller）发送确认（ACK）。
- 操作系统（BS）继续处理内存中的数据（ weiterverarbeiten bzw. weitergeben）

流程结束之后才会发送Interrupt。

之前是传输每个数据（每个字符）都会触发一次Interrupt，现在是传输整个数据块只会触发一次。



## **数据缓冲（Puffern von Daten）**



缓冲的主要作用是解耦（Entkopplung）用户程序和设备。相当于提供一个中间层。

（解耦指的是减少两个系统组件之间的直接依赖关系。）

缓存分以下几种类型：

1. **`无缓冲（Ohne Puffer）`**：

   用户进程必须自己存储 I/O 数据，并且数据必须始终驻留在进程的内存中，直到 I/O 操作完成。

2. **`简单缓冲（Einfacher Puffer）`**：

   进程仍然必须快速取走数据，否则缓冲区会满，影响数据流。

3. **`双缓冲（Doppelter Puffer）`**：

   一个缓冲区正在被读取（geleert）的同时另一个缓冲区会正在被写入（gefüllt）。清空速度必须足够快，否则会导致数据堆积。

4. **`环形缓冲（Zirkulär / Ringpuffer）`**：

   扩展双缓冲的概念，使用多个缓冲区（k 个缓冲区）。可以适应不同的负载和处理速度，提高数据吞吐率。

   会使用2个指针来管理数据：写指针和读指针。



![image-20250320231338305](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250320231338305.png)

有时可能会存在多个级别的缓冲，比如说：Nutzerprozess, Kern, Gerätetreiber, Gerätecontroller, …



## **设备驱动程序（Geräte-Treiber）**



**`设备驱动程序（Geräte-Treiber，Device Driver）`** 是操作系统中用于控制硬件设备的软件模块（Software-Module）。它充当 BS 和设备（尤其是Controller）之间的桥梁，让系统能够识别和管理外部设备。

驱动具有以下特点：

- 针对特定设备类型（Gerätetyp-spezifisch）

  它了解相应设备的指令集（即控制设备的命令），以便和controller进行交互。

- 一个驱动程序可适用于多个同类设备

  比如说USB驱动会支持所有的USB设备。

驱动充当BS 和设备（尤其是Controller）之间的桥梁指的是它可以：

- 查询设备状态（Gerätezustand abfragen）
- 向设备发送命令（Befehle an das Gerät zu übermitteln）
- 与设备进行数据交换（Daten mit dem Gerät auszutauschen）

同样，驱动也可能存在子结构（Unterstruktur），比如说USB。



**驱动的主要任务：**

- **定义**设备并向操作系统注册，并**激活**设备。（**definiert** das Gerät gegenüber dem BS, **aktiviert** das Gerät）
- 在系统启动时**初始化**控制器和设备。（**initialisiert** den Controller und das Gerät beim Systemstart）
- **转换**I/O 请求，使其变为设备可理解的指令。（**wandelt** E/A-Anforderungen in gerätespezifische Befehle um）
- **响应**（来自设备或控制器的）硬件信号。（**antwortet** auf Hardwaresignale des Geräts bzw. des Controllers）（比如说 Interrupt handling）
- **报告**设备和控制器的**错误**（错误检测和日志记录）。（**meldet** Geräte- und Controller-**Fehler**）
- **传输**设备与操作系统之间的**数据**和**状态信息**。（**überträgt** **Daten** und **Zustandsinformation** vom/zum Gerät）
- **缓冲**输入/输出数据，优化数据传输性能。（提供Buffer）（**puffert** Daten bei Ein- und Ausgabe）



**设备驱动是如何与设备控制器协作的？**

- 驱动程序发送命令到设备控制器，并在等待期间阻塞自身（防止 CPU 过度轮询）。（**Treiber schickt Kommandos** zum Controller und **blockiert sich**）
- 控制器处理数据并在传输完成后发送信号（通知数据交换已完成）。（**Controller signalisiert** das Ende des Datenaustausches）
- 中断处理程序（Interrupt-Handler）解除驱动的阻塞状态，例如通过信号量（Semaphore） 让进程恢复运行。（**Der Interrupt-Handler entsperrt** den Treiber (z.B. Semaphore)）
- 驱动程序处理收到的数据或继续发送新数据。（Treiber **verarbeitet empfangene Daten** bzw. **schickt weitere Daten**）



## **设备无关的软件（Geräte-unabhängige Software）**



设备无关的软件的目的是简化驱动程序的编程（Vereinfachte Treiber-Programmierung），并便于集成新的驱动程序软件（Einfache Einbindung neuer Treiber-Software）。



设备无关软件的主要任务：

- 在设备驱动程序和操作系统之间建立**标准接口**。（Bereitstellung einer **einheitlichen Schnittstelle** zwischen Gerätetreibern und  dem Rest des Betriebssystems）

- **缓冲**

  如果缓冲不由驱动管理，则由设备无关的软件负责。

- **错误处理（Fehlerbehandlung）**

  除了驱动程序本身的错误处理外，还提供额外的错误管理机制。

- **设置**设备无关的**参数**（Festlegung geräteunabhängiger Parameter）

  比如说块设备（Blockgerät）使用的块大小（Blockgröße）



## **用户级软件（User-Level-Software）**

系统库（Systembibliothek）通常会直接给用户提供E/A的编程接口。

比如说：

- {% kbd open() %}：

  打开设备的逻辑通道，返回一个 文件描述符（Descriptor 或 Handle），供后续操作使用。

- {% kbd read() %}：

  从设备读取数据，返回指定数量的字节流（Bytestream）。

- {% kbd close() %}：

  关闭先前打开的通道，释放相关的系统资源。

- {% kbd write() %}：

  向设备写入数据，发送指定数量的字节到设备。

- {% kbd ioctl() %}：

  改变设备的操作模式，比如调整串行端口的传输速率或者是修改设备的控制参数



除了这些标准库函数，还有：

### **假脱机（Spooling）**

由于在现实生活中，我们经常会有多个进程同时提交I/O请求，比如说用一台打印机打印多份文件。这个时候就需要想办法协调资源的使用，避免出现冲突。



什么是 Spooling？

**Spooling（Simultaneous Peripheral Operations Online，同步外设操作）** 是一种用于管理**独占（）exklusiv nutzbar)**设备（如打印机）访问的缓冲机制。

在这个机制下，进程不会直接访问设备，而是将任务交给 Spooler Daemon（假脱机守护进程） 处理。只有 Spooler Daemon 会直接与设备驱动程序交互，确保设备顺序执行任务。用户进程的任务先存入 Spooling 目录（缓冲区），然后按顺序执行。



## **UNIX/Linux里的设备管理**

在UNIX/Linux里，我们需要通过文件系统访问 I/O 设备（因为“Everything is a file"）：

- 在访问设备前，必须先打开它 {% kbd open %}。
- 不同设备支持额外的文件系统操作，如读写、状态查询等。
- **设备管理位于 {% kbd /dev %} 目录**，所有设备文件都存放在这里。
- **设备状态查询和配置可能位于 {% kbd /proc %}  目录。**



设备文件名称指示设备类型，比如说：

- {% kbd /dev/tty0 %}：物理串行接口（终端）。
- {% kbd /dev/USBtty1 %}：抽象串行接口（USB 串口设备）。
- {% kbd /dev/sd0 %}：硬盘设备（`sd` 代表 SCSI 磁盘）。
- {% kbd /dev/null %}：伪设备，写入的数据会被丢弃。
- {% kbd /dev/zero %}：伪设备，读取时返回无限的 0 字节。

Spooling 任务存储在 {% kbd /var/spool %} 目录下，其中

- {% kbd lpq %}：打印任务队列（打印机 Spooling）。
- {% kbd mqueue %}：邮件服务器的发送队列（邮件 Spooling）。
- {% kbd news %}：新闻系统消息队列（新闻 Spooling）。
- {% kbd cron %}：定时任务执行队列（任务调度 Spooling）。



而设备的真正标识存储在 i-Node 中。i-Node会包含：

- **主设备号（Major Device Number）**：**标识设备驱动程序**（决定设备的驱动）。
- **次设备号（Minor Device Number）**：要访问的**具体设备**。





## **设备例子**

### **（机械）硬盘（Festplatten，HDD）**

机械硬盘属于Block-Gerät，有着以下构造：

- 同心圆柱（Konzentrische Zylinder）
- 堆叠的**磁盘盘片**（**Platten**, k 层），每张盘片的两面都可以读写（2k 面）。
- 每张盘片上有多个**磁道**（**Tracks**），磁道的编号取决于 圆柱、盘片和面（Track = f(Zylinder, Platte, Seite)）。
- 每个磁道由多个**扇区**（**Sektoren**）组成，每个扇区大小为 512 字节。不过靠近磁盘中心的区域可能有更少的扇区（由于圆周较小）。
- **机械读写磁头**（**Schreib-/Leseköpfe**），每个盘片有两个读写磁头（上下各一个），总数为 2k。

构造图示：



![image-20250321130511294](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250321130511294.png)

![image-20250321130906927](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250321130906927.png)

早期会用到3个参数来确定需要读写的具体位置：

1. x Zylindernummer，Radius：确定是哪一个环；
2. y Kopfnummer，Höhe：确定是哪一张盘片的哪一面；
3. z Sektornummer pro Winkel：确定是哪个扇面；

![Hard_drive_geometry_-_German_-_2019-05-29.svg](https://raw.githubusercontent.com/archer-baiyi/Picture/main/Hard_drive_geometry_-_German_-_2019-05-29.svg.png)



由于早期 BIOS 和文件系统的设计的限制，只能访问有限的区域。

所以现在一般都使用**线性逻辑地址（lineare Adressierung logischer Blöcke）**，即给每个Sector编号（0，1，2，3，...）。



一个Sector里会包含以下信息：

- 前导信息（Präambel）： 包含同步位、磁道号和扇区号
- 数据（Daten）： 通常为512字节
- 错误校正码（ECC）： Error Correcting Code

![image-20250321201451040](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250321201451040.png)



Cylinder Skew: The offset distance from the start of the last track of the previous cylinder so that the head has time to seek from cylinder to cylinder and be at the start of the first track of the new cylinder.

Head Skew: The offset distance from the start of the previous track so that the head has time to switch from top of platter to bottom of platter and be at the start of the new track.

![image-20250321202751735](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250321202751735.png)

控制器通常一次读取整个磁道，这会需要足够的缓存来存储数据。但假如没有足够的缓存，则会采用交错的格式（ Formatierung mit Interleaving）：扇区不会按顺序排列的：1, 2, 3, 4, 5, 6, …, 15，而是交错排列的：1, 4, 7, 10, 13, 2, 5, 8, 11, 14, 3, 6, 9, 12, 15。这样子可以确保读取某个扇区 N ，将数据传输到主存后，扇区 N+1 会刚好移动到读写头下方，不需要再多等一圈。（因为磁盘好像是会一直转的）

为了避免磁盘损坏影响硬盘功能，会使用RAIS-System。（详细内容见[数据库的笔记](https://archer-baiyi.github.io/2025/03/11/TUM%E7%AC%94%E8%AE%B0/Datenbank-%E7%AC%94%E8%AE%B0/)）

![image-20250321210337675](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250321210337675.png)



读写磁头找到所需Sector的策略分3种：

1. FCFS
2. Shortest Seek First (SSF)
3. Elevator algorithm (Fahrstuhl-Algorithmus)





### **固态硬盘（SSD）**

SSD的全称为Solid State Drives，主要基于 (NAND) 闪存。

**SSD的一些特点：**

- 无机械部件（Keine beweglichen Teile）

  所以不会有机械磨损及其导致的故障，更耐振动、冲击等，访问速度更快。

- 仍然可能出现故障（Fehlfunktionen auch hier möglich），比如

  - 坏块，存储芯片故障（Bad blocks, Fehler in Speicherchips）
  - 反复读取可能影响相邻存储单元
  - 故障可能导致整个 SSD 无法读取
  - 数据恢复更加复杂

- 闪存写入次数有限（Flash-Speicher nur begrenzt oft schreibbar）

- 读取比写入快，顺序（sequentiell）写入比随机写入快



#### **SSD的基本工作原理**

SSD的初始状态是：

```
11111111 11111111 11111111 ...
```

写入的话会将1改成0：

```
01000111 01000010 01010011 ...
```

但如果想修改的话，不能只是修改一位，而是需要将这一整块重置然后再写入。

写入的大小最低为4KB，删除的大小最低为256KB，所以会导致所谓的**写入放大（Write Amplification）**的问题。

解决方式：这部分我没看懂，等看懂了再写。





### 时钟（Uhr,）

时钟会持续性计时。

硬件时钟（Hardware-Uhr (Chip)）的构成：

- Quarz als Taktgeber：

  石英晶体”作为时钟信号源，用来产生稳定的振荡信号（周期性电信号）作为“节拍”。

- 计数器（Zähler）：

  - 每个时钟节拍到来时，计数器的值会减1（dekrementiert）；
  - 当计数器值减到0时，就会触发一个中断（Interrupt）。

- Register zum (wiederholten) Setzen  des Zählers auf einen Startwert：

  可以通过软件来控制Interrupt的频率。

时钟/定时器的**任务**：

- 管理时间和日期（**Tageszeit** und **Datum** verwalten）
- 中断和切换进程（**调度**）（Prozesse unterbrechen und umschalten (**Scheduling**)）
- 测量某个进程的**计算时间消耗**（**Rechenzeitverbrauch** eines Prozesses messen）
- 向应用程序提供定时器功能（ Zeitschaltuhren den Anwendungen zur Verfügung stellen）
- **功能监控**（看门狗定时器）（**Funktionsfähigkeitsüberwachung** (watchdog timer)）
- 性能分析、监控、统计（Profiling, Monitoring, Statistik）



可以用链表的数据结构来管理定时事件：

![image-20250324210614723](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250324210614723.png)

所有时间均为相对时间（relativen Zeiten），也就是说每个节点的值代表相对于前一个事件的延迟（以 tick 为单位）。





### 定时器（Timer）

Timer（定时器）确实通常分为两种类型：

1. 硬件定时器（Hardware Timer）：

   系统通常有第二个可编程定时器。它在到时间的时候会触发Interrupt。但Interrupt的代价有点高，因为会引发上下文切换，并且可能会干扰程序正常运行。

2. 软件定时器（Software Timer）：

   这个的想法是只在系统处于内核态时检查定时器状态（nur dann aktiv werden, wenn System im Kernel-Mode ist），这样一来就不需要额外的上下文切换。在从内核模式切换到用户模式之前，操作系统读取实时时钟并检查是否有软件定时器已经超时，如有需要，处理相应的事件。

   它的缺点也很明显，就是延迟，不过大部分情况下都是可以接受的。





### 终端（Terminals）

终端是如何通过驱动程序将用户输入/输出转化为系统能够理解的数据流的：

- 上层：提供一个统一接口给操作系统的输入/输出子系统（Einheitliche Schnittstelle zum E/A-Subsystem des BS）
- 中层：解析输入和构造输出内容（Bearbeitungsmodul für Ein- und Ausgaben）
- 下层：与不同的物理硬件设备直接对应（Abbildung verschiedene physische Geräte），比如鼠标、显卡。



系统中的 terminal 是一个底层的字符设备机制，管理输入输出流、进程控制和驱动之间的协作。而我们平常用的cmd只是是 terminal的一种表现形式。
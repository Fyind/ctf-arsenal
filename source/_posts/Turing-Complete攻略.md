---
title: Turing Complete攻略
date: 2025-05-03 08:37:53
categories: 安全学习笔记
tags: 计算机架构
---

# Turing Complete攻略

## 基础逻辑电路

### 原力觉醒

点一下左上角，设置为关

### NAND

![Two Input NAND Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250410115842864553/frame_291.webp)

![image-20250503084731951](Turing-Complete攻略/image-20250503084731951.png)

### NOT

![NOT Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250410115643310672/frame_290.webp)

用 NAND 搭建 NOT 门

![image-20250503084945342](Turing-Complete攻略/image-20250503084945342.png)

### AND

![Two Input AND Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250409234459629891/file.webp)

可以用NAND和NOT门

![image-20250503085106469](Turing-Complete攻略/image-20250503085106469.png)

### NOR

![Two Input NOR Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250410115811732879/frame_292.webp)

![image-20250503085405018](Turing-Complete攻略/image-20250503085405018.png)

### OR

![image-20250503085757962](Turing-Complete攻略/image-20250503085757962.png)

### 高电平

始终输出高电平

![image-20250503090032244](Turing-Complete攻略/image-20250503090032244.png)

#### 德摩根定律

![image-20250503090122039](Turing-Complete攻略/image-20250503090122039.png)

### 第二刻

在第二时刻（第二列的真值表）输出高电平。

它很像AND的真值表，所以not下面那个

![image-20250503090450968](Turing-Complete攻略/image-20250503090450968.png)

### XOR

只有一样的值输出0

![XOR Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250410115911277691/frame_293.webp)

和官方解法不一样

![image-20250503091132934](Turing-Complete攻略/image-20250503091132934.png)

### 三路或门/与门

用两个接起来

![image-20250503091325605](Turing-Complete攻略/image-20250503091325605.png)

### XNOR

![XNOR Gate](https://media.geeksforgeeks.org/wp-content/uploads/20250410120225427216/frame_2993.webp)

![image-20250503091440498](Turing-Complete攻略/image-20250503091440498.png)

## 算数运算

### 二进制速算

找刚好比它小的那一个开始，往后选不断累加，如果超过了那就是后面的

### 成对的麻烦

有2个或以上高电平时候输出高电平

用XOR和AND表示加法个位和溢出位，只要有溢出就说明输出1，否则和下面的继续累加

![image-20250503093025795](Turing-Complete攻略/image-20250503093025795.png)

### 奇数个信号

奇数个1输出1

XOR基础题，XOR可以保留奇偶信息

![image-20250503093319172](Turing-Complete攻略/image-20250503093319172.png)

### 半加器

sum是xor，carray是and

![image-20250503095722801](Turing-Complete攻略/image-20250503095722801.png)

### 全加器

CAR位就是成对的麻烦那个思路

![image-20250503100713081](Turing-Complete攻略/image-20250503100713081.png)

### 信号计数器

简单加法器

有点复制，个位用奇数计数器，最高位用and算，中间用至少2个的判断器，在加一个xor，如果AND和OR同时1那么就是0，否则就是原来的，下面1上面0的情况不存在.

![image-20250503102027723](Turing-Complete攻略/image-20250503102027723.png)

### 加倍

就是位运算

![image-20250503102455941](Turing-Complete攻略/image-20250503102455941.png)

### 八位非/八位或

两个是一样的思路

![image-20250503104353060](Turing-Complete攻略/image-20250503104353060.png)

### 八位加法器

![image-20250503104230484](Turing-Complete攻略/image-20250503104230484.png)

### 负数

负数的二进制：反着点（绝对值-1）的二进制

### 相反数

先取反再加1

![image-20250503105940383](Turing-Complete攻略/image-20250503105940383.png)



## 存储器

### 循环依赖

电路输入依赖它的输出，随便找两个，把输出和输入连在一起就可以了，不要管报错直接核对

### 延迟线

延迟线可以把输入延迟一个时刻输出， 把两个延迟线连在一起就能延迟2个时刻

![image-20250503093929791](Turing-Complete攻略/image-20250503093929791.png)

### 奇变偶不变

把上个输出取反后输入

![image-20250503094656475](Turing-Complete攻略/image-20250503094656475.png)

### 1位取反器

如果反正引脚=1那么反转输入后输出，否则直接输出输入

观察真值表，发现就是异或

### 一位开关

上面的是控制是否导通的，下面是连接线

XOR：如果导通了就相同，没有导通就取反

![image-20250503103505754](Turing-Complete攻略/image-20250503103505754.png)

### 数据取反器

![image-20250503110134565](Turing-Complete攻略/image-20250503110134565.png)

### 总线

第一个选择输入设备，第二个选择输出设备

中间直接连起来，两个选择器分别选择输入和输出

![image-20250503110742706](Turing-Complete攻略/image-20250503110742706.png)

### 优雅存储

如果开了，就存当前的值。如果没开，就把旧的值再存一遍

![image-20250503111505900](Turing-Complete攻略/image-20250503111505900.png)

### 存储一字节

![image-20250503112656609](Turing-Complete攻略/image-20250503112656609.png)

### 一位解码器

看真值表就行

![image-20250503113001422](Turing-Complete攻略/image-20250503113001422.png)

### 三位解码器

二叉树思路，swc和AND是等价的，应该还能简化

![image-20250503120838671](Turing-Complete攻略/image-20250503120838671.png)

### 小盒子

空间比较小。先做个选择器。然后根据选择器连接到寄存器。Read和Write都有个开关

![image-20250503202719461](Turing-Complete攻略/image-20250503202719461.png)

### 计数器

![image-20250503203437224](Turing-Complete攻略/image-20250503203437224.png)

## 处理器架构

### 寄存器之间

解码寄存器编号分别到输入和输出

![image-20250503212453257](Turing-Complete攻略/image-20250503212453257.png)

### 逻辑引擎/算术引擎

![image-20250503204611566](Turing-Complete攻略/image-20250503204611566.png)

### 条件判断

![image-20250504092704568](Turing-Complete攻略/image-20250504092704568.png)

### 指令解码器

![image-20250504093144098](Turing-Complete攻略/image-20250504093144098.png)

### 计算单元

![image-20250504094527235](Turing-Complete攻略/image-20250504094527235.png)

### 程序

![image-20250504094751996](Turing-Complete攻略/image-20250504094751996.png)

### 立即数

![image-20250504095122687](Turing-Complete攻略/image-20250504095122687.png)

### 图灵完备

![image-20250504095600268](Turing-Complete攻略/image-20250504095600268.png)

## 编程

### 加5

![image-20250504100828943](Turing-Complete攻略/image-20250504100828943.png)

### 激光炮

``` asm
# 注释以 # 开头
# 示例代码：计算 1 + 1
MOV_R1_IN
MOV_R2_IN
add
MOV_R2_R3
add
MOV_R2_R3
add
MOV_R2_R3
add
MOV_R2_R3
add
reg3_to_out
```

### 密码锁

懒得二分，直接暴力

``` asm
# 如下定义跳转标签
label my_label
# 如下定义常数
const PI 3
# 此外，我们还推荐你
# 看一看手册的“汇编”页面
1
MOV_R1_R0
ADD
reg3_to_out
MOV_R2_R3

MOV_R3_IN
end
J3G0_R0

my_label
JMP_R0


label end
```

### 太空入侵者

``` asm
# 如下定义跳转标签
label my_label
# 如下定义常数
const PI 3
# 此外，我们还推荐你
# 看一看手册的“汇编”页面
5
MOV_OUT_R0
1
MOV_OUT_R0
1
MOV_OUT_R0
1
MOV_OUT_R0
1
MOV_OUT_R0
1
MOV_OUT_R0
3
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
5
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
label wait
3
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
5
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
3
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
5
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
MOV_OUT_R0
wait
JMP_R0
```

### 时间掩码

``` asm
MOV_R1_IN
3
MOV_R2_R0
AND
MOV_OUT_R3
```

### 迷宫

``` asm
label start

# while up==1 and left==1, turn left
label w1_beg
enter
exec
load_in
MOV_R2_R3
left
exec
enter
exec
load_in
MOV_R1_R3
right
exec
AND
w1_mid
J3G0_R0
w1_end
JMP_R0

label w1_mid
left
exec
w1_beg
JMP_R0

label w1_end

enter
exec
left
exec
go exec
right
exec
# check right
load_in
start
J3G0_R0
# if see=1
# 	to start
# else
enter
exec
go
exec
right
exec
start
JMP_R0

```

# Godot 游戏开发

``` shell
sudo add-apt-repository ppa:alexlarsson/flatpak
sudo apt update
sudo apt install flatpak
flatpak install flathub org.godotengine.Godot
```




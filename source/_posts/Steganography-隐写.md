---
title: Steganography 隐写
date: 2025-02-08 02:42:27
tags:
 - CTF笔记
---

# Steganography 隐写





### Image Check

#### 安装

``` shell
sudo apt install graphicsmagick-imagemagick-compat
```





### Binwalk

查看隐藏文件头

#### 解压文件

解压所有文件

``` shell
binwalk --dd=".*" xx.png
```



### 010Editor

#### 

#### dd 导出

``` text
unknownPadding[293756]		525EBh	47B7Ch	char	Fg: Bg:0x606060
```

这里skip填010 Editor里面的数就好了

``` shell
dd if=2weird.jpeg of=unknown bs=1 skip=337387 count=293756
```





### Checklist

https://georgeom.net/StegOnline/checklist

https://pequalsnp-team.github.io/cheatsheet/steganography-101

### 工具集

https://github.com/mmtechnodrone/SSAK

https://github.com/DominicBreuker/stego-toolkit/tree/master


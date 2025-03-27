---
title: InsomniHACK CTF 2025 Writeup
date: 2025-03-15 23:27:19
tags:
	- writeups
math: true
---
# InsomniHACK CTF 2025 Writeup

## Forensics

### v0l4til3

给定了一个win10的内存mem文件, 求 `flag_user` 的密码hash.

这个mem文件是用vodatility分析的，这里使用vodatility3进行分析。

首先windows的密码是存在 `windows32\config\SAM` 这里以加密的形式存在的。密钥是 `windows32\config\SYSTEM` 里面的

提取这两个文件后，可以用 mimikatz 这个工具来提取

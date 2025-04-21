---
title: DawgCTF 2025 Keeping on Schedule
date: 2025-04-21 17:05:42
categories: [CTF, Forensics]
tags: [Forensics, 注册表]
---

# Keeping on Schedule

One of our computers on the company network had some malware on it. We think we cleared of the main payload however it came back. Can you check for any signs of persistence? We are able to provide you a copy of the registry, the sooner the better!

*For any registry related challenges, make sure to not overwrite you machines used registry as it is a sensitive system.*

Download Challenge File(s): [Click Here](https://github.com/UMBCCyberDawgs/dawgctf-sp25/tree/main/Keeping on Schedule)

给定了一些注册表 `SOFTWARE`, `HARDWARE`, `SAM`, `SYSTEM`

## Writeups

可以用 RegRipper 来分析注册表

下载：https://github.com/keydet89/RegRipper4.0

``` shell
rip.exe -r SOFTWARE -p tasks | grep Dawg
```

用 task 插件分析，然后就有flag了

``` shell
DawgCTF{Fun_W1th_T4sks}
```

之前试了其他插件 run 之类的，没有分析出什么东西


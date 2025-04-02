---
title: HTB-Full-Stack-Conf Writeup
date: 2025-04-02 13:17:31
categories: 
  - CTF
  - Web
tags: [Web,HTB,Writeup,Injection,JavaScript,注入]
excerpt: ""
---


## **题目描述**

![image-20250330124156592](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330124156592.png)

（无附件）

## **观察**

打开网页：

![image-20250330124242294](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330124242294.png)

## 渗透

因为提示用alert，并且题目描述里提到了JavaScript，所以直接尝试最简单的JavaScript注入：

```javascript
<script>alert('1');</script>
```

![image-20250330124411860](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330124411860.png)

得到flag：`HTB{p0p..p0p..p0p...alert(1337)}`  。

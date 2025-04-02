---
title: HTB-sanitize Writeup
date: 2025-04-02 13:17:04
categories: 
  - CTF
  - Web
tags: [Web,HTB,Writeup,Injection, SQL Injection, SQL]
excerpt: ""
---


## **题目描述**

![image-20250328201424018](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328201424018.png)

（无附件）

## **观察**

打开网页：

![image-20250328201530601](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328201530601.png)

随便输入个username和password会看到下方有一段SQL代码：

![image-20250328201620593](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328201620593.png)

## 渗透

猜测网页的登录逻辑是这样的：如果当前select成功（也就是说能在数据库里找到当前输入的账号信息），那么就可以登录成功。

所以直接SQL Injection，在username一栏输入

```
admin' --
```

，然后password那一栏输入任意内容（比如说1），就可以得到flag：`HTB{SQL_1nj3ct1ng_my_w4y_0utta_h3r3}`。

![image-20250328201841519](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328201841519.png)

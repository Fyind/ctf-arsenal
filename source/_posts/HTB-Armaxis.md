---
title: HTB Armaxis
date: 2025-04-02 13:51:28
categories:
 - [CTF, Web]
tags:
 - [IDOR, markdown]
---

这个网站的reset password会把token发送到email里面，但是这个token可以重置任意的email。我们从 `database.js` 里面得知管理员的账户是 `admin@armaxis.htb` , 于是我们用 `test@email.htb` 申请一个账户并且拿到重置密码的token，然后用hackbar发送一个reset-password的请求，可以在 `index.js` 里面看到这个，它会读取post的三个参数并且重置密码。这样我们重置了管理员账户的密码登录上去。

第二步是，disbute weapon里面会有个markdown，这个markdon可以读取本地的文件。因为 `markdown.js` 里面的 parse函数，会先把filecontent下载下来，然后用base64编码，于是我们构造payload是

``` md
![img](file:///flag.txt)
```

这样的图片，然后显示源代码拿到base64，解码得到flag

``` shell
HTB{m4rkd0wn_bugs_1n_th3_w1ld!}
```

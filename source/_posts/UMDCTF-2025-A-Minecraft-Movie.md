---
title: UMDCTF 2025 A Minecraft Movie
date: 2025-05-03 23:24:31
categories: [CTF, Web]
tags: [Writeup, Web, HTML, CSRF]
---

题目给了2个网站

### [a-minecraft-movie.challs.umdctf.io](https://a-minecraft-movie.challs.umdctf.io/)

抓包：

* index-DyRpPGax.js： 没法看
* index-BSu8rXO4.css
* single-file-hooks-frames.js 没法看
* top-posts: 显示的内容

点一个会跳转到一个youtube视频

点Like显示 Not authenticated

2个按钮：

Create a Post: 有 Title输入框和Content输入框

Submit Post显示Not authenticated

有Login和Regiser

* testtest : already exist

* testtest1

注册登录：

有 Account：Account Summary

Username: testtest1

> Current Session Number: undefined
>
> Your Posts
>
> You haven't posted anything yet.

登录后点Like没什么用

CHICKEN JOCKEY可以点Like，让数字变化，Like可以重复点

that's a legend可以点Like，

登陆后，自己可以发布Post

* create-post 请求

#### XSS点

post内部写入 `<input>` 会解析

### [a-minecraft-movie-admin.challs.umdctf.io](https://a-minecraft-movie-admin.challs.umdctf.io/)

这个里面可以输入PostID，之后Admin可能可以访问。

## 分析

可能思路：

* 通过XSS登录上Admin，Admin页面有Flag



#### Payload

`<script>document.location="http://requestbin.whapi.cloud/woqsw6wo"</script>`

这个似乎没什么用

```html
<input autofocus onfocusin=confirm()>
```

这个也没有用

``` html
<img src="http://requestbin.whapi.cloud/woqsw6wo" onerror="fetch("http://requestbin.whapi.cloud/woqsw6wo")">
```

这个不会弹出窗口，把onerror过滤了

可能可以用XSS工具扫描？

``` html
<img src="http://requestbin.whapi.cloud/woqsw6wo" >
```

这个有用！

但是把对应的id发给admin，Admin点击了它！！



### index-DyRpPGax.js

也就是说：

你需要想办法让 **Admin用户访问你的Post**，触发你写进去的**XSS**，让Admin的浏览器执行你的JS，**读取 `/me` 接口拿到flag**，然后把flag发回给你！

## Writeup

这个题有几个思路：

首先可以用 `12341234` 这个用户名和密码登录拿到flag，因为账号是共享的

第二个可以 CSRF, 用img的链接转到其他地方，然后再其他地方写个XSS提交POST点赞请求

第三个可以用HTML通过autofocus写一个强制点赞的标签。因为模拟浏览器会模拟鼠标点击。所以可以这样。

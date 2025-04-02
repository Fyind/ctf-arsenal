---
title: HTB Flag Command
date: 2025-04-02 13:49:15
categories:
  - [CTF, Web]
tags:
  - 开发者工具, javascript
---

# HTB Flag command

从开发者工具里面抓包，找到游戏的 `main.js` ，里面发现有个 `fetchOptions` 里面通过发送请求，得到所有可以执行的命令。然后在开发者工具的抓包里面看到 `options` 就是这个请求，我们打开看看请求返回的内容，在里面得到看到一个secret的命令 `Blip-blop, in a pickle with a hiccup! Shmiggity-shmack`。 在游戏start后，输入这个命令，就可以得到flag了

``` shell
HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}
```




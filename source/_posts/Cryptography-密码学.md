---
title: Cryptography 密码学
date: 2025-02-08 20:25:34
tags:
 - CTF笔记
 - Cryptography
---

# Cryptography 密码学



## 古典密码



### Rabbit密码

需要一个密码, 解密一个类似base64的

> BITSCTF2025: The most wanted lagomorph

``` txt
BITSCTF{f3rb_1_kn0w_wh47_w3_4r3_60nn4_d0_70d4y}
```

加密 `key=dennis`，变成

``` txt
U2FsdGVkX1+Kci2LQvPTy06ga66qMTDgoOip6SxH1t7EreImxWCP3RarTyRTU2k3Nrd4vChzcXYKqPZSyl3T
```

### 梅森旋转算法

python 里的 `random` , C++ 里的  `std::mt19937` 都是这个算法, 梅森旋转算法（Mersenne Twister Algorithm，简称 MT）

>  参考博客:  https://liam.page/2018/01/12/Mersenne-twister/

如果知道若干个连续生成的随机数，就可预测下一个

> [BITSCTF2025: Praise Our RNG Gods](https://cr4zyp1x3l.netlify.app/bitsctf2025-write-up/)

#### mersenne-twister-predictor

使用 `mt19937predictor` 这个python包

> [MT19937介绍 BLOG](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng#python-import-random-mersenne-twister)

先pip安装

``` shell
pip install mersenne-twister-predictor
```

使用：

``` python
import random
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()

for _ in range(624):
    x = random.getrandbits(32)
    predictor.setrandbits(x, 32)  # Submit samples here

# When enough samples are given, you can start predicting:
assert random.getrandbits(32) == predictor.getrandbits(32)
```




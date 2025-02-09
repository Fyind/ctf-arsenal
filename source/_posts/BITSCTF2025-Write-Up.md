---
title: BITSCTF2025 Write Up
date: 2025-02-09 15:39:08
tags:
 - writeups
---

# BITSCTF2025 Write Up

## Cryptography

### The most wanted lagomorph

给了一串密文

``` text
簾簿 簾簽 簽籶 簽籀 簿簼 簼簻 簾簻 簽籁 簾簿 簿米 籀簽 簾籂 簽米 簾簼 籀簽 簽籴 簾籂 簼簻 簿籵 籀籂 簾簽 簽簿 簽簿 簼簻 簾簾 簽簿 簾簻 簼簾 簽米 簽簽 簾籶 簿籲 簾籂 簾簽 簾籂 簼簻 簿簼 簾簾 簼簺 簾簾 簾簻 簽籀 簿簽 籀簿 簾簽 簼簻 簿籴 籀籀 簽籲 簿籴 簽籲 簼簽 簾簼 簽簽 簽簿 簼簹 簽籲 簼簹 簾簿 籀籂 簾籶 簾簾 簿籴 籀簽 簿簾 簽簿 簿簽 簽簽 簾簾 簽簽 簽籲 簾簼 簾籂 簾籁 簽籶 簾簾 簿簾 簾簿 簽籶 簾簾 簾簿 簾簽 簽籶 籀簻 簽米 簼簹 簼簾 籀籂 簾籶 簽簽 簾簻 簼簻 簾簺 簼簻 簿籁 簼簿 簾籂 簼簺 簿籁 簾籶 簾簼 簼簼 簽簿 簾簺 簾籀 簿籴 簽籲 簼簾 簿簻 簽簽 簽籲 簾簾
```

这里可以想到  `ROT8000`  加密，首先做一遍 ROT8000

``` txt
56 54 4m 47 63 32 52 48 56 6j 74 59 4j 53 74 4k 59 32 6l 79 54 46 46 32 55 46 52 35 4j 44 5m 6i 59 54 59 32 63 55 31 55 52 47 64 76 54 32 6k 77 4i 6k 4i 34 53 44 46 30 4i 30 56 79 5m 55 6k 74 65 46 64 44 55 44 4i 53 59 58 4m 55 65 56 4m 55 56 54 4m 72 4j 30 35 79 5m 44 52 32 51 32 68 36 59 31 68 5m 53 33 46 51 57 6k 4i 35 62 44 4i 55
```

发现它很像Hex, 但是 abcdef 变成了 ijklm

先做一次 ROT13

``` txt
56 54 4z 47 63 32 52 48 56 6w 74 59 4w 53 74 4x 59 32 6y 79 54 46 46 32 55 46 52 35 4w 44 5z 6v 59 54 59 32 63 55 31 55 52 47 64 76 54 32 6x 77 4v 6x 4v 34 53 44 46 30 4v 30 56 79 5z 55 6x 74 65 46 64 44 55 44 4v 53 59 58 4z 55 65 56 4z 55 56 54 4z 72 4w 30 35 79 5z 44 52 32 51 32 68 36 59 31 68 5z 53 33 46 51 57 6x 4v 35 62 44 4v 55
```

发现变成了 vwxyz, 可以用 Atbash Cipher 就变回 abcde了

``` txt
56 54 4a 47 63 32 52 48 56 6d 74 59 4d 53 74 4c 59 32 6b 79 54 46 46 32 55 46 52 35 4d 44 5a 6e 59 54 59 32 63 55 31 55 52 47 64 76 54 32 6c 77 4e 6c 4e 34 53 44 46 30 4e 30 56 79 5a 55 6c 74 65 46 64 44 55 44 4e 53 59 58 4a 55 65 56 4a 55 56 54 4a 72 4d 30 35 79 5a 44 52 32 51 32 68 36 59 31 68 5a 53 33 46 51 57 6c 4e 35 62 44 4e 55
```

然后把hex转成字符

``` txt
VTJGc2RHVmtYMStLY2kyTFF2UFR5MDZnYTY2cU1URGdvT2lwNlN4SDF0N0VyZUlteFdDUDNSYXJUeVJUVTJrM05yZDR2Q2h6Y1hZS3FQWlN5bDNU
```

看看base64

``` txt
U2FsdGVkX1+Kci2LQvPTy06ga66qMTDgoOip6SxH1t7EreImxWCP3RarTyRTU2k3Nrd4vChzcXYKqPZSyl3T
```

然后标题是 The most wanted lagomorph, google搜索`"The most wanted lagomorph"`  后是 `dennis` 的兔子

有一个Cipher叫 Rabbit Cipher , 把 dennis 作为密码可以用 CapfEncoder 解密

``` txt
BITSCTF{f3rb_1_kn0w_wh47_w3_4r3_60nn4_d0_70d4y}
```

## Reverse Engineering

### Praise Our RNG Gods

Given is a Python Byte Code
```
```0 LOAD_CONST 0 (0)
2 LOAD_CONST 1 (None)
4 IMPORT_NAME 0 (random)
6 STORE_NAME 0 (random)

...

14 LOAD_CONST 3 (322420958)
16 BINARY_OP 12 (^)
18 BINARY_OP 5 () 
20 LOAD_CONST 4 (2969596945L)
22 BINARY_OP 5 ()
24 STORE_FAST 1 (password)

26 LOAD_FAST 1 (password)
28 RETURN_VALUE```

```

`BINARY_OP 5 () ` 这里应该是乘法，用过验证回复的数字得到

Using a website https://www.codeconvert.ai/assembly-to-python-converter
,we can decode it to python code.

``` python
import random
import os

seed = int.from_bytes(os.urandom(8), "big")
random.seed(seed)

flag = "REDACTED"

def generate_password():
    global i
    password = (random.getrandbits(32) ^ i ^ 195894762) ^ 322420958
    return password

print("Vault is locked! Enter the password to unlock.")

i = 1

while True:
    password = generate_password()
    attempt = input("> ")

    if not attempt.isdigit():
        print("Invalid input! Enter a number.")
        continue

    difference = abs(password - int(attempt))

    if difference == 0:
        print("Access Granted! Here is your flag:")
        print(flag)
        break

    print(f"Access Denied! You are {difference} away from the correct password. Try again!")
    i += 1

```

The problem is, the password shoud be a 32bit integer,however when we connnect to the `nc chals.bitskrieg.in 7007` , it replies a 64 bit integer.

UPD: Found it, the result was wrong. The actual generate password should be

``` python
def generate_password():
    global i
    password = random.getrandbits(32) *  ( i ^ 195894762 ^ 322420958) * 2969596945
    return password
```

The solution should be that the random library of python
uses Mersenne Twister Algorithm, which is not secure.
If we know some consecutive random numebrs generated,
we can predict the next one.

Reference: (In Chinese) https://liam.page/2018/01/12/Mersenne-twister/

还有另一个方便的方法, 使用 `mt19937predictor` 这个python包

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


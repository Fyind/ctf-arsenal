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



## AES-CBC

### Decryption Oracle

#### 得到IV

在AES的CBC模式下，如果有Decryption Oracle，那么可以得到IV的值, 

> 参考：https://cedricvanrompay.gitlab.io/cryptopals/challenges/27.html

首先发送3个block, $C_1, C_2,C_3$

其中 $C_2=\text{0x00}$ , $C_3 = C_1$ 那么解密得到的第一个是 $dec(C_1) \oplus IV$ , 第三个是 $dec(C_1)$ 然后它们异或一下就可以了

Python 例子

``` python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def xor(a,b):
    return bytearray([x ^ y for (x,y) in zip(a,b)])

key = b"A" * 16
iv = b"B" * 16
print(f"{iv.hex() = }")

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad((b"C" * 16) * 3, AES.block_size))

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext[:16] + (b"\x00" * 16) + ciphertext)

iv = xor(plaintext[:16], plaintext[32:48])
print(f"{iv.hex() = }") # iv.hex() = '42424242424242424242424242424242'
```

## RSA

首先生成 $p,q$ 两个大质数, 计算

* $N=p \cdot q$
* $\varphi(n)=(p-1)\cdot (q-1)$

然后选择 $e$ 作为公钥, 计算
$$
d = e^{-1}\bmod \varphi(n)
$$
是私钥

#### 加密

对于 message $m$
$$
c= m^{e} \bmod n
$$

#### 解密

对于 ciphertext $c$
$$
m = c^{d}\bmod n
$$
正确性：
$$
m=(m^e)^d=m \bmod n
$$

### 结论

#### 可枚举 z

$$
e\cdot d \equiv 1\bmod \varphi(n)
$$

所以 
$$
e\cdot d=1+z\cdot \varphi(n)
$$
这个 $z$ 在 $[0,e]$ 之间

> BITSCTF2025 Noob RSA returns

## ECDSA

全称是 Elliptic Curve Digital Signature Algorithm. 

在椭圆曲线 
$$
y^2 \equiv x^3 + ax +b \bmod p
$$
其中 $n \times G = O$

密钥包括私钥和公钥 $(d_A, Q_A)$ 私钥是 $d_A$ 公钥是 $Q_A$ 

$d_A$ 是 $[1,n-1]$ 的整数, $Q_A = d_A \times G$ 

### 签名

输入消息 $m$ , 计算 $z = HASH(m)$ , 随机生成 $k = CRNG(1,n-1)$ 然后计算 $k \times G = (x_1, y_1)$
$$
r = x_1 \bmod n \\
 s= k^{-1}(z + rd_A) \bmod n
$$
签名是 $(r,s)$ 

### 验证签名

已知 $(r,s), e, Q_A$  先计算
$$
u_1 =zs^{-1} \bmod n \\
u_2 = rs^{-1} \bmod n
$$
然后计算
$$
u_1 \times G + u_2 \times Q_A \\
= (zs^{-1})\times G+(rs^{-1})\times (d_A \times G) \\
= (z+rd_A) s^{-1} \times G \\
= k \times G = (x_1,y_1)
$$
  如果 $r$ 和 $x_1$ 一样，那么签名合法

### Python 库 ecdsa

首先

``` shell
pip install ecdsa
```

签名和验证

``` python
import ecdsa
from hashlib import sha256
import random

private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256)
dA = private_key.privkey.secret_multiplier
public_key = private_key.verifying_key

print(dA) # 打印 k
print(public_key.pubkey.point.to_bytes()) # 得到点

k = random.randint(1, ecdsa.SECP256k1.order - 1)  
signature = private_key.sign(b"First msg",hashfunc=sha256 ,k=k)

vk = private_key.get_verifying_key()
sig = private_key.sign(b"Hello msg")

vk.verify(sig, b"Hello msg")
vk.verify(signature, b"First msg") # 如果报错说明验证错误

# 手动签名1:
priv_key = ecdsa.SigningKey.from_secret_exponent(dA, curve=ecdsa.SECP256k1)
priv_key.sign(b"Hello msg",k=12)
print(sig)

# 得到 r,s
r = int.from_bytes(sig[:32])
s = int.from_bytes(sig[32:])
z = int.from_bytes(sha256(b"Hello msg").digest()) % ecdsa.SECP256k1.order
```






---
title: x3ctf2025 Write Up
date: 2025-02-03 17:39:31
tags:
  - writeups
---

# x3ctf Write Up



## 1. Misc

### p11n-trophy（签到题）:

题目描述：
![image-20250127165738440](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127165738440.png)

我们首先会得到这样一份证书：

![trophy](https://raw.githubusercontent.com/Lycorisby/Picture/main/trophy.png)



第一题签到题的答案就是证书下面正中间的“This certificate does not grant the rank of Master"。

### trophy-plus + trophy-plus64:

这两道目描述一模一样

### ![image-20250127165834982](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127165834982.png)

![](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127165903642.png)

其中一个flag是藏在certificate周围一圈的位置：

![image-20250127170254595](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127170254595.png)

![image-20250127170344389](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127170344389.png)

人工将这些内容识别，再翻译成二进制然后解码就会得到flag
```python
def decode_binary(content, mapping):
    # Convert content to binary using the mapping
    binary_str = ''.join(mapping[char] for char in content if char in mapping)

    # Split the binary string into 8-bit chunks
    bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]

    # Convert each 8-bit chunk to a character
    decoded_text = ''.join(chr(int(byte, 2)) for byte in bytes_list if len(byte) == 8)

    return decoded_text

# Input string
c_1 = "MVVVVMMMMMVVMMVVMVVMMMVVMVVVVMVVMVVM VMMV MV MVVVVVMVVMM VMM MMVVMMMV"
c_2 =   "MVVMM VMMMVVMVVVMMM VMMVVVMVVVMV MMM VMVVVVVMVVM VMVVMVVMVVVMMMVVMMMMMVVVMVVVM VMVVVVV"
c_3 = "VMMMVVMMM VMMMVVMVVVVVM VMMV MMVVVMMMMMVVMMMVVMMVVMVVVVVM VMMM VMMVVMVVMMVVMMVVMMVVVM VMV MVVVMVVVVVM VM VM VMMVVMMV MMMVVMVVVVVMV MMMV MMVVMMMVVMVVM VMV MVVVMMMMMVVMMVVMMMVVMVVVVVM VMV MVVMVVMMVVMVVVM VMVVMVVM"
reversed_c_3 = c_3[::-1]
c_4 = "MMV MMVVMMMMMVVMMVVMMMVVMMVVVMVVMVVMMVVMMVVVVVM VMV MMVVVVMMV MMVVVMMM VMVVMMMVVVMVVM"
reversed_c_4 = c_4[::-1]
c_5 = "MMVVMMM VMVVMVVVMMVVMMVVVM VMVVVVVMVVMVVMMMMVVMMMMMVVMVVMMMVVVVVMV"

# mapping = {'M': '0', 'V': '1'}

mapping1 = {'M': '1', 'V': '0'}
mapping2 = {'M': '0', 'V': '1'}


# print(decode_binary(c_1, mapping2)+decode_binary(c_2, mapping2) + decode_binary(c_3, mapping2) + decode_binary(c_4, mapping2) + decode_binary(c_5, mapping2) )
print(decode_binary(c_1, mapping2)+decode_binary(c_2, mapping2) + decode_binary(reversed_c_3, mapping2) + decode_binary(reversed_c_4, mapping2) + decode_binary(c_5, mapping2) )

# 输出结果：x3c{i_d1dn't_kn0w_mvm_c0uld_be_us3d_f0r_b1n4ry_3nc0d1ng_l0l}

```

另外一个flag则是藏在右下角的勋章里：
![屏幕截图 2025-01-25 210727](https://raw.githubusercontent.com/Lycorisby/Picture/main/屏幕截图 2025-01-25 210727.png)

人工将这些内容识别出来然后用base64进行解码即可。

内容大概为：

```
-----BEGIN CERTIFICATE-----
MIIDyjCCAlCgAwIBAgISBKmF/S4TYSXpTzcor9eZJ/GrMAoGCC
qGSM49BAMDMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEwlMZXQn
cyBFbmNyeXB0MQswOQYDVQQDEwJFNjAeFw0yNTAxMDYyMDM2MD
FaFw0yNTA0MDYyMDM2MDBaMEAxPjA8BgNVBAMMNXgzY3ttdTV0
X2IzX2Zlbl90eXAxbmdfdGgxcl9ieV9oNG5kXzEzNzUxMDUzMD
QyNDgzNjF9MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcYu3
flnEI2dttI5lQQmzRld72SDdBqCDtfto9pg5t/NFFIolkY8W8C
ryM9XlJEx3NAOGTgBoeUNTuWgiCseQeaOCAjYwggIyMA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQ
UHAwIwDAYDVR0TAQH/BAIwADAdBgNVRQ4EFgQUrbtyF28hjw8o
IqwXpakw8t7J9jQwHwYDVR0jBBgwFoAUkydGmAOpUWiOmNbEQk
jbI79YlNIwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVo
dHRwOi8vZTYuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dH
A6Ly91Ni5pLmxlbmNyLm9yZy8wQAYDVR0RBDkwN4IleDNje2ll
NXRfYjNfZnVuX3R5cDFuZl90aDFzX2J5X2g0bmRfMTM3NTEwNT
MwNDI0ODM2MX0wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEDBgor
BgEEAdZ5AgQCBIH0BIHxAO8AdQB9WR4S4XggexxhZ3xe/fjQhl
w0oE6VnrkDL9kOjC55uAAAAZQ9inTEAAAEAwBGMEQCIENpWRg9
8SQo5JdzyjgnyFeUY0WnNVzn5NkdDA3bzeKbAiBsAkk3fe5esm
7A0efsLN/EyFjEK/NBGqYxgOucgZheQwB2ABNK3xglmEIjeAxv
70x6kaQWtyNJzlhXat+u2qfCq+AiAAAB1D2KdXoAAAQDAEcwRQ
IgBfU4pkiNyNsl+I6skjXz6qqu+mNoI4JvtDsoYxoI+ZoCIQCR
iMQSCEwahN0ImXu3cwDeyM+AbNeve0VgSLMSUBdxvTAKBggghk
jOPQQDAwNoADBlAjEAvxa6nSpUMl7NuDB/+LJfzTskR498vLoe
tnZuHo14J6d9zuFRGQ8Dk4w2aQNsbuVsAjB9fE6GJYBiebb4aH
u/J2amych3KP//D951/CdmiV5PKZqXWWdpaQZL+pbmsXRa8rM=
-----END CERTIFICATE-----
```

会有一些误差，所以最后提交flag时需要多试几次。



### foundations （Osint）：

题目描述：

![image-20250127171132744](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127171132744.png)



使用https://archive.org/来搜索这个比赛网站的历史纪录内容

![image-20250127171253342](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127171253342.png)

可以在这里发现最早的纪录是在2024年7月14日：

![image-20250127171328034](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127171328034.png)

点进去会发现：
![image-20250127171419684](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127171419684.png)

x3CTF{m4yb3_w3ll_m4ke_4_ch4ll3nge_0u7_0f_7h1s}



### mvm：

![image-20250127171618699](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127171618699.png)

打开下载文件会得到
```
MMVMVMVVMMVMVMVVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVMVMMVMVVVMMMVMVMVVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVMVVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMMVMVMVVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVVVMMMVVVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVVMMMVMVVMVMMVMVVMVMVMVVMVVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVMVVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMVMVVMVVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMMVVVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVMMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVMVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVVMMMVMVVMVMMVMVVVMMMVMVMVVMMVMVMVVMVMVVMVVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVMVVMMVMVVVMMVMVVMVVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVMVVMMVMVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVMVVMMVMVVVMMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVMVMMVMVVVMMMVVVVVMMMVMVVMVMMVMVVMVMVMVVMVVMMVMVVMVMMVMVVMVMMVVVVVMMMVMVMVVMMVMVMVVMMVMVMVVMMVVVVMMMVMVVVMVMMVVVVVMMMVMVVVM

```

跟之前一样，将其转成二进制再解码会得到

```
++[---------->+<]>.+++++++++.---------.-[->+++++<]>-.+[----->+<]>+.+++++++++.---------.-[---->+++++<]>.+[--->++<]>++.>-[--->+<]>---.--[->++++<]>+.++++++++.+++++.[-->+++++++++<]>.[--->+++++<]>.++++++++++.++++++++++++.-[----->+<]>.>-[--->+<]>.-[----->+<]>-.++++++++.------.-.++[->+++++<]>+.[----->++++<]>+.+++++++++.---------.>--[-->+++<]>.
```

很显然这是Brainfuck,所以找个在线的intepreter运行一下就可以得到flag：


![image-20250127172039130](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127172039130.png)

MVM{MVM_BRAIN_IS_FUCKED_MVM}



### count-the-mvms

主要是数背景的mvm个数，发现它们的像素点是一样的。所以写个图像匹配脚本即可.

首先要把pdf转换成 png，推荐 adobe acrobat 

``` python
import cvlib
# cvlib 是自己写的库
im = cvlib.read_img("certificate_h4tum.png")
sim = cvlib.subrectimg(im, 605, 516, 837, 665)
sim2 = cvlib.subrectimg(sim, 44, 32, 79, 48)
mvm = cvlib.subrectimg(sim2, 2, 2, 32, 13)
print("read success")


def match(im, x,y):
    if x+len(mvm) > len(im):
        return False
    if y+len(mvm[0]) > len(im[0]):
        return False
    
    for i in range(len(mvm)):
        for j in range(len(mvm[i])):
            [r,g,b] = mvm[i][j]
            [ri,gi,bi] = im[x+i][y+j]        
            if r != ri or g != gi or b != bi:
                return False
    return True
            
def count_matches(im):
    cnt = 0
    for i in range(len(im)):
        print(i)
        for j in range(len(im[i])):
            if match(im, i,j):
                cnt += 1
                j += len(mvm[0]) - 1
    return cnt

print(count_matches(im))
print("finish")

```



## 2. Crypto

### man-vs-matrix:

题目描述：

![image-20250127172638257](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250127172638257.png)

打开下载文件会看到：

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long

class RNG:

    def __init__(self, seed):
        self.p = next_prime(2**24)          # 16777259
        self.F = GF(self.p)
        self.M = matrix(self.F, 3,3, [bytes_to_long(seed[i:i+3]) for i in range(0, len(seed), 3)])
        self.state = vector(self.F, map(ord, "Mvm"))        # [77, 118, 109]
        self.gen = self.F(2)

    def get_random_num(self):
        out = self.M * self.state

        for i in range(len(self.state)):        # len = 3
            self.state[i] = self.gen**self.state[i]

        return out * self.state

flag = b"MVM{???????????????????????????}"
seed = flag[4:-1]               # 27位，27/3=9

rng = RNG(seed)
samples = []

for i in range(9):
    samples.append(rng.get_random_num())

print(f"{samples = }")
# samples = [6192533, 82371, 86024, 4218430, 12259879, 16442850, 6736271, 7418630, 15483781]

```

是几个随机数的生成器（RNG），但生成逻辑非常简单。

每次会计算
$$
(M \cdot state) \cdot new\_state
$$
(括号外的乘法是内积。在sage里，矩阵与矩阵/向量的乘法和向量与向量的内积都是用*)。并且有
$$
new\_state[i] = 2^{state[i]}.
$$
这里的初始state是已知的，所以我们只需要建立一个9元1次线性方程组即可。

我们可以写一段sagemath的代码来通过解方程逆推出matrix以及flag内容：

```python
p = 16777259		# = next_prime(2**24)
F = GF(p)

samples = [6192533, 82371, 86024, 4218430, 12259879, 16442850, 6736271, 7418630, 15483781]

# 初始状态 S0 = [77, 118, 109]
S0 = vector(F, [77, 118, 109])

def next_state(st):
    return vector(F, [F(2)^int(x) for x in st])

# 求出 S0 ~ S9
S = [None]*10
S[0] = S0
for i in range(1, 10):
    S[i] = next_state(S[i-1])

# 构造线性方程组 X * M_vec = Y
X = matrix(F, 9, 9)
Y = vector(F, 9)

for i in range(9):
    row_coeffs = []
    # M_vec 的顺序: M[0,0], M[0,1], M[0,2], M[1,0], ..., M[2,2]
    for k in range(3):
        for j in range(3):
            row_coeffs.append(S[i][j] * S[i+1][k])
    X[i] = row_coeffs
    Y[i] = samples[i]

# 求解 9 个未知量
M_vec = X.solve_right(Y)
M_mat = matrix(F, 3, 3, M_vec)
print("Recovered M =")
print(M_mat)


# 将 3x3 矩阵以行优先顺序（row-major）展开成 9 个元素
# 对应当初 [bytes_to_long(seed[0:3]), bytes_to_long(seed[3:6]), ..., bytes_to_long(seed[24:27])]
m_ints = []
for i in range(3):
    for j in range(3):
        # Sage 返回的是 GF(p) 的元素，先转成普通整型
        val = int(M_mat[i, j])
        m_ints.append(val)

# 将每个 val 转成 3 字节后依次拼接
seed_recovered = b"".join(val.to_bytes(3, "big") for val in m_ints)

# 最终还原 flag = b"MVM{" + seed_recovered + b"}"
flag_recovered = b"MVM{" + seed_recovered + b"}"

print("Recovered seed  =", seed_recovered)
print("Recovered flag  =", flag_recovered)

#最后得到的结果：
# Recovered M =
# [7090542 3355762 6252149]
# [5137236 3223662 3497780]
# [7484255 7174495 6698102]
# Recovered seed  = b'l1n34r_fuNcT10n5_4r3_my_f4v'
# Recovered flag  = b'MVM{l1n34r_fuNcT10n5_4r3_my_f4v}'
```


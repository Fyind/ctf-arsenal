---
title: Bronco CTF Write Up
date: 2025-02-17 00:21:42
tags:
---

# Bronco CTF Write Up



[TOC]



## Beginner



### Break the Battalion

![Break_the_Battalion](https://raw.githubusercontent.com/Lycorisby/Picture/main/Break_the_Battalion.png)

这道题我们会拿到一份ELF文件，我们用IDA打开它会看到

![image-20250216231337295](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216231337295.png)

可以发现，这个程序的核心内容是encrypt，所以我们查看一下它的内容：
![image-20250216231507284](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216231507284.png)

写一段python便可以简单得知输入什么内容最后会输出“brigade”：

```python
def decrypt(encrypted):
    return ''.join(chr(ord(c) ^ 0x50) for c in encrypted)

encrypted = "brigade"
original_input = decrypt(encrypted)
print(f"Original input: {original_input}")

# Original input: 2"97145
```

所以flag为：

```
bronco{2"97145}
```

(吐槽一下，这个flag的内容真的非常奇怪，一般都是会带点正常单词的。)



### Simon Says

![image-20250216231818653](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216231818653.png)

这道题我们会拿到这样一张图片：

![simon](https://raw.githubusercontent.com/Lycorisby/Picture/main/simon.png)

并没有任何有用的内容。根据题目描述我们猜测这道题用了LSB隐写，所以用Stegsolve打开图片便可得到：


![simon](https://raw.githubusercontent.com/Lycorisby/Picture/main/simon.bmp)

flag为：

```
bronco{simon_says_submit_this_flag}
```





### Too Many Emojis

这道题我们会得到一串emoji内容：
![emojis](https://raw.githubusercontent.com/Lycorisby/Picture/main/emojis.png)

因为知道flag的格式为bronco{}，所以可以确定这个应该是单表加密，并且知道前6个emoji对应的明文。

经过一系列搜索与排查可以发现每一个emoji对应的字母为这个emoji的官方英文名的首字母，根据这个线索我们可以通过找到的这些信息来解密内容：

（用到的网站：https://unicode.org/emoji/charts/full-emoji-list.html）

![e9b91f9004a900c2e4d7a34ce6a5862](https://raw.githubusercontent.com/Lycorisby/Picture/main/e9b91f9004a900c2e4d7a34ce6a5862.png)

![0931ce3f56bb2a321ba0f4fff03f4b2](https://raw.githubusercontent.com/Lycorisby/Picture/main/0931ce3f56bb2a321ba0f4fff03f4b2.png)

![9cd2886e404b3a12858ab96b92b478d](https://raw.githubusercontent.com/Lycorisby/Picture/main/9cd2886e404b3a12858ab96b92b478d.png)

![00189c6b43958a1524e193d50025b34](https://raw.githubusercontent.com/Lycorisby/Picture/main/00189c6b43958a1524e193d50025b34.png)

![547588949b4ceef18e8c752d9fdca67](https://raw.githubusercontent.com/Lycorisby/Picture/main/547588949b4ceef18e8c752d9fdca67.png)

![978715d5488adf92ad9f87db0a3cbee](https://raw.githubusercontent.com/Lycorisby/Picture/main/978715d5488adf92ad9f87db0a3cbee.png)

![b08cc26fa2123e3eb3e954be60c3c2c](https://raw.githubusercontent.com/Lycorisby/Picture/main/b08cc26fa2123e3eb3e954be60c3c2c.png)

![79fca2aa297cab3187b7aba9dd6951f](https://raw.githubusercontent.com/Lycorisby/Picture/main/79fca2aa297cab3187b7aba9dd6951f.png)

![a8740db264e5c8c07e9a7319bc2c477](https://raw.githubusercontent.com/Lycorisby/Picture/main/a8740db264e5c8c07e9a7319bc2c477.png)

![b0d298cd23920e18c9bae5935c7b5d7](https://raw.githubusercontent.com/Lycorisby/Picture/main/b0d298cd23920e18c9bae5935c7b5d7.png)

这里有一个小技巧：如果找不到想要的 emoji，可以描述给 ChatGPT 并询问其官方名称，再到网站上用名称（或部分名称）搜索，确认是否是我们需要的。

![de8fa183dfa28abeb9e31ea0bc70027](https://raw.githubusercontent.com/Lycorisby/Picture/main/de8fa183dfa28abeb9e31ea0bc70027.jpg)

最后得到flag：

```
bronco{emojis_express_my_emotions}
```





## Crypto



### Across the Tracks

![image-20250216233604997](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216233604997.png)

我们会得到一段内容：

```
Samddre··ath·dhf@_oesoere·ebun·yhot·no··oso·i·a·lr1rcm·iS·aruf·toibadhn·nadpikudynea{l_oeee·ch·oide·f·n·aoe·sae·aonbdhgo_so·rr.i·tYnl·s·tdot·xs·hdtyy'·.t·cfrlca·epeo·iufiyi.t·yaaf·.a.·ts··tn33}i·tvhr·.tooho···rlmwuI·h·e·iHshonppsoleaseecrtudIdet.·n·BtIpdheiorcihr·or·ovl·c··i·acn·t·su··ootr·:b3cesslyedheIath·e·_
```

根据题目描述我们猜测这段内容使用了栅栏密码，并且key为题目描述中提到的“tenth”（10）。解密即可得到flag：

![image-20250216233833884](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216233833884.png)

```
bronco{r@1l_f3nc3_cip3rs_r_cool}
```





### Rahhh-SA

![image-20250216233937032](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216233937032.png)

这道题我们会得到以下内容：

```python
e = 65537
n = 3429719
c = [-53102, -3390264, -2864697, -3111409, -2002688, -2864697, -1695722, -1957072, -1821648, -1268305, -3362005, -712024, -1957072, -1821648, -1268305, -732380, -2002688, -967579, -271768, -3390264, -712024, -1821648, -3069724, -732380, -892709, -271768, -732380, -2062187, -271768, -292609, -1599740, -732380, -1268305, -712024, -271768, -1957072, -1821648, -3418677, -732380, -2002688, -1821648, -3069724, -271768, -3390264, -1847282, -2267004, -3362005, -1764589, -293906, -1607693]
p = -811
```

首先注意到c的所有内容都是负数，但是其绝对值都小于等于n，所有猜测将其直接放进 $\mathbb{Z}/n\mathbb{Z}$ 进行计算即可。但因为发现$p' := n+p = 3,428,908$ 并不是n的因数，所以尝试 $3429719/811=4229$ ，发现结果为整数。

所以写一段python代码来尝试RSA解码即可：

```python
#!/usr/bin/env python3


e = 65537
n = 3429719
p = 811  # 题中写的是 -811，这里只取绝对值
q = n // p  # 4229

# 计算 phi(n)
phi = (p - 1) * (q - 1)  # (811 - 1)*(4229 - 1) = 810*4228 = 3424680

# 求 d = e^-1 mod phi(n)
# Python 3.8+ 可以直接用 pow(e, -1, phi) 得到模逆
d = pow(e, -1, phi)

# 给出的负数密文
c_list = [
    -53102, -3390264, -2864697, -3111409, -2002688, -2864697, -1695722, -1957072,
    -1821648, -1268305, -3362005, -712024, -1957072, -1821648, -1268305, -732380,
    -2002688, -967579, -271768, -3390264, -712024, -1821648, -3069724, -732380,
    -892709, -271768, -732380, -2062187, -271768, -292609, -1599740, -732380,
    -1268305, -712024, -271768, -1957072, -1821648, -3418677, -732380, -2002688,
    -1821648, -3069724, -271768, -3390264, -1847282, -2267004, -3362005, -1764589,
    -293906, -1607693
]

# 解密
plaintext_nums = []
for c in c_list:
    # 先把负数转为 mod n 内的非负代表元
    c_mod = c % n 
    m = pow(c_mod, d, n)
    plaintext_nums.append(m)

message = ''.join(chr(m) for m in plaintext_nums)

print("解密后得到的数值:", plaintext_nums)
print("尝试映射到字符后的结果:")
print(message)

# bronco{m4th3m4t1c5_r34l1y_1s_qu1t3_m4g1c4l_raAhH!}
```





## Web



### Grandma's Secret Recipe

![image-20250216234904671](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216234904671.png)

（因为这份食谱离婚了实在是有点抽象）

点击网站可以看到：

![image-20250216235137334](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216235137334.png)

点开Cookie可以发现有2条内容：
![image-20250216235220057](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216235220057.png)

```
checksum: a223befb6660a23f9c3491f74ef84e43
role: "kitchen helper"
```

结果检查发现checksum为role的md5结果：

![image-20250216235434789](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216235434789.png)

所以我们将role改为："grandma"，并且将checksum改为a5d19cdd5fd1a8f664c0ee2b5e293167（=md5(grandma))。点击“Grandma's Pantry“便可以看到：

![image-20250216235705560](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216235705560.png)

得到flag：

```
bronco{grandma-makes-b3tter-cookies-than-girl-scouts-and-i-w1ll-fight-you-over-th@t-fact}
```



## Reverse



### Reversing for Ophidiophiles

![image-20250216235950245](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250216235950245.png)

这道题我们会得到以下内容：

```
23a326c27bee9b40885df97007aa4dbe410e93
```

```python
flag = input()
carry = 0
key = "Awesome!"
output = []
for i,c in enumerate(flag):
    val = ord(c)
    val += carry
    val %= 256
    val ^= ord(key[i % len(key)])
    output.append(val)
    carry += ord(c)
    carry %= 256

print(bytes(output).hex())
```

直接用python写一段逆向的算法便可以得到flag：

```python
encrypted_hex = "23a326c27bee9b40885df97007aa4dbe410e93"
encrypted_bytes = bytes.fromhex(encrypted_hex)
carry = 0
key = "Awesome!"
flag = []

for i, val in enumerate(encrypted_bytes):
    val ^= ord(key[i % len(key)])  # 逆向 XOR 操作
    val = (val - carry + 256) % 256  # 逆向 carry 计算
    flag.append(chr(val))
    carry = (carry + val) % 256  # 重新计算 carry 值

print("".join(flag))

# bronco{charge_away}
```



### theflagishere!

![image-20250217000219950](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217000219950.png)

这道题我们会得到一份Python 编译后的字节码文件 “theflagishere.pyc”，我们首先用这个网站将其反汇编：

https://www.lddgo.net/string/pyc-compile-decompile

```python
# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Version : Python 3.9


def what_do_i_do(whoKnows):
    a_st = { }
    for a in whoKnows:
        if a_st.get(a) == None:
            a_st[a] = 1
            continue
        a_st[a] += 1
    variable_name = 0
    not_a_variable_name = 'None'
    for a in a_st:
        if a_st[a] > variable_name:
            not_a_variable_name = a
            variable_name = a_st[a]
            continue
            return (not_a_variable_name, variable_name)


def char_3():
    return 'm'


def i_definitely_return_the_flag():
    
    def notReal():
        
        def actually_real():
            return 'actuallyaflag'

        return actually_real

    
    def realFlag():
        return 'xXx___this__is_the__flag___xXx'

    return (realFlag, notReal)


def i_am_a_function_maybe(param):
    variableName = (param + 102) * 47
    for i in range(0, 100):
        variableName *= i + 1
        variableName /= i + 1
        newVariable = variableName * i
        newVariable += 100
    return chr(ord(chr(int(variableName) + 1)))


def i_do_not_know():
    realFlagHere = 'br0nc0s3c_fl4g5_4r3_345y'
    return 'long_live_long_flags'


def unrelated_statement():
    return 'eggs_go_great_with_eggs'


def i_am_a_function(param):
    variableName = (param + 102) * 47
    for i in range(0, 100):
        variableName *= i + 1
        newVariable = variableName * i
        newVariable += 100
        variableName /= i + 1
    return chr(ord(chr(int(variableName))))


def i_return_a_helpful_function():
    
    def i_do_something(char):
        var = []
        for i in range(54, 2000):
            var.append(ord(char) / 47 - 102)
        var.reverse()
        return var.pop()

    return i_do_something


def i_return_the_flag():
    return 'thisisdefinitelytheflag!'


def i():
    return 'free_flag_f'


def char_0():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_return_the_flag())[0]))


def char_1_4_6():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[0]())[0]))


def char_2_5_9():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[1]()())[0]))


def char_7():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(interesting()()()()())[0]))


def char_8():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_do_not_know())[0]))


def char_10():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(unrelated_statement())[0]))


def interesting():
    
    def notinteresting():
        
        def veryuninteresting():
            
            def interesting_call():
                return i

            return interesting_call

        return veryuninteresting

    return notinteresting

```



然后用python写一段逆向的脚本即可得到flag （主要内容其实就是复制粘贴）：

```python
def what_do_i_do(whoKnows):
    a_st = {}
    for a in whoKnows:
        if a_st.get(a) is None:
            a_st[a] = 1
            continue
        a_st[a] += 1
    variable_name = 0
    not_a_variable_name = 'None'
    for a in a_st:
        if a_st[a] > variable_name:
            not_a_variable_name = a
            variable_name = a_st[a]
    return (not_a_variable_name, variable_name)

def i_definitely_return_the_flag():
    def notReal():
        def actually_real():
            return 'actuallyaflag'
        return actually_real

    def realFlag():
        return 'xXx___this__is_the__flag___xXx'
    return (realFlag, notReal)

def i_do_not_know():
    realFlagHere = 'br0nc0s3c_fl4g5_4r3_345y'
    return 'long_live_long_flags'

def unrelated_statement():
    return 'eggs_go_great_with_eggs'

def interesting():
    def notinteresting():
        def veryuninteresting():
            def interesting_call():
                return i
            return interesting_call
        return veryuninteresting
    return notinteresting

def i():
    return 'free_flag_f'

def i_return_a_helpful_function():
    def i_do_something(char):
        var = []
        for i in range(54, 2000):
            var.append(ord(char) / 47 - 102)
        var.reverse()
        return var.pop()
    return i_do_something

def i_am_a_function_maybe(param):
    variableName = (param + 102) * 47
    for i in range(0, 100):
        variableName *= i + 1
        variableName /= i + 1
        newVariable = variableName * i
        newVariable += 100
    return chr(ord(chr(int(variableName) + 1)))

def char_0():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_return_the_flag())[0]))

def char_1_4_6():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[0]())[0]))

def char_2_5_9():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_definitely_return_the_flag()[1]()())[0]))

def char_3():
    return 'm'

def char_7():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(interesting()()()()())[0]))

def char_8():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(i_do_not_know())[0]))

def char_10():
    return i_am_a_function_maybe(i_return_a_helpful_function()(what_do_i_do(unrelated_statement())[0]))

def i_return_the_flag():
    return 'thisisdefinitelytheflag!'

# 拼接 flag
flag = (
    char_0() +
    char_1_4_6() +
    char_2_5_9() +
    char_3() +
    char_1_4_6() +
    char_2_5_9() +
    char_1_4_6() +
    char_7() +
    char_8() +
    char_2_5_9() +
    char_10()
)

print("Recovered flag:", flag)

# i_am_a_flag
# bronco{i_am_a_flag}
```





## Forensics



### QR Coded

![image-20250217001518466](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217001518466.png)

这道题我们会得到一张二维码：
![easy_scan](https://raw.githubusercontent.com/Lycorisby/Picture/main/easy_scan.png)

直接扫描（https://scanqr.org/）会得到一个fake flag：

![image-20250217001643995](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217001643995.png)

用Stegsolve打开并调整到Gray bits会得到另外一张二维码：

![easy_scan_gray](https://raw.githubusercontent.com/Lycorisby/Picture/main/easy_scan_gray.bmp)

扫描后会得到真正的flag：

![image-20250217001828549](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217001828549.png)

```
bronco{th1s_0n3_i5}
```



### Uno

![image-20250217102445644](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217102445644.png)

这道题我们会得到这样一张图片：

![uno](https://raw.githubusercontent.com/Lycorisby/Picture/main/uno.jpg)

根据题目描述（”a significant bit of the cards were left on the *plane* I was on.“）我们猜测这道题用的是LSB隐写了ASCII码，所以我们用StegSolve打开图片，利用其Data Extract模块进行查看。这个模块可以查看RGB三种颜色的每一个通道，并且按照（自选的）一定的排列顺序显示每个通道的Hex和ASCII码字符：

![image-20250217102658148](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217102658148.png)

最后，根据题目描述中的 “the numbers really speak to me...” 这一句，尝试各种由 2、3、4、5 组成的组合，便可以得到 flag：

![image-20250217102401676](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217102401676.png)

```
bronco{no_un0_y3t}
```





### Wordlands

![image-20250217110344089](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217110344089.png)

我们会得到这张图片：

![wordlands](https://raw.githubusercontent.com/Lycorisby/Picture/main/wordlands.png)

经过一番尝试后，当用StegSolve打开图片，利用其Data Extract模块进行查看时可以发现：

![image-20250217110543579](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217110543579.png)

8BPS是标准的Photoshop 的.psd 文件有固定的文件头，所以我们点击“Save Bin”将其存为wordlands.psd，并用这个网站打开它：

https://www.photopea.com/

![image-20250217110726747](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217110726747.png)

可以发现这里有所有图片创作的信息（图层之类的）。最后根据line的图层的顺序进行拼接便可以得到flag：

![image-20250217110900696](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217110900696.png)

比如说Shape1这个图层里的线连接了b和r，表示开头为br

![image-20250217110917647](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250217110917647.png)

然后是(b)ro，以此类推...

```
bronco{i_love_admiring_beautiful_winter_landscapes}
```







## Misc



### Tick Tock

![image-20250218111657044](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250218111657044.png)

这道题我们首先会得到这张图片：

![tick_tock](https://raw.githubusercontent.com/Lycorisby/Picture/main/tick_tock.png)

经过多次尝试可以在StegSolve的Data Extract模块里发现有一长串由“tick”和“tock”组成的内容：

![image-20250218112313111](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250218112313111.png)

```
ticktocktocktockticktickticktock ticktocktocktickticktocktocktock ticktocktocktickticktockticktick ticktocktockticktickticktocktock ticktocktocktocktickticktocktick ticktocktocktickticktockticktick ticktocktocktocktockticktocktock ticktocktocktockticktockticktock ticktocktocktocktocktickticktick ticktocktockticktockticktocktock ticktocktocktockticktockticktick ticktockticktocktocktocktocktock ticktocktockticktickticktocktick ticktocktocktocktocktickticktick ticktocktockticktickticktocktock ticktocktockticktockticktocktick ticktocktockticktocktickticktock ticktocktocktockticktockticktick ticktocktockticktocktickticktick ticktockticktocktocktocktocktock ticktocktockticktockticktocktick ticktocktockticktickticktocktock ticktocktockticktocktickticktock ticktocktocktocktocktickticktick ticktocktocktickticktickticktock ticktockticktocktocktocktocktock ticktocktockticktickticktocktick ticktocktocktocktocktickticktick ticktocktocktocktickticktocktock ticktocktockticktickticktocktock ticktocktocktocktocktickticktick ticktocktocktockticktocktocktick ticktocktocktockticktocktocktock ticktocktockticktocktickticktock ticktocktocktocktocktockticktock
```

写一段python将tick替换成0，tock替换成1然后当成二进制内容进行解码会得到：

```python
def ticktock_to_binary(text):
    return text.replace("tick", "0").replace("tock", "1")



text = "ticktocktocktockticktickticktock ticktocktocktickticktocktocktock ticktocktocktickticktockticktick ticktocktockticktickticktocktock ticktocktocktocktickticktocktick ticktocktocktickticktockticktick ticktocktocktocktockticktocktock ticktocktocktockticktockticktock ticktocktocktocktocktickticktick ticktocktockticktockticktocktock ticktocktocktockticktockticktick ticktockticktocktocktocktocktock ticktocktockticktickticktocktick ticktocktocktocktocktickticktick ticktocktockticktickticktocktock ticktocktockticktockticktocktick ticktocktockticktocktickticktock ticktocktocktockticktockticktick ticktocktockticktocktickticktick ticktockticktocktocktocktocktock ticktocktockticktockticktocktick ticktocktockticktickticktocktock ticktocktockticktocktickticktock ticktocktocktocktocktickticktick ticktocktocktickticktickticktock ticktockticktocktocktocktocktock ticktocktockticktickticktocktick ticktocktocktocktocktickticktick ticktocktocktocktickticktocktock ticktocktockticktickticktocktock ticktocktocktocktocktickticktick ticktocktocktockticktocktocktick ticktocktocktockticktocktocktock ticktocktockticktocktickticktock ticktocktocktocktocktockticktock"
text = text.replace(" ", "")

binary = ticktock_to_binary(text)
print(binary)

# 01110001 01100111 01100100 01100011 01110010 01100100 01111011 01110101 01111000 01101011 01110100 01011111 01100010 01111000 01100011 01101010 01101001 01110100 01101000 01011111 01101010 01100011 01101001 01111000 01100001 01011111 01100010 01111000 01110011 01100011 01111000 01110110 01110111 01101001 01111101

content = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
print(content)

# qgdcrd{uxkt_bxcjith_jcixa_bxscxvwi}
```

最后通过遍历凯撒密码便可以得到flag：

![image-20250218111604430](https://raw.githubusercontent.com/Lycorisby/Picture/main/image-20250218111604430.png)

```
bronco{five_minutes_until_midnight}
```


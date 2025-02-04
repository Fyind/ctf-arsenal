---
title: CTF知识点
date: 2024-05-15 00:06:29
tags:
---

### 知识点

https://ctf101.org/web-exploitation/overview/

https://www.youtube.com/watch?v=5C-OtW7C5oU&t=30s





https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask

### 练习网站

buuctf

https://adworld.xctf.org.cn/

https://ctflearn.com/challenge/1/browse

https://www.root-me.org/?lang=en

https://picoctf.org/

1. tryhackme.com
2. hackthebox.eu
3. overthewire.org
4. Root-me.org
5. Ringzer0team.com
6. Hack.me
7. ctftime.org
8. picoctf.com
9. ctf365.com
10. ctf101.org

### 虚拟机

打开或关闭功能, 打开 Hyper V, 然后重启

下载 kali的Hyper V的Hyper V镜像. 然后双击bat安装. 然后就能打开了,点击连接就有gui

## 文件

### 图片文件处理

打开图片

``` shell
eog xxx.jpg
```

#### hexdump

hex中查找 string

* pdf里面找隐藏

``` shell
strings xxx.jpg | grep CTFlearn 
strings -n 10 xxx.jpg  # >= 10 长度的字符串
```

hexdump

``` shell
hexdump -C Pho.jpg | less
```

python

``` python
file = open("TheMessage.txt", "r").read()
res = ""
for ch in file:
	if ord(ch) == 32:
		res += "0"
	else:
		res += "1"
print(res)
```



### binwalk

``` shell
binwalk --dd=.* xx.jpeg # 查看所有隐藏的二进制, DD 可以顺便解压
binwalk -e xx.jpg # 提取文件
file * # 查看当前目录所有文件类型
exiftool xx.jpg # 查看更多信息，有file里面没有显示完全的
```

#### stegehide

``` shell
steghide extract -sf xx.jpg
```

### 二维码

显示二维码

``` shell
sudo apt install zbar-tools
zbarimg xx.png
```

python

``` python
import cv2
img = cv2.imread("qr.png")
det = cv2.QRCodeDetector()
data, box, b = det.detectAndDecode(img)
print(data)
```



## python 

### string

所有可打印字符

``` python
string.printable
```

### 提取flag

``` python
import re
def extract_flag_from_string(string):
    match = re.search(r'flag\{[^}]+}', string)
    return match.group(0) if match else None
```

### Crypto

``` python
pip install pycryptodome
```

#### 计算两个byte的xor

``` python
def xor(data, key):
    return bytearray([x ^ y for x,y in zip(data,key)])
```

### urlencode

``` python
import urllib.parse
# 字典格式的数
data = {'name': '张三', 'age': 25}
# 使用 urlencode 进行编码
encoded_data = urllib.parse.urlencode(data)
print(encoded_data)
```





## Git

查看历史log

``` shell
git log
```

查看commit改变了什么

``` shell
git show
```

## Linux

#### 解压

``` shell
unzip x.zip
unrar x x.rar
```

### 查看ls

打印所有文件夹内容

``` shell
ls -la *
```

查找

``` shell
find / -name *.txt
```





# 密码学

online的工具

https://gchq.github.io/CyberChef/

https://www.dcode.fr/en

加密

https://www.boxentriq.com/code-breaking/cipher-identifier

### 2进制到hex

``` python
x = str(hex(int(bc, 2)))[2:]
```

#### hex转换

``` python
from binascii import unhexlify
hexstr = "41 42 43 54 46 7B 34 35 43 31 31 5F 31 35 5F 55 35 33 46 55 4C 7D"
hexs = "".join(hexstr.split(" "))
print(unhexlify(hexs.encode()))
```

#### 输入bytes

``` cpp
s = "f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M"
a = bytearray(s.encode())
```

#### 字符串转换字符数组

``` python
char_array = list("your_string")
string = ''.join(char_array)
```

#### 交换大小写

``` python
"asb".swapcase()
```

`c.isalpha()`：判断 `c` 是否是字母。

`c.isupper()`：判断 `c` 是否是大写字母。

`c.islower()`：判断 `c` 是否是小写字母

### base64

shell

``` shell
base64 -d xxx
echo "c3ludCB2ZiA6IGEwX29icWxfczBldHJnX2RlX3BicXI=" | base64 -d
```

python

``` python
from base64 import decodebytes
s = decodebytes("Q1RGe0ZsYWdneVdhZ2d5UmFnZ3l9".encode())
print(s)
```

cyberchef的label和jump可以实现循环解密

原理：

**将二进制数据转换为 6 位块：**

- 每个字节有 8 位，3 个字节一共是 24 位。
- 将这 24 位拆分为 4 个 6 位的块。

**将 6 位的数据映射到 Base64 字符表：**

- `A-Za-z0-9+/`

如果输入数据的字节数不是 3 的倍数，编码过程会用 `=` 字符进行填充，使输出数据的长度是 4 字节的倍数。

在后面每次填一个byte(0) 直到是3的倍数，然后base64加密，最后把由加入新0产生的A换成=就好了

``` python
def b64en(s, table="default"):
    if table == "default":
        table = ""
        for i in range(26):
            table += chr(i + ord('A'))
        for i in range(26):
            table += chr(i + ord('a'))
        for i in range(10):
            table += chr(i + ord('0'))
        table += "+/"
    s = s.encode()
    lens = len(s)
    s = int.from_bytes(s)
    s = bin(s)[2:]
  
    while len(s) < lens*8:
        s = "0" + s
    needed = 0
    while len(s) % 3 != 0:
        s += "00000000"
        needed += 1

    s = list(map(int,list(s)))
    i = 0
    ans = []
    while i < len(s):
        x = 0
        for j in range(6):
            x = (x<<1) + s[i+j]
        ans.append(table[x])
        i += 6
    for j in range(needed):
        ans.pop()
    for j in range(needed):
        ans += "="
    return "".join(ans)

def b64de(s, table="default"):
    if table == "default":
        table = ""
        for i in range(26):
            table += chr(i + ord('A'))
        for i in range(26):
            table += chr(i + ord('a'))
        for i in range(10):
            table += chr(i + ord('0'))
        table += "+/"
    s = list(s)
    needed = 0
    while s[-1] == "=":
        s.pop()
        needed += 1
    for i in range(needed):
        s += table[0]
    a = ""
    for i in range(len(s)):
        x = table.index(s[i])
        
        toa = ""
        for j in range(6):
            if x>>j&1:
                toa = "1" + toa
            else:
                toa = "0" + toa
        
        a += toa

    a = list(map(int,list(a)))
    for i in range(needed):
        for j in range(8):
            a.pop()
    i = 0
    ans = []
    while i < len(a):
        x = 0
        for j in range(8):
            x = (x<<1) + a[i+j]
        ans.append(chr(x))
        i += 8

    ans = ''.join(ans)
    return ans
```



#### DTMF 声调

https://dtmf.netlify.app/

## 不同种类的密码

#### Vigenere Cipher

一种凯撒密码

key 是 `OCU` 那么第一个字符被移动了 O (14)次，第二个字符被移动了 `C` (2) 次

#### CAESAR Cipher

在线暴力破解

https://www.dcode.fr/caesar-cipher

#### keyboard shift

`BUH'tdy,|Bim5y~Bdt76yQ` 长这样, 有可能下划线不被解密

https://www.dcode.fr/keyboard-shift-cipher

#### bacon cipher



#### 与佛论禅

https://www.keyfc.net/bbs/tools/tudoucode.aspx

密语是`佛曰：` 开头的

#### rot13

https://www.rot13.de/index.php



### enigma cryptogarphy

https://cryptii.com/pipes/enigma-machine

#### Playfair cipher

通常有一个表格表示密钥
$$
\begin{array}{lllll}
Q & W & E & R & T \\
Y & U & I & O & P \\
A & S & D & F & G \\
H & K & L & Z & X \\
C & V & B & N & M
\end{array}
$$
https://www.boxentriq.com/code-breaking/playfair-cipher

### brute force

暴力key的长度，然后暴力，使得xor后的string有 `flag` 



#### sha1

这个里面的 `0x8004u`就是sha1加密的标志

http://www.ttmd5.com/hash.php?type=5

#### Md5

这个里面的 `0x8003u`就是sha1加密的标志

https://hashes.com/en/decrypt/hash

https://md5.gromweb.com/?md5=b74dec4f39d35b6a2e6c48e637c8aedb

https://www.somd5.com/

可以直接google MD5值, 看有没有解密



### Discrete logarithm

如果 $p-1$ 的质数分解比较小，那么可以解出来

https://github.com/idekctf/idekctf-2024/blob/main/crypto/goldenticket/debug/solve.py

sage 有一个函数 `discrete_log_lambda` 可以对一个区间计算答案，复杂度是 $O(\sqrt{len})$ 级别, 之后再用CRT合并出大答案

``` py
def PH_partial(h, g, p, fact_phi):
    """Returns (x, m), where
    - x is the dlog of h in base g, mod m
    - m = lcm(pi^ei) for (pi, ei) in fact_phi
    """
    res = []
    mod = []
    F = GF(p)

    phi = p-1
    for pi, ei in fact_phi:
        gi = pow(g, phi//(pi**ei), p)
        hi = pow(h, phi//(pi**ei), p)
        xi = discrete_log_lambda(F(hi), F(gi), bounds = (0, pi**ei))
        res.append(int(xi))
        mod.append(int(pi**ei))

    x, m = CRT(res, mod), lcm(mod)
    assert pow(g, x * phi//m, p) == pow(h, phi//m, p)
    return x, m
```





# Web

#### 信息收集

从HTTP头中的Server字段可以了解用了什么服务器

敏感目录：

* `.git`
* `svn`
* `idea`

工具

* dirsearch
* ffuf

### SQL 注入

#### 数字型注入

`?id=1` 和 `?id=2-1` 是一样的



## PWN

#### pwn tool 

``` shell
pip install pwmtools
```

#### recv

``` python
con.recvuntil("ready? Y/N : ".encode()).decode()
con.recvline_startswith("Computer".encode()).decode() # 一直到有一个符合的
con.recv(1024)
```

#### send

``` python
con.sendline(b'Y')
```



#### 连接

``` python
import pwn
con = pwn.remote("thekidofarcrania.com", 10001)
s = con.recvuntil("ready? Y/N : ")
```



### Post Request

#### curl

``` shell
curl -X POST -d "username=admin&password=71urlkufpsdnlkadsf" http://165.227.106.113/post.php
```



### Burpsuite

install

``` shell
sudo apt install burpsuite
```

打开之后点Proxy, 然后点 intercept on, 然后open browser 打开连接就可以获得对应的请求

#### header

可以右键发送到repeater里面

然后在里面改header



#### referer

表示从哪里来的

``` html
Referer:awesomesauce.com
```



#### python插件

Repeater里面右键，extension，里面可以复制为python的request



### 开发者工具

#### Storage

可以看到存储的信息



## 网站

### `robots.txt`

去网站的 https://ctflearn.com/robots.txt 可以看到不允许的网页

#### wikipedia

https://en.wikipedia.org/ 

用diff可以看到修改的信息

#### 备份文件名

`.git .svn .swp .svn .~ .bak .bash_history`

### dirsearch

可以看网页的目录

https://github.com/maurosoria/dirsearch



#### 更改网页源代码

可以把disable的按钮改成可以按下去

用hackbar可以发送post请求



#### 查找网站的隐藏连接

#### gobuster

#### 查找历史网页状态

wayback machinehttps://web.archive.org/

## PHP

#### 判断相等

`==, >` 是弱类型判断，会先转换类型再判断，所以 `a=123abc` 会变成 `123`

#### 反序列化

序列化：把对象转成字符串存储。反序列化：把字符串转成对象

`__wakeup()` 是在序列化的时候执行的

``` php+HTML
<?php 
class xctf{
public $flag = '111';
public function __wakeup(){
exit('bad requests');
}
}
$a = new xctf();
$c = serialize($a);
echo $c
?> 
```

输出是 ` O:4:"xctf":1:{s:4:"flag";s:3:"111";} ` 现在要绕过这个exit方法,改成2就行

#### THINK PHP RCE

RCE是remote code execution，在github上搜索think php5 可以找到漏洞

### 文件上传



https://www.cnblogs.com/xhds/p/12218471.html

# misc

#### 在线工具

https://www.ilovepdf.com/zh-cn , https://pdf2doc.com/ PDF转换

https://georgeom.net/StegOnline/checklist checklist steg

### 隐写术

#### 文件附加

#### PNG

开头是

``` text
89 50 4E 47 0D 0A 1A 0A
```

IEND 是

``` text
00 00 00 00 49 45 4E AE 42 60 82
```

查看metadata在linux上:

``` shell
exiftool xxx.png
```

#### JPEG

* 头 `FF D8 FF`
* 尾 `FF D9`

#### GIF 

拆分图片工具：stegsolve分离图片（先open再analyse-frame browser）

* `47 49 46 38`
* `00 3B`

#### ZIP 

* `50 4B 03 04`
* `50 4B`

#### RAR

* `52 61 72 21`

#### WAVE

* `57 41 56 45`

#### AVI

* `41 56 49 20`

### LSB

Least significant bit 在图片的最低有效位上写入信息

Stegsolve , zsteg 工具可以识别

``` shell
sudo apt install zsteg
zsteg cats.png
zsteg xx.bmp -b 1 -a yx -v
```

python脚本

``` python
from bitarray import bitarray
import cv2

def LSBtoBytes(path, index=0):
    # index 0,1,2 = r,g,b
    im = cv2.imread(path)
    data = []
    for row in im:
        for col in row:
            data.append(col[index] & 1)
    return bitarray(data).tobytes()

def LSBtoImg(path, index=0):
    im = cv2.imread(path)
    for i,row in enumerate(im):
        for j,col in enumerate(row):
            if col[index] & 1 == 1:
                im[i][j] = [255,255,255]
            else:
                im[i][j] = [0,0,0]
    # cv2.imwrite("out.png",im)
    return im
```

LSB可能RG， GB之类的组合使用

#### 隐写思路

* 图片结构改变： 结尾加东西，`zsteg`

  提取文件： `zsteg -e "b1,rgb,lsb,xy" xx.png > flag.png`

  Chunks 改变 : 用 `pngcheck` 检查

* LSB 隐写： 对应工具

### 盲水印

在不同与域上隐藏信息，在图片傅里叶变换后。把信息添加到“噪声”中，再逆变换回去就不会对原图片产生大变化

工具: `BlindWaterMark`

#### 现成的隐写工具

* Jphide: JPG

* Outguess: JPG

  ``` shell
  outguess -k "key" -r file.jpg out.txt # decode
  ```

* Steghide: support for JPEG, BMP, WAV and AU files

* F5-steganography: BMP, GIF, or JPEG

* invisible secrets

* wbs43open

* stegosuite

* cloacked-pixel

* Slient-Eye

 暴力工具

`DominicBreuker/stego-toolkit`

### 压缩文件

#### ZIP 文件

* 数据区 (504B0304)
  * 解压要的版本
  * flags
  * 压缩算法
  * 文件修改时间
  * CRC32
  * 压缩前与后大小
  * 文件名长度和内容
  * 文件数据
* 核心目录区 (504B0102)
* 核心目录结束区 (504B0506)



#### PDF 文件

可能藏在图片后面，转word或者全选可以看



#### RAR 文件

`RAR <=4` 的签名 `5261172211A0700`

`RAR5` 的签名 `526172211A070100`

#### 暴力破解工具

windows: ARCHPR

Linux: fcrackzip, RarCrack

也可以通过爆破CRC32来获得

`zip-crc-cracker` ，`crc32` 

#### 伪加密

ZIP里面有个通用标记位

距离 `504B0102` 偏移 8 byte, 本身占 2 byte，最低位标识是否被加密。只要改回0就可以正常打开

RAR里面也有

HeadFlags 从低位起第3bit是，但是要重新计算CRC(`HEAD_CRC`)

#### ZIP 明文攻击

知道内容一些字节可以用，要先确认把呢不能

可以用 `ARCHPR` , 非完整明文 `bkcrack`



### 音频隐写

#### 工具

* audacity 查看音频





### 流量分析

Wireshark

统计里面，协议分级可以看流量包的比例

会话里面会有地址

过滤器

``` shell
ip.src == xxx.xx.xx.xx
```

也可以右键作为过滤器应用

#### HTTP

明文传输的

#### HTTPS

添加TLS，要导入密钥才能看到内容

#### FTP

20，21 端口

#### DNS

解析网址

### USB流量分析

通过USB协议传输，从一个地址发送到host

键盘是8字节，鼠标是4字节

* 第一个字节是按键按下
  * `00` 没有按下，`01` 按左键，`02` 按右键
* 第二个字节是左右偏移
  * 正是向右移动 `n` 个像素位
* 第三个字节是上下偏移
  * 正是向上移动

键盘流量

* Byte1：控制信息
  * `[Right gui,Right alt,Right shift,Right control,Left Gui,Left Alt,left shift,Left Control]`
* byte3：击键信息

### wireshark

提取流量数据

``` python
import pyshark
import pyshark.packet
from binascii import unhexlify

capture = pyshark.FileCapture('justapcap.pcap')
hexstr = ""
cnt = 0
for packet in capture:
    s = str(packet)
    cur = s.split("Name:")[-1].split(".")[0].split("1m ")[1]
    hexstr += cur
hexstr = hexstr.split("exam")[0]

with open("a.png","wb") as f:
    f.write(unhexlify(hexstr))
```

### 内存取证

#### volatility

``` shell
sudo snap install volatility-phocean
```

#### 确定信息

``` shell
vol.py -f memory imageinfo
```

psxview 查看内存

``` shell
vol.py -f memory --profile=Win7SPx86 psxview
```

pslist 查看运行的进程

``` shell
volatility -f mem.mem --profile=Win10x64_1231 pslist
```



filescan 是打开的文件对象

dumpfile 

``` shell
vol.py -f memory --profile=Win7SPx86 prodump -p 1384 --dump-dir ./dump/

file dump/executable.i384.exe
```

PEB 会保存PEB信息

``` shell
vol.py -f memory --profile=Win7SPx86 cmdline
```

是命令行信息

sockets

hivelist, hivescan 是注册表

hashdump获取用户密码的hash， mimikatz 插件可以还原hash

#### volatitlity 3

确定信息

``` shell
vol -f x.mem windows.info
```



### 磁盘取证

#### 文件系统

windows: FAT16, FAT32, NTFS

Linux: Ext2, Ext3, Ext4

#### Fat16/32

16bit 来表示一个簇

DBR扇区

![image-20240819191436093](CTF知识点/image-20240819191436093.png)

#### NTFS

性能优秀，安全性高，可恢复性，文件压缩



# OSINT

时光机 web archive





# 区块链blockchain

IDE：REMIX

#### windows 安装nc

去nmap官网下载就行



### msg.sender

当一个外部账户（例如，用户的钱包地址）调用合约中的函数时，`msg.sender` 会是该外部账户的地址。

如果一个合约调用另一个合约的函数，那么 `msg.sender` 将是调用方合约的地址，而不是最终的外部账户。

例如，如果合约 A 调用合约 B 的函数，合约 B 中的 `msg.sender` 会是合约 A 的地址，而不是最初发起调用的外部账户。

当一个函数从合约内部调用另一个合约的函数时，`msg.sender` 仍然是直接发起调用的那个地址。如果函数调用链中有多个合约调用，`msg.sender` 始终代表的是当前执行上下文中的调用者。

### storage

在 Solidity 中，`storage` 是用于存储智能合约中状态变量的数据位置。它是智能合约中非常重要的一部分，用来持久化存储数据，也就是存储在以太坊区块链上的数据。与其他数据存储位置（如 `memory` 和 `stack`）不同，`storage` 中的数据是持久的，意味着它们在交易执行后会一直存在，直到被更新或删除。每个合约都有自己的 `storage` 空间。

#### 1. **`storage` 的特点**

- **持久性**：`storage` 中的数据在合约的生命周期内是持久的，意味着它们会被保存在区块链中。即使合约函数执行完成后，数据仍然保留，并且在下一次函数调用时可以访问。
- **费用**：在 Solidity 中，将数据写入 `storage` 是昂贵的操作，因为这需要改变区块链状态并消耗 `gas`。相对而言，从 `storage` 中读取数据的费用要比写入便宜一些。
- **每个合约的 `storage` 空间独立**：每个智能合约都有自己的 `storage` 空间，且 `storage` 中的数据可以通过合约的状态变量来访问

#### slot

Solidity 会将每个状态变量存储在固定的槽（slot）中。每个状态变量占据一定的存储槽，状态变量的存储位置由其在合约中声明的顺序决定。这些槽位在区块链上是固定的



### 合约交互python

先要安装solc, 然后pip安装`web3`,`py-solc-x`下面是基本配置

``` python
w3 = Web3(Web3.HTTPProvider('http://94.237.59.45:52415'))


def create_abi(name):
    temp_file = solcx.compile_files(f'{name}.sol')
    abi = temp_file[f'{name}.sol:{name}']['abi']
    return abi

setup_abi = create_abi('Setup')
fNFT_abi = create_abi('FrontierNFT')
fMarket_abi = create_abi('FrontierMarketplace')

if w3.is_connected():
    print("Connected to Ethereum network")
else:
    print("Failed to connect")

private_key = "1249bb2c45202146bbe401b6b29848c5f0345e418434eeedaade8dd8bdbb437a"
my_address = "0x41b34Fe0b213FF5300D648F875F84B0F016295cc"
fmarket_address = "0x899c356B0489472c99EF4A46b3893B62Fd73F349"
setup_address = "0xD984cF86bfEbb01E62f0729c2Dd5562a852038f4"
```

#### 调用函数

不创建新节点

``` python
setup = w3.eth.contract(address=setup_address, abi=setup_abi)

print(setup.functions.isSolved().call())
print(setup.functions.paramfunc(param).call()) # 有参数的写法
```

读取值，可以把值当成函数

#### 查询block chain

``` python
latest_block = w3.eth.get_block('latest')
# block_number = 10000000  #
# latest_block = w3.eth.get_block(0)
# print(block['number']) 

print("Latest Block Info:")
print(f"Block Number: {latest_block['number']}")
print(f"Block Hash: {latest_block['hash'].hex()}")
print(f"Parent Hash: {latest_block['parentHash'].hex()}")
print(f"Timestamp: {latest_block['timestamp']}")
print(f"Miner: {latest_block['miner']}")
print(f"Gas Used: {latest_block['gasUsed']}")
print(f"Gas Limit: {latest_block['gasLimit']}")
print(f"Transactions Count: {len(latest_block['transactions'])}")

```

##### 查询balance

``` python
# 查询该地址的余额（返回值是以 wei 为单位）
balance_wei = web3.eth.get_balance(address)
# 将 wei 转换为 ether
balance_ether = web3.from_wei(balance_wei, 'ether')
```



#### 查询transactions

``` python
# 查询某个区块范围内的交易
block_start = 10000000  # 起始区块
block_end = 10001000    # 结束区块

# 获取区块范围内的交易
for block_number in range(block_start, block_end + 1):
    block = web3.eth.getBlock(block_number, full_transactions=True)

    # 遍历区块中的所有交易
    for tx in block.transactions:
        # 如果交易是发送到合约地址
        if tx.to == contract_address:
            # 解析交易的input数据，检查是否是函数调用
            input_data = tx.input
            print(f"Transaction Hash: {tx.hash.hex()}")

            # 使用ABI来解码交易数据
            decoded_input = contract.decode_function_input(input_data)
            function_name = decoded_input[0].fn.__name__
            print(f"Called function: {function_name}")
            print(f"Function Arguments: {decoded_input[1]}")
            
# 遍历
for tx_hash in latest_block['transactions']:
    tx = w3.eth.get_transaction(tx_hash)
    print(f"from: {tx['from']}")

    # 
    if tx['to'] is None:
        print(f"Transaction {tx_hash.hex()} is a contract deployment.")
    else:
        print(f"Transaction {tx_hash.hex()} is a contract function call to {tx['to']}.")

    # 
    receipt = w3.eth.get_transaction_receipt(tx_hash)

    # 
    if receipt['contractAddress']:
        print(f"Contract deployed at address {receipt['contractAddress']}")
    else:
        print("No contract deployed in this transaction.")

    # print(f"Transaction Input Data: {tx['input']}")
    
    # decoded_input = setup.decode_function_input(tx['input'])
```

##### 交易信息

``` python
# 打印交易的详细信息
for tx_hash in transactions:
    transaction = web3.eth.get_transaction(tx_hash)
    print(f"Transaction Hash: {tx_hash.hex()}")
    print(f"From: {transaction['from']}")
    print(f"To: {transaction['to']}")
    print(f"Value: {web3.fromWei(transaction['value'], 'ether')} ETH")
    print(f"Gas: {transaction['gas']}")
    print(f"Gas Price: {web3.fromWei(transaction['gasPrice'], 'gwei')} Gwei")
    print("-" * 40)
```



#### 查询事件

``` python
event_filter = setup.events.DeployedTarget.create_filter(from_block=1, to_block=1) #DeployedTarget是函数名字
events = event_filter.get_all_entries()

# print event
for event in events:
    print(f"Event: {event.event}")
    print(f"Arguments: {event.args}")
```

#### 发送transaction

``` python
# send transactions
tx = forgotten.functions.discover(hashed).build_transaction(
    {
        'from': my_address,
        "gasPrice": w3.eth.gas_price,  # two ******* hours it took to figure out this was needed.
        'nonce': w3.eth.get_transaction_count("0xEB4B81DE5738a22d24631ABD62f62cEECC268e71"),
    }
)

# needs to be signed as we are executing/writing not just reading
tx_create = w3.eth.account.sign_transaction(tx, private_key)
tx_hash = w3.eth.send_raw_transaction(tx_create.raw_transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f'Tx successful with hash: { tx_receipt.transactionHash.hex() }')
```

#### 计算keccak哈希

``` python
hashed = w3.solidity_keccak(
    ['uint256', 'uint256', 'address'], 
    [1, 1734258030, "0x3E698Aba19B29C3fB625966A9631e6cf5C79505e"]  
)

print(f"Keccak256 Hash: {hashed.hex()}")
```





## Hack 思维

### 数据范围

输入不合法数据范围


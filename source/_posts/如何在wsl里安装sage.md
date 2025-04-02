---
title: 如何在wsl里安装sage
date: 2025-03-31 13:58:38
categories:
  - 系统配置
tags: [wsl,sage,vscode]
---



一共分成2个步骤：

1. 安装Miniforge（Anaconda的轻量化替代品）
2. 通过Anaconda安装sage
3. 下载vscode的wsl版（可选）


## 安装Miniforge

```bash
wget https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh
```

然后安装脚本：

```bash
bash Miniforge3-Linux-x86_64.sh
```

如果安装时询问你是否要把它加入 `.bashrc`， 选择是，这样一来每次打开wsl它都会自动启动并进入base环境，会比较方便。

当然如果这个自启没有设置成功，也可以手动设置：

先打开 打开 `.bashrc` 编辑器

```
nano ~/.bashrc
```

在文件末尾添加：

```bash
. "$HOME/miniforge3/etc/profile.d/conda.sh"
conda activate base
```

然后使用`Ctrl + O` 和 `Ctrl + X` 保存并退出。

最后再运行：

```bash
source ~/.bashrc
```



## 安装sage

通过

```bash
conda create -n sage sage -c conda-forge
```

安装sage。然后每次使用

```bash
conda activate sage
```

激活sage环境并用

```bash
sage
```

打开sage。



## 下载vscode的wsl版

由于单纯用命令行运行sage代码不太方便，并且只用sage的话有些python的命令（比如说连接服务器等）容易出问题，可以安装一个vscode的wsl版。

首先在Windows里的vscode下载 `wsl` 的插件

![image-20250331142857212](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250331142857212.png)

之后在当前wsl的命令行里输入：

```bash
code .
# 用vscode打开当前文件夹
```

它便会开始自动下载wsl版的vscode。

下载完成后，每次启动wsl之后只需要先打开vscode：

```
code .
```

然后在vscode的命令行里输入：

```
conda activate sage
```

便可以编写并运行import了sage库的python代码。

![image-20250331143508887](https://raw.githubusercontent.com/archer-baiyi/Picture/main/image-20250331143508887.png)

！！！记住要先开vscode再开启sage的环境，不然先开启了sage环境后，进到vscode里会掉回base的环境。


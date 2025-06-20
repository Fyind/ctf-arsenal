---
title: Cloudflare图床服务
date: 2025-06-20 10:43:37
tags: blog
categories: 系统配置
---

# Cloudflare+ PicGo 免费图床服务

可以部署图片上传服务，用来上传写博客的图片

## Cloudflare

先去[这里](dash.cloudflare.com)注册个账号. 

然后去 R2 Object Storage 里面选择 10GB 的免费方案，添加个paypal.

## 创建bucket

然后里面会出现 Create a bucket, 点进去输入名字，创建一个bucket。

然后再到bucket的设置里，启用 `公共开发 URL` 这样可以让外部也访问这个bucket.

## 购买域名

在cloudflare里面买一个便宜的域名。

然后在bucket设置了的自定义域里面选择这个域名。

![](https://fyindex.work/PicGo/20250620130650389.png)

## API

去R2对象存储里面，概览里面，选择API令牌管理

创建account api令牌，在权限里面选择读对象和写, 然后创建就好了

我们会生成

* 访问密钥ID
* 机密访问密钥

这两个东西，之后填入PicGo设置里面

## R2 配合 API

去R2对象存储里面，概览里面，选择将R2与API配合使用

里面有个链接

``` shell
https://ef1bf82c34c4f7619b83ab97e34dd45c.r2.cloudflarestorage.com
```

这个之后填入PicGo的设置里的自定义节点

## PicGo

### Linux 安装

下载 AppImage, 然后给权限

``` shell
chmod 777 PicGo-2.4.0-beta.10.AppImage
```

然后右键，点击run

## 安装S3插件

打开插件设置, 搜索S3, 选择 `s3-lls 1.0.2` 这个点击安装。

## 设置图床

点图床设置，Amazon S3, 更改Default设置

填入API的ID和密钥

文件路径填 `PicGo/{fullName}` 

自定义节点填写R2配合API里的地址，然后确定

自定义域里面填刚才买的 `https://fyindex.work` 比如说这个

然后设置为默认图床

![img](https://pub-5fab50a440ad4e308c55446a1f0d9a5d.r2.dev/PicGo/20250620113335105.png)

# Ubuntu 截图

可以去设置里，keyboard 里面选择shortcut搜索screenshot

可以把interactive的那个改称 Alt + Shift + P

# Typora 设置

首先把typora调成中文，然后去图片里面选择 `PicGo(App)`

![image-20250620132609306](https://fyindex.work/PicGo/image-20250620132609306.png)

选择好PicGo的路径，就可以了

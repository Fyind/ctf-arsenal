---
title: Electron桌面应用开发
date: 2025-02-05 00:50:00
tags:
  - Web技术
---

# Electron桌面应用开发

## 配置环境

首先需要安装NodeJS，https://nodejs.org/en, 安装好后用下面命令检查

``` shell
node -v
```

### 创建项目

在一个空文件夹里面

``` shell
npm init
```

然后一路回车，会给一个 `package.json` 

里面的 `main` 是主程序的入口，一般是 `main.js`

然后我们创建一个 `main.js`, 就可以开始写代码了

还有一步是安装 Electron

``` shell
npm install electron --save-dev
```

然后再 `package.json` 里加入 `start` 命令

``` json
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "start": "electron ."
}
```

然后用

``` shell
npm start
```

另一种方式：在Windows Powershell管理员里面写 

``` shell
set-ExecutionPolicy RemoteSigned
```

就可以在powershell里面运行了

就可以启动应用程序

使用

``` shell
npm get prefix
```

可以看到全局变量安装的位置. 

### 智能补全

把 `node_modules` 里面 `electron` package里面的 `electron.d.ts` 复制到项目 `node_modules` 目录里，在vscode里面就可以代码智能补全了

## 简单APP

### 开启主窗口

#### 导入

在 `main.js` 里面可以引入app, BrowserWindow. app控制应用的生命周期，BrowserWindow 是用来创建窗口的

``` js
const {app, BrowserWindow} = require('electron') // 引入

const createWindow = () => {
    const win = new BrowserWindow({
        width : 800,
        height : 600
    })
    win.loadFile('src/index.html')
}

app.on('ready',() => {
    createWindow()

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length == 0) {
            createWindow()
        }
    })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
```

我们可以建立一个 createWindow 函数用来创建窗口, 用 loadFile 来加载一个 html 作为窗口的内容

再MacOS中，没有窗口运行的时候App仍然可以运行，所以要判断一下，如果没有窗口就创建一个

> #### **为什么特殊处理 macOS？**
>
> 在 macOS 中，关闭窗口（点红色关闭按钮）通常不会完全退出应用，而是将其保持在后台，这与 Windows 和 Linux 的行为不同。因此，开发者通常保留后台运行功能，直到用户显式退出程序

当所有窗口关闭的时候，如果平台不是 Windows 我们就关闭app，因为Windows会自动关闭没有窗口的App

判断平台：
| **值**     | **操作系统**      |
|------------|-------------------|
| `darwin`   | macOS             |
| `win32`    | Windows            |
| `linux`    | Linux              |
| `aix`      | IBM AIX            |
| `freebsd`  | FreeBSD            |
| `sunos`    | SunOS              |


### 创建菜单

可以创建一个 `template` 和  `menucreate` 函数

#### template

template 是一个数组，每一个元素是一个菜单项目

``` js
let template = [{
    label : '文件',
    submenu : [{
        label : '新建笔记',
        accelerator: "CmdOrCtrl+N",
        click: function () {
            if (mainWindow) {
                mainWindow.webContents.send('info_create')
            }
        }
    }, {
        label : '新建标签',
        accelerator : "CmdOrCtrl+Shift+N",
        click : function() {
            if (mainWindow) {
                mainWindow.webContents.send('info_create_label')
            }
        }
    },{
        type: 'separator'
    },{
        label : '保存',
        accelerator : "CmdOrCtrl+S",
        click : function() {
            if (mainWindow) {
                mainWindow.webContents.send('info_save')
            }
        }
    }]
 
```

#### menucreate

用于对MacOS的菜单特殊处理, `unshift` 是插入数组第一个并且返回个数

``` shell
function menucreate() {
    if (process.platform === 'darwin') {
        const name = app.getName()
        template.unshift({
            label : name,
            submenu : [
                {label : '关于 ${name}', role: 'about'},
                {type: 'separator'},
                {label : '退出', accelerator: 'Command+Q', click: ()=>app.quit()}
            ]
        })
    }
}
```

在主函数里面加入菜单, Menu 需要导入

``` js
const {app, BrowserWindow, Menu} = require('electron')

const createWindow = () => {
    const win = new BrowserWindow({
        width : 500,
        height : 800
    })
    menucreate()
    var menu = Menu.buildFromTemplate(template)
    Menu.setApplicationMenu(menu)
    win.loadFile("src/index.html")
}
```

### 实现监听的事件

新建一个 `files_manage.js` 用于编写菜单传输的事件函数


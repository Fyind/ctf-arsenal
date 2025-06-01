---
title: FreeBSD
date: 2025-06-01 21:53:57
tags:[operating system]
---

## 配置FreeBSD 环境

## 1.下载Oracle VirtualBox

### 2. 下载FreeBSD的镜像

去这个[链接](https://archive.freebsd.org/old-releases/amd64/amd64/ISO-IMAGES/14.0/FreeBSD-14.0-RELEASE-amd64-disc1.iso), 下载FreeBSD-14.0-RELEASE-amd64-disc1.iso

#### 3. 把镜像导入到Oracle VirtualBox

#### 4.配置




https://docs.freebsd.org/en/books/handbook/mac/

Chapter 9

Chapter 18. Mandatory Access Control

### 2. 开始实现功能



| 常量名                     | 含义                                       |
| -------------------------- | ------------------------------------------ |
| `EXTATTR_NAMESPACE_USER`   | 用户命名空间，**用户进程可以读写**         |
| `EXTATTR_NAMESPACE_SYSTEM` | 系统命名空间，**只有内核或特权进程可访问** |

你可以用命令给某个文件添加扩展属性：

```c
setextattr user secure 1 somefile.txt
```

这表示：

- 命名空间是 `user`
- 属性名是 `secure`
- 属性值是 `1`



```c
vn_extattr_get(vp, IO_NODELOCKED, EXTATTR_NAMESPACE_USER, "secure", ...)
```

表示

“我要读取 vnode vp 上属于用户空间的名为 secure 的扩展属性”。

`vnode` 是 **FreeBSD（以及其他 BSD 类 Unix 系统）内核中的一个重要数据结构**，用于统一表示**文件系统中的所有对象**，包括文件、目录、符号链接、设备节点等。

------

## 📦 简单理解：vnode 是“虚拟文件节点”

“vnode” 是 “**virtual node**” 的缩写，是 **VFS（Virtual File System，虚拟文件系统）** 的核心概念之一。

你可以把 vnode 看成内核中的一个“文件描述对象”，但不是用户进程 `open()` 得到的那个文件描述符，而是**内核层面上的抽象表示**。

------

## 🧩 vnode 是干什么用的？

它将不同类型、不同格式的文件系统（UFS, ZFS, NFS 等）统一抽象成一个通用的接口。

| 文件系统对象 | 对应的 vnode 作用           |
| ------------ | --------------------------- |
| 普通文件     | 提供读写接口、属性接口等    |
| 目录         | 提供遍历、添加/删除子项接口 |
| 设备文件     | 提供对设备的统一访问方式    |
| 套接字、FIFO | 也有 vnode 表示它们         |



------

## 📄 vnode 的结构（简化）

在 FreeBSD 内核中，一个 `struct vnode` 通常包含如下信息：

```
struct vnode {
    enum vtype v_type;           // 类型：VREG（普通文件）、VDIR（目录）等
    struct mount *v_mount;       // 所属文件系统
    struct vop_vector *v_op;     // 指向一组操作函数指针
    void *v_data;                // 指向具体文件系统的私有数据
    ...
};
```

------

## 📚 vnode 与文件访问的流程

当你在用户态执行：

```
open("/etc/passwd", O_RDONLY);
```

系统调用最终会：

1. **解析路径** → 得到对应的 vnode
2. **检查权限** → 通过 vnode 的属性
3. **建立文件描述符** → 关联到该 vnode
4. **返回给用户进程使用的 fd**

也就是说，**每个打开的文件，内核都通过 vnode 来表示和操作**。

------

## 🔐 vnode 在 MAC 模块中的作用

在 MAC（Mandatory Access Control）模块中，很多 hook 函数以 `vnode` 为参数，比如：

```
int secure_vnode_check_open(struct ucred *cred, struct vnode *vp, ...)
```

这里的 `vp`（vnode pointer）就表示你试图打开的那个文件或目录，MAC 模块可以通过它：

- 检查扩展属性（是否有 `user.secure`）
- 判断类型（文件？目录？设备？）
- 拿到挂载点信息、具体路径等

------

## ✅ 总结

| 名称       | vnode（virtual node）                    |
| ---------- | ---------------------------------------- |
| 是什么     | 内核中表示文件/目录的对象                |
| 属于       | VFS（虚拟文件系统）层                    |
| 作用       | 跨文件系统访问统一接口                   |
| 使用场景   | 内核内部访问文件、权限检查、挂载点解析等 |
| MAC 中用法 | 拿 vnode 判断是否需要限制访问            |



#### 2.基础部件

步骤一

编写一个 MAC 模块，当用户打开文件时：

- 系统调用 `open()` 会触发我们的 hook
- 我们打印一条日志，比如：`[mac_log] Process 1234 opened a file

创建一个 C 文件，比如 `mac_log.c`：

```C
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#include <sys/proc.h>

static int
mac_log_vnode_check_open(struct ucred *cred, struct vnode *vp,
                         struct label *vnodelabel, accmode_t accmode)
{
    struct proc *p = curproc;
    printf("[mac_log] Process %d opened a file\n", p->p_pid);
    return 0; // 允许打开
}

static struct mac_policy_ops mac_log_ops = {
    .mpo_vnode_check_open = mac_log_vnode_check_open,
};

MAC_POLICY_SET(&mac_log_ops, mac_log, "Simple open logger", MPC_LOADTIME_FLAG_UNLOADOK, NULL);
```



Makefile

## 步骤二：创建 Makefile

创建一个 Makefile 文件用于编译内核模块：

```makefile
KMOD    = mac_log
SRCS    = mac_log.c
.include <bsd.kmod.mk>
```

> 我要编译一个名字叫 `mac_log` 的内核模块，它的源代码文件是 `mac_log.c`。

FreeBSD 会使用你提供的信息，再加上系统自带的编译规则，自动完成：

- 编译 `.c` → `.o`
- 生成 `.ko` 模块（KLD 文件）
- 处理依赖

```c
KMOD = mac_log

```

KMOD 是 “Kernel Module”的缩写。

它的值是你要生成的内核模块的名字（不带 .ko）。

这一行告诉 Makefile：我最后想生成一个 mac_log.ko 文件。

SRCS = mac_log.c
这是源码文件的列表，告诉系统我们要编译的是 mac_log.c。

如果你有多个源文件，比如 a.c b.c，就写成：





- MALLOC_DEFINE

```
MALLOC_DEFINE(M_TAINT, "mac_secure_taint", "tainted-process list");
```

它的作用是：

> 在内核中定义一个新的 **内存分配标签（memory allocation type）**，名字叫 `M_TAINT`，描述为 `"mac_secure_taint"` 和 `"tainted-process list"`。

之后你就可以这样分配内存：

```
te = malloc(sizeof(*te), M_TAINT, M_WAITOK | M_ZERO);
```

也可以这样释放：

```
free(te, M_TAINT);
```

------

## 🧩 二、语法结构解析

```
MALLOC_DEFINE(name, shortdesc, longdesc)
```

### 参数说明：

| 参数        | 解释                                                         |
| ----------- | ------------------------------------------------------------ |
| `name`      | 一个 C 宏变量（如 `M_TAINT`），以后 `malloc()` 和 `free()` 会用这个作为分类标签 |
| `shortdesc` | 用于内核统计或调试的简短说明                                 |
| `longdesc`  | 更详细的描述，用于内核分析工具显示                           |



------

## 🔍 三、这个宏是怎么定义的？

这个宏定义在头文件 `<sys/malloc.h>` 中：

```
#define MALLOC_DEFINE(type, shortdesc, longdesc) \
    struct malloc_type type[1] = {               \
        { NULL, 0, shortdesc, longdesc }         \
    }
```

它背后实际是定义了一个结构体数组：

```
struct malloc_type M_TAINT[1] = {
    { NULL, 0, "mac_secure_taint", "tainted-process list" }
};
```

这个 `malloc_type` 会被 FreeBSD 内核的 malloc 管理器识别，用于：

- 统计这个类型分配了多少内存
- 给内核工具如 `vmstat -m` 提供内存分析报告





##### 内核链表

```c
struct taint_entry {
    LIST_ENTRY(taint_entry) link;
    pid_t pid;
};
```



```
LIST_ENTRY(taint_entry) link;
```

相当于

```c
struct {
    struct taint_entry *le_next;  // 指向下一个元素
    struct taint_entry **le_prev; // 指向前一个元素的指针
} link;
```




看似简单，其实它背后结合了 FreeBSD（BSD 风格）内核编程中非常重要的一套数据结构：内核链表（BSD 链表宏）。



static struct rwlock taint_lock;
FreeBSD 内核使用 struct rwlock 实现 读写锁，用于并发同步。

🔒 为什么需要加锁？
因为多个 CPU/线程可能会同时：

向 taint_head 插入节点（LIST_INSERT_HEAD）

遍历它（LIST_FOREACH）

删除节点（LIST_REMOVE）

不加锁会造成数据竞争，甚至内核崩溃。

🔐 为什么用 rwlock 而不是 mutex？
因为：

读多写少场景，读写锁更高效

多个 reader 可以同时持有读锁（rw_rlock）

写的时候需要独占写锁（rw_wlock）

例如：
rw_rlock(&taint_lock);    // 加读锁
rw_runlock(&taint_lock);  // 解读锁

rw_wlock(&taint_lock);    // 加写锁
rw_wunlock(&taint_lock);  // 解写锁
✅ 第三部分：static 的含义（非常重要）
在这两行中：


static LIST_HEAD(...) taint_head;
static struct rwlock taint_lock;
static 的作用是 限制变量作用域只在当前 C 文件中有效。

📍 为什么要这样？
防止模块中其他文件访问到这些全局变量

提高封装性

避免与其他模块/内核全局变量命名冲突

在内核模块中，几乎所有你不希望暴露给外部的全局变量或函数都应加 static。



```c
struct proc {
    pid_t        p_pid;        // 进程 ID
    struct ucred *p_ucred;     // 用户身份信息（谁在运行这个进程）
    struct filedesc *p_fd;     // 打开文件的描述符表
    struct proc *p_pptr;       // 父进程指针
    struct thread *p_threads;  // 线程链表（FreeBSD 是线程调度）
    int          p_state;      // 当前状态
    ...
};

```



# Challenge

For this challenge please use FreeBSD 14.0-RELEASE for everything.
Your submitted code should contain everything necessary to build your module, as well as build instructions.

## A simple module
Write a simple FreeBSD kernel module. This module should register itself as a MAC policy module and should have the following functionality:

1. Every open request on a file containing the extended attribute ```user.secure``` should be denied.
2. If such a request happened, the requesting process should be marked as ```tainted```.
3. All requests to remove extended attributes by a process marked ```tainted``` (or one of its descendants) on a file containing the extended attribute ```user.secure``` should be denied.
4. Your module has to be cleanly unloadable - no memory leaks!
5. Everything has to be appropriately synchronized, your module should not be subject to race-conditions



```c
/* mac_secure.c
 *
 * A small FreeBSD 14.0-RELEASE MAC policy module that:
 *   1. Denies open requests on files with the "user.secure" xattr;
 *   2. Marks such processes as "tainted";
 *   3. Denies any attempts by tainted processes to remove this xattr;
 *   4. Is cleanly unloadable (no memory leaks);
 *   5. Uses locking to ensure concurrency safety.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/errno.h>

#include <security/mac/mac_policy.h>

#define ATTR_NAMESPACE  EXTATTR_NAMESPACE_USER
#define ATTR_NAME       "secure"

//struct malloc_type M_TAINT[1] = {
//    { NULL, 0, "mac_secure_taint", "tainted-process list" }
//};
MALLOC_DEFINE(M_TAINT, "mac_secure_taint", "tainted-process list");
//定义了目标扩展属性 `user.secure` 的命名空间和名字。
/* ---------- taint tracking ---------- */
struct taint_entry {
    LIST_ENTRY(taint_entry) link;
    pid_t pid;
};

//#define LIST_HEAD_INITIALIZER(head) { NULL }
//struct {
//    struct taint_entry *lh_first;
//} taint_head = { NULL };
static LIST_HEAD(, taint_entry) taint_head = LIST_HEAD_INITIALIZER(taint_head);
static struct rwlock taint_lock;  /* protects taint_head */

static bool
proc_is_tainted(struct proc *p){//检查给定进程 p 是否已经被标记为 tainted（污染）
    struct taint_entry *te;
    bool tainted = false;

    rw_rlock(&taint_lock);//使用 rw_rlock() 给 taint_head 加读锁，表示我们只读链表，不会修改它。
    LIST_FOREACH(te, &taint_head, link) {// 相当于for (te = taint_head.lh_first; te != NULL; te = te->link.le_next)
        if (te->pid == p->p_pid) {
            tainted = true;
            break;
        }
    }
    rw_runlock(&taint_lock);
    return (tainted);
}

static void
proc_mark_tainted(struct proc *p){//将指定的进程 p 标记为 tainted
    struct taint_entry *te;

    if (proc_is_tainted(p))
        return;

    te = malloc(sizeof(*te), M_TAINT, M_WAITOK | M_ZERO);
    //分配一块大小为 struct taint_entry 的内存，类型为 M_TAINT，并初始化为全 0。
    //M_WAITOK 如果内存不够，允许睡眠等待（而不是立刻失败）
    te->pid = p->p_pid;

    rw_wlock(&taint_lock);
    LIST_INSERT_HEAD(&taint_head, te, link);//把这个 taint_entry 插入到 taint 链表的头部。
    rw_wunlock(&taint_lock);
}

static void
proc_untaint(struct proc *p)//把一个被标记为 tainted 的进程，从 taint 列表中移除，并释放对应内存。
{
    struct taint_entry *te;

    rw_wlock(&taint_lock);
    LIST_FOREACH(te, &taint_head, link) {// 相当于for (te = taint_head.lh_first; te != NULL; te = te->link.le_next)
        if (te->pid == p->p_pid) {
            LIST_REMOVE(te, link);//这是 BSD 提供的宏，用于从链表中删除 te 节点
            free(te, M_TAINT);
            break;
        }
    }
    rw_wunlock(&taint_lock);
}

static bool
vnode_has_secure(struct vnode *vp)//判断一个 vnode（文件或目录）是否拥有扩展属性 user.secure。
{
    char dummy;
    int buflen = 1;
    int error;

    error = vn_extattr_get(vp, //要操作的 vnode
                           IO_NODELOCKED, //表示 vnode 已加锁，避免在此函数内部再次加锁（防止死锁）
                           ATTR_NAMESPACE,//命名空间，一般是 EXTATTR_NAMESPACE_USER，也就是 user
                           ATTR_NAME,//属性名，这里是 "secure"
                           &buflen,//输入：缓冲区大小；输出：实际读取的字节数
                           &dummy,//缓冲区指针，接收扩展属性内容（我们不关心它）
                           curthread);//当前线程指针，表示这是谁在发起操作（权限检查用）
    //这个函数是 FreeBSD 内核中读取扩展属性的标准接口。

    return (error == 0); //如果 vn_extattr_get 返回 0，表示成功读取属性 //否则返回错误码（如 ENOATTR 表示属性不存在）
}

/* ---------- MAC hooks ---------- */
static int
secure_vnode_check_open(struct ucred *cred, struct vnode *vp,
                        struct label *vplabel, accmode_t accmode){
    //struct ucred *cred 它是 FreeBSD 内核中非常重要的一个结构体指针，用于描述：“当前操作的用户身份信息”，也就是一个进程或线程的权限凭证（credentials）。
    //struct ucred {
   // uint32_t cr_ref;       // 引用计数
   // uid_t    cr_uid;       // 实际用户 ID（effective UID）
   // uid_t    cr_ruid;      // 实际用户 ID（real UID）
   // gid_t    cr_gid;       // 主组 ID
   // gid_t    cr_groups[NGROUPS]; // 所属组列表
   // int      cr_ngroups;   // 有多少个组
   // ...
//};
    
    
    if (vnode_has_secure(vp)) {//判断文件是否有 user.secure 属性
        proc_mark_tainted(curproc);
        return (EPERM);// EPERM 是 C 系统编程中一个非常常见的 错误码，它的含义是：Operation not permitted（操作不被允许）
    }
    return (0);
}
//curproc 和 curthread 是 FreeBSD 内核中两个非常关键的全局变量，用于表示当前正在运行的“进程”和“线程”。
//这两个变量随时指向正在被 CPU 执行的代码的上下文环境，几乎在所有内核子系统（VFS、MAC、网络）中都要用到。
//curproc	struct proc *	当前运行的 进程	获取当前进程的 PID、UID、访问控制、文件描述符等
//curthread	struct thread *	当前运行的 线程	获取线程栈、错误码、调度状态、I/O 权限等


static int
secure_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
                              struct label *vplabel, int attrnamespace,
                              const char *name){//阻止 tainted 进程去修改带有 user.secure 扩展属性的文件的属性。
    if (attrnamespace == ATTR_NAMESPACE &&
        name != NULL && strcmp(name, ATTR_NAME) == 0) {//属性命名空间是否是 user（即 EXTATTR_NAMESPACE_USER）
        if (proc_is_tainted(curproc) && vnode_has_secure(vp))
            return (EPERM); //我们只想阻止那些：“已经被 tainted 的进程 又 试图修改一个真正是 user.secure 的文件”的行为。?????????????
    }
    return (0);
}

static void
secure_policy_init(struct mac_policy_conf *conf __unused){//是你 FreeBSD MAC 模块的初始化函数，在模块加载时由内核自动调用。
    rw_init(&taint_lock, "mac_secure taint lock");
    //taint_lock 是一个全局变量，类型为 struct rwlock
//在使用任何 rw_wlock()、rw_rlock() 之前必须初始化！
//第二个参数是字符串描述，用于调试、锁统计信息输出
//init 之后才能安全使用
//rw_rlock(&taint_lock);    // 加读锁
//rw_runlock(&taint_lock);  // 解读锁
//rw_wlock(&taint_lock);    // 加写锁
//rw_wunlock(&taint_lock);  // 解写锁
}

static void
secure_policy_destroy(struct mac_policy_conf *conf __unused){
    //是 FreeBSD MAC 模块的卸载钩子函数（销毁函数），它非常重要，作用是：
	//在模块被卸载（kldunload）时清除 taint 列表和销毁读写锁，确保没有内存泄漏、没有脏资源留下。
    struct taint_entry *te;

    rw_wlock(&taint_lock);
    while ((te = LIST_FIRST(&taint_head)) != NULL) {
        LIST_REMOVE(te, link);
        free(te, M_TAINT);
    }
    rw_wunlock(&taint_lock);
    rw_destroy(&taint_lock);// 把锁本身释放掉
}

static struct mac_policy_ops secure_ops = { // 定义一个结构体 secure_ops，类型是 mac_policy_ops，这是 FreeBSD MAC 框架中用于注册你的安全策略行为的结构体。
    .mpo_init                     = secure_policy_init,
    .mpo_destroy                  = secure_policy_destroy,
    .mpo_vnode_check_open         = secure_vnode_check_open,
    .mpo_vnode_check_setextattr   = secure_vnode_check_setextattr,
};

MAC_POLICY_SET(&secure_ops, mac_secure, "Deny open/remove user.secure",
               MPC_LOADTIME_FLAG_UNLOADOK, NULL); //我有一个策略模块叫 mac_secure，它的行为定义在 secure_ops 结构里，请你以后每次 open 文件时调用我写的 secure_vnode_check_open。
//&secure_ops 所有 hook 函数定义的结构体地址
//mac_secure 模块内部名称
//"My policy"	模块对外说明文字（比如打印在日志中）
//MPC_LOADTIME_FLAG_UNLOADOK “这个 MAC 策略模块可以被卸载（unload）。”
//// 在 sys/security/mac_policy.h 中
//#define MPC_LOADTIME_FLAG_UNLOADOK    0x00000001 所以，它只是一个 int 类型的标志位值，用来传给注册函数，告诉系统你这个模块是否可以被 kldunload 卸载。
//#define MPC_LOADTIME_FLAG_UNLOADOK     0x00000001  // 可卸载
//#define MPC_LOADTIME_FLAG_NOTLATE      0x00000002  // 必须在启动时加载（不能late load）
//#define MPC_LOADTIME_FLAG_LABELMBUFS   0x00000004  // 标记 mbuf 网络数据结构
//#define MPC_LOADTIME_FLAG_LABELINPCB   0x00000008  // 标记 socket 的 inpcb
//MODULE_VERSION(mac_secure, 1);


```





#### 写完之后

```c
# 1. 编译模块
make

# 2. 查看模块是否已经在系统中（应该还没）
kldstat

# 3. 加载模块
sudo kldload ./hello.ko

# 4. 再次查看
kldstat | grep hello   # 现在应该能看到 hello.ko

# 5. 卸载模块
sudo kldunload hello

# 6. 再查看（已移除）
kldstat 

```



Appendix 

```c
/*
 * KLD Skeleton
 * Inspired by Andrew Reiter's Daemonnews article
 */

#include <sys/types.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/module.h>
#include <sys/kernel.h> /* types used in module initialization */

/*
 * Load handler that deals with the loading and unloading of a KLD.
 */

static int
skel_loader(struct module *m, int what, void *arg)
{
	int err = 0;

	switch (what) {
	case MOD_LOAD:                /* kldload */
		uprintf("Skeleton KLD loaded.\n");
		break;
	case MOD_UNLOAD:
		uprintf("Skeleton KLD unloaded.\n");
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return(err);
}

/* Declare this module to the rest of the kernel */

static moduledata_t skel_mod = {
	"skel",
	skel_loader,
	NULL
};

DECLARE_MODULE(skeleton, skel_mod, SI_SUB_KLD, SI_ORDER_ANY);
```



最后一句用的是这个

```c
#define DECLARE_MODULE(name, data, sub, order)          \
    static struct module __CONCAT(name, _mod) = {       \
        .name = #name,                                  \
        .data = &data,                                  \
        .subsystem = sub,                               \
        .order = order,                                 \
        .handler = module_register_init,                \
        .arg = NULL,                                    \
    };                                                  \
    SYSINIT(__CONCAT(name, _init), sub, order,          \
            module_register, &__CONCAT(name, _mod));    \
    SYSUNINIT(__CONCAT(name, _uninit), sub, order,      \
              module_unregister, &__CONCAT(name, _mod));
```













```c
#include<sys/param.h>
#include<sys/kernel.h>
#include<sys/module.h>
#include <sys/systm.h>

static int hello_loader(struct module *m, int event, void *arg)
{
    switch(event) {
        case MOD_LOAD:
            uprintf("hello_kld - Hello World\n");
            break;
        case MOD_UNLOAD:
            uprintf("hello_kld - Goodbye, Kernel\n");
            break;
        default:
            return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t hello_mod = {
    "Hello World Kernel Module",
    hello_loader,
    NULL,
};

DECLARE_MODULE(hello_world, hello_mod, SI_SUB_KLD, SI_ORDER_ANY);
```

reference



https://docs.freebsd.org/en/books/handbook/mac/

https://docs.freebsd.org/en/books/arch-handbook/mac/

https://man.freebsd.org/cgi/man.cgi?query=mac&apropos=0&sektion=9&manpath=FreeBSD+14.2-RELEASE+and+Ports&arch=default&format=html





**竞态条件**（**race condition**）是并发编程中常见的问题之一，指的是：

> 当两个或多个线程（或进程）**同时访问某个共享资源**，并且至少有一个是**写操作**，**程序的最终结果就可能依赖于它们的执行顺序**。

### 如何避免竞态条件？

通过**同步机制**来保护共享资源，例如：

- 🔒 **互斥锁（mutex）**
- 🔁 **读写锁（rwlock）**
- 🧩 **信号量（semaphore）**
- 🧵 **原子操作（atomic）**

这样可以确保同一时刻**只有一个线程访问关键数据**

---
title: HTB渗透测试
date: 2025-02-25 11:35:57
tags:
  - 渗透测试
math: true
---

# 渗透测试

### 信息安全概述

[信息安全](https://en.wikipedia.org/wiki/Information_security)(infosec) 是一个庞大的领域。该领域在过去几年中发展迅速。它提供许多专业，包括但不限于：

- 网络和基础设施安全
- 应用程序安全
- 安全测试
- 系统审计
- 业务连续性规划
- 数字取证
- 事件检测与响应

简而言之，信息安全就是保护数据免遭未经授权的访问、更改、非法使用、破坏等的实践。信息安全专业人员还会采取行动来减少此类事件的整体影响。

数据可以是电子的或物理的，可以是有形的（例如设计蓝图）或无形的（知识）。在我们的信息安全职业生涯中，一个经常出现的常用短语是保护“数据的机密性、完整性和可用性”，或 CIA

#### 风险管理流程

数据保护必须注重高效而有效的政策实施，而不会对组织的业务运营和生产力产生负面影响。为实现这一点，组织必须遵循一个称为 的过程`risk management process`。此过程涉及以下五个步骤：

| 步骤                   | 解释                                                         |
| ---------------------- | ------------------------------------------------------------ |
| `Identifying the Risk` | 识别企业面临的风险，例如法律、环境、市场、监管和其他类型的风险。 |
| `Analyze the Risk`     | 分析风险以确定其影响和概率。应将风险映射到组织的各种政策、程序和业务流程。 |
| `Evaluate the Risk`    | 评估、排列和确定风险的优先次序。然后，组织必须决定接受（不可避免）、避免（更改计划）、控制（减轻）或转移风险（投保）。 |
| `Dealing with Risk`    | 尽可能地消除或控制风险。这是通过直接与风险相关的系统或流程的利益相关者进行交互来处理的。 |
| `Monitoring Risk`      | 必须持续监控所有风险。应持续监控风险，以防任何可能改变其影响分数的情况变化`i.e., from low to medium or high impact`。 |

#### 红队 vs. 蓝队

用最简单的话来说，`red team`扮演攻击者的角色，而`blue team`扮演防御者的角色。

#### 渗透测试人员的作用

安全评估员（网络渗透测试员、Web 应用程序渗透测试员、红队成员等）可帮助组织识别其外部和内部网络中的风险。这些风险可能包括网络或 Web 应用程序漏洞、敏感数据泄露、配置错误或可能导致声誉受损的问题。

### 开始使用渗透测试发行版

作为渗透测试人员，我们必须了解如何设置、维护和保护 Linux 和 Windows 攻击机器。

有许多 Linux 发行版 (distro) 可用于渗透测试。本节将介绍如何设置和使用[Parrot OS](https://www.parrotsec.org/)。该发行版用于我们将在整个学院看到的 Pwnbox，经过定制以练习和解决我们将遇到的各个模块中的练习。

有很多方法可以设置我们的本地渗透测试发行版。我们可以将其安装为基本操作系统（尽管不推荐），将我们的工作站配置为双启动（在操作系统之间来回切换很耗时），或者使用虚拟化进行安装。

`hypervisor`是一种允许我们创建和运行虚拟机 (VM) 的软件。它使我们能够使用主机（台式机或笔记本电脑）通过虚拟共享内存和处理资源来运行多个 VM。
虚拟机管理程序上的 VM 与主操作系统隔离运行，这在我们的生产网络和易受攻击的网络（例如 Hack The Box）之间或在从 VM 连接到客户端环境时提供了一层隔离和保护（尽管 VM 突破漏洞确实会不时出现）。

为了实现我们的目的，我们将使用 Parrot Security (Pwnbox) 的修改版本（可[在此处](https://www.parrotsec.org/download/)获取）来构建本地虚拟机。

### 保持井然有序

在攻击单个盒子、实验室或客户端环境时，我们应该在攻击机上有一个清晰的文件夹结构来保存数据，例如：范围信息、枚举数据、利用尝试的证据、凭据等敏感数据以及在侦察、利用和后利用期间获得的其他数据。示例文件夹结构可能如下所示：

``` shell
Fyind@htb[/htb]$ tree Projects/

Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

这里我们为客户创建了一个文件夹`Acme Company`，其中包含两项评估：内部渗透测试 (IPT) 和外部渗透测试 (EPT)。每个文件夹下都有子文件夹，用于保存扫描数据、任何相关工具、日志输出、范围信息（即要提供给我们的扫描工具的 IP/网络列表），还有一个证据文件夹，其中可能包含评估期间检索到的任何凭据、检索到的任何相关数据以及屏幕截图。

### 使用 VPN 连接

虚拟专用网络[(VPN)](https://en.wikipedia.org/wiki/Virtual_private_network)允许我们连接到私有（内部）网络并访问主机和资源，就像我们直接连接到目标专用网络一样。VPN 通过加密通道上的通信来提供一定程度的隐私和安全性，以防止窃听和访问通过通道的数据。

![图像](https://academy.hackthebox.com/storage/modules/77/GettingStarted.png)

远程访问 VPN 主要有两种类型：基于客户端的 VPN 和 SSL VPN。SSL VPN 使用 Web 浏览器作为 VPN 客户端。连接建立在浏览器和 SSL VPN 网关之间，可以配置为仅允许访问基于 Web 的应用程序（例如电子邮件和内部网站点），甚至内部网络，但无需最终用户安装或使用任何专用软件。基于客户端的 VPN 需要使用客户端软件来建立 VPN 连接。连接后，用户的主机将像直接连接到公司网络一样工作，并能够访问服务器配置允许的任何资源（应用程序、主机、子网等）。一些企业 VPN 将为员工提供对内部公司网络的完全访问权限，而另一些企业 VPN 将用户置于为远程工作人员保留的特定网段上。

#### 为什么要使用 VPN？

我们可以使用 VPN 服务（例如`NordVPN`或 ）`Private Internet Access`并连接到我们国家/地区其他地方或世界其他地方的 VPN 服务器，以隐藏我们的浏览流量或伪装我们的公共 IP 地址。这可以为我们提供一定程度的安全性和隐私性。

但是，由于我们连接到的是公司的服务器，因此数据可能会被记录，或者 VPN 服务可能不遵循安全最佳实践或他们宣传的安全功能。使用 VPN 服务存在风险，即提供商没有履行其承诺并记录所有数据。使用 VPN 服务**并不能**保证匿名性或隐私性，但对于绕过某些网络/防火墙限制或连接到可能的敌对网络（即公共机场无线网络）很有用。

#### 连接到 HTB VPN

HTB 网络中的主机无法直接连接到互联网。连接到 HTB VPN（或任何渗透测试/黑客实验室）时，我们应始终将网络视为“敌对”。我们应该只从虚拟机连接，如果攻击虚拟机上启用了 SSH，则不允许密码验证，锁定任何 Web 服务器，并且不要在攻击虚拟机上留下敏感信息（即，不要使用我们用于执行客户端评估的同一虚拟机玩 HTB 或其他易受攻击的网络）。连接到 VPN 时（在 HTB 学院或主 HTB 平台内），我们使用以下命令进行连接：

``` shell
sudo openvpn user.ovpn
```

则如果成功连接到 VPN，`ifconfig`我们将看到一个适配器。

输入后`netstat -rn`我们将看到可通过 VPN 访问的网络。

### 常用术语

#### shell

`Shell`是一个非常常见的术语，在我们的旅程中我们会一次又一次地听到它。它有几种含义。在 Linux 系统上，shell 是一个程序，它通过键盘从用户那里获取输入，并将这些命令传递给操作系统以执行特定功能。例如 Linux 终端、Windows 命令行 (cmd.exe) 和 Windows PowerShell。Bash是Unix系统原始shell程序[sh](https://man7.org/linux/man-pages/man1/sh.1p.html)`bash`的增强版本。除此之外还有其他shell，包括但不限于[Zsh](https://en.wikipedia.org/wiki/Z_shell)，[Tcsh](https://en.wikipedia.org/wiki/Tcsh)，[Ksh](https://en.wikipedia.org/wiki/KornShell)，[Fish shell](https://en.wikipedia.org/wiki/Fish_(Unix_shell))等。shell 连接主要有三种类型：

| **shell type**  | **描述**                                                     |
| --------------- | ------------------------------------------------------------ |
| `Reverse shell` | 启动与攻击箱上的“监听器”的连接。                             |
| `Bind shell`    | “绑定”到目标主机上的特定端口并等待来自我们的攻击箱的连接。   |
| `Web shell`     | 通过 Web 浏览器运行操作系统命令，通常不是交互式或半交互式的。它还可用于运行单个命令（即利用文件上传漏洞并上传`PHP`脚本来运行单个命令）。 |

#### 端口

[端口](https://en.wikipedia.org/wiki/Port_(computer_networking))是网络连接开始和结束的虚拟点。它们基于软件并由主机操作系统管理。端口与特定进程或服务相关联，并允许计算机区分不同的流量类型个。端口都分配有一个编号，许多端口在所有联网设备上都是标准化的（尽管服务可以配置为在非标准端口上运行）。例如，`HTTP`消息（网站流量）通常发送到端口`80`，而`HTTPS`消息发送到端口 ，`443`除非另有配置。

端口有两种类型：[传输控制协议 (TCP)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)和[用户数据报协议 (UDP)](https://en.wikipedia.org/wiki/User_Datagram_Protocol)。

`TCP`面向连接，这意味着必须先建立客户端和服务器之间的连接，然后才能发送数据。服务器必须处于监听状态，等待客户端的连接请求。
`UDP`采用无连接通信模型。没有“握手”，因此引入了一定程度的不可靠性，因为无法保证数据传输。`UDP`当不需要纠错/检查或由应用程序本身处理时很有用。

| port              | 协议                    |
| ----------------- | ----------------------- |
| `20`/ `21`（TCP） | `FTP`                   |
| `22`（TCP）       | `SSH`                   |
| `23`（TCP）       | `Telnet`                |
| `25`（TCP）       | `SMTP`                  |
| `80`（TCP）       | `HTTP`                  |
| `161`（TCP/UDP）  | `SNMP`                  |
| `389`（TCP/UDP）  | `LDAP`                  |
| `443`（TCP）      | `SSL`/ `TLS`（`HTTPS`） |
| `445`（TCP）      | `SMB`                   |
| `3389`（TCP）     | `RDP`                   |

作为信息安全专业人员，我们必须能够快速回忆起有关各种主题的大量信息。对于我们（尤其是作为渗透测试人员）来说，牢牢掌握许多`TCP`和`UDP`端口并能够仅通过其编号快速识别它们（即知道端口`21`是`FTP`、端口`80`是、`HTTP`端口`88`是`Kerberos`）而无需查找是至关重要的。

#### 什么是 Web 服务器

Web 服务器是在后端服务器上运行的应用程序，它处理`HTTP`来自客户端浏览器的所有流量，将其路由到请求目标页面，并最终响应客户端浏览器。

我们经常会听到/看到对[OWASP Top 10](https://owasp.org/www-project-top-ten/)的引用。这是开放 Web 应用程序安全项目 (OWASP) 维护的 Web 应用程序十大漏洞的标准化列表。

| Number | Category                                                     | Description                                                  |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1.     | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc. |
| 2.     | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | Failures related to cryptography which often leads to sensitive data exposure or system compromise. |
| 3.     | [Injection](https://owasp.org/Top10/A03_2021-Injection/)     | User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are SQL injection, command injection, LDAP injection, etc. |
| 4.     | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/) | These issues happen when the application is not designed with security in mind. |
| 5.     | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information. |
| 6.     | [Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) | Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date. |
| 7.     | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | Authentication-related attacks that target user's identity, authentication, and session management. |
| 8.     | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) | Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). |
| 9.     | [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.. |
| 10.    | [Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/) | SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL). |

### 基本工具

#### ssh

[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell))是一种默认在端口上运行的网络协议`22`，它为系统管理员等用户提供了一种安全的远程访问计算机的方式。 SSH 可以使用密码验证或无密码配置，使用 SSH 公钥/私钥对进行[公钥验证](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/)。SSH 可用于通过互联网远程访问同一网络上的系统，使用端口转发/代理方便地连接其他网络中的资源，以及从远程系统上传/下载文件。

#### netcat

`ncat`或`nc`是用于与 TCP/UDP 端口交互的出色网络实用程序。它的主要用途是连接到 shell，我们将在本模块后面讨论。除此之外，它`netcat`还可用于连接到任何侦听端口并与在该端口上运行的服务交互。我们可以看到，端口 22 向我们发送了它的横幅，表明`SSH`正在运行。这种技术称为`Banner Grabbing`，可以帮助识别在特定端口上运行的服务。

``` shell
netcat 10.10.10.10 22
```

#### Using Tmux

Terminal multiplexers 终端多路复用器（例如`tmux`或`Screen`）是扩展标准 Linux 终端功能的绝佳实用程序，例如在一个终端内拥有多个窗口并在它们之间跳转。

安装：

``` shell
sudo apt install tmux -y
```

* 启动 `tmux`
* 命令前缀： `Ctrl+B` ，
* 新建窗口 `Ctrl+B` , `C`
* 切换窗口 `Ctrl+B` , `<编号>`
* 竖直切分 `Ctrl+B`, `Shift+%`
* 水平切分 `Ctrl+B`, `Shift+"`
* 切换 `Ctrl+B` , `方向键` 

https://tmuxcheatsheet.com/ 这个是常用命令

#### Vim

[Vim](https://linuxcommand.org/lc3_man_pages/vim1.html)是一款出色的文本编辑器，可用于在 Linux 系统上编写代码或编辑文本文件。使用的一大优点`Vim`是它完全依赖于键盘，因此您不必使用鼠标，这（一旦我们掌握了它）将大大提高您编写/编辑代码的生产力和效率。

### 服务扫描

#### Nmap

基础扫描

``` shell
nmap 10.129.42.253
```

默认情况下，`Nmap`将进行 TCP 扫描，除非特别要求执行 UDP 扫描。`STATE`确认这些端口是开放的。有时我们会看到列出的其他端口具有不同的状态

随着我们越来越熟悉，我们会注意到几个端口通常与 Windows 或 Linux 相关联。例如，端口 3389 是远程桌面服务的默认端口，这很好地表明目标是 Windows 计算机。

我们可以使用`-sC`参数来指定`Nmap`应使用脚本来尝试获取更详细的信息

`-sV`参数指示`Nmap`执行版本扫描。在此扫描中，Nmap 将对目标系统上的服务进行指纹识别，并识别服务协议、应用程序名称和版本。

`-p-`告诉 Nmap 我们要扫描所有 65,535 个 TCP 端口。

#### 其他脚本：

指定`-sC`将针对目标运行许多有用的默认脚本，但在某些情况下需要运行特定脚本。

``` shell
nmap --script <script name> -p<port> <host>
```

#### 横幅抓取

如前所述，横幅抓取是一种快速对服务进行指纹识别的有用技术。通常，服务会在发起连接后显示横幅来表明自己的身份。如果`nmap -sV --script=banner <target>`指定了语法，Nmap 将尝试抓取横幅。

#### FTP

熟悉 FTP 是值得的，因为它是一种标准协议，并且此服务通常包含有趣的数据。

`ftp`让我们使用命令行实用程序连接到该服务。

``` shell
Fyind@htb[/htb]$ ftp -p 10.129.42.253

Connected to 10.129.42.253.
220 (vsFTPd 3.0.3)
Name (10.129.42.253:user): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
227 Entering Passive Mode (10,129,42,253,158,60).
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
226 Directory send OK.

ftp> cd pub
250 Directory successfully changed.

ftp> ls
227 Entering Passive Mode (10,129,42,253,182,129).
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            18 Feb 25 19:25 login.txt
226 Directory send OK.

ftp> get login.txt
local: login.txt remote: login.txt
227 Entering Passive Mode (10,129,42,253,181,53).
150 Opening BINARY mode data connection for login.txt (18 bytes).
226 Transfer complete.
18 bytes received in 0.00 secs (165.8314 kB/s)

ftp> exit
221 Goodbye.
```

#### SMB

SMB（服务器消息块）是 Windows 机器上流行的协议，为垂直和横向移动提供了许多载体。敏感数据（包括凭据）可能位于网络文件共享中，某些 SMB 版本可能容易受到[EternalBlue](https://www.avast.com/c-eternalblue)等 RCE 攻击。仔细枚举这个潜在的攻击面至关重要。`Nmap`有许多用于枚举 SMB 的脚本，例如[smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)，它将与 SMB 服务交互以提取报告的操作系统版本。

``` shell
nmap --script smb-os-discovery.nse -p445 10.10.10.40
```

SMB 允许用户和管理员共享文件夹，并允许其他用户远程访问这些文件夹。这些共享中通常包含敏感信息（例如密码）的文件。可以枚举并与 SMB 共享交互的工具是[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)。该`-L`标志指定我们要检索远程主机上可用共享的列表，同时`-N`抑制密码提示。

``` shell
smbclient -N -L \\\\10.129.42.253
```

之后可能看到文件夹 `users` 可以用下面的来登录

``` shell
smbclient -U bob \\\\10.129.42.253\\users
```

使用 `get` 可以下载文件，类似ftp

#### SNMP

SNMP社区字符串提供了有关路由器或设备的信息和统计数据，帮助我们访问设备。制造商的默认社区字符串“public”和“private”通常没有更改。在SNMP版本1和2c中，访问控制是通过明文的社区字符串进行的，只要知道字符串名称，就能获得访问权限。SNMP版本3才加入了加密和身份验证功能。

`onesixtyone` 是一个用于暴力破解SNMP社区字符串的工具，可以通过常见的社区字符串字典文件（如`dict.txt`）进行扫描。通过这种方式，你可以测试多个社区字符串，看是否能够成功访问目标设备。

``` shell
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
```

### 网络枚举

在执行服务扫描时，我们经常会遇到在端口 80 和 443 上运行的 Web 服务器。Web 服务器托管 Web 应用程序（有时不止 1 个），这些应用程序在渗透测试期间通常会提供相当大的攻击面和非常高价值的目标。正确的 Web 枚举至关重要，尤其是当组织没有公开许多服务或这些服务已得到适当修补时。

发现 Web 应用程序后，我们总是需要检查是否可以发现 Web 服务器上任何不打算公开访问的隐藏文件或目录。我们可以使用[ffuf](https://github.com/ffuf/ffuf)或[GoBuster](https://github.com/OJ/gobuster)等工具来执行此目录枚举。

``` shell
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

HTTP 状态代码`200`表示资源请求成功，而 403 HTTP 状态代码表示我们被禁止访问该资源。301 状态代码表示我们正在被重定向，这不是失败的情况。我们有必要熟悉各种 HTTP 状态代码，可[在此处](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)找到。

#### 横幅抓取/Web 服务器标头

在上一节中，我们讨论了用于一般目的的横幅抓取。Web 服务器标头可以很好地显示 Web 服务器上托管的内容。它们可以揭示正在使用的特定应用程序框架、身份验证选项以及服务器是否缺少必要的安全选项或配置错误。

``` shell
curl -IL https://www.inlanefreight.com
```

另一个方便的工具是[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)，它可用于截取目标 Web 应用程序的屏幕截图、提取指纹并识别可能的默认凭据。

我们可以使用命令行工具提取Web服务器、支持框架和应用程序的版本`whatweb`。这些信息可以帮助我们确定所使用的技术并开始搜索潜在的漏洞。

#### DNS 子域名枚举

子域上还可能托管着重要资源，例如管理面板或具有可利用的附加功能的应用程序。我们可以使用标志`GoBuster`来枚举给定域的可用子域，`dns`以指定 DNS 模式。首先，让我们克隆 SecLists GitHub [repo](https://github.com/danielmiessler/SecLists)，其中包含许多可用于模糊测试和利用的有用列表

接下来，向文件中添加 DNS 服务器（例如 1.1.1.1）`/etc/resolv.conf`

``` shell
sudo apt install seclists -y
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

#### Robots.txt

网站通常会包含一个`robots.txt`文件，其目的是指示搜索引擎网络爬虫（例如 Googlebot）哪些资源可以访问，哪些不能访问以进行索引。该`robots.txt`文件可以提供有价值的信息，例如私人文件和管理页面的位置。

#### 源代码

检查我们遇到的任何网页的源代码也是值得的。我们可以点击`[CTRL + U]`在浏览器中打开源代码窗口。

### 公开漏洞

一旦我们确定了在扫描中识别出的端口上运行的服务`Nmap`，第一步就是查看是否有任何应用程序/服务存在任何公开漏洞。

一个著名的用于此目的的工具是`searchsploit`，我们可以使用它来搜索任何应用程序的公开漏洞/漏洞利用。我们可以使用以下命令安装它：

``` shell
sudo apt install exploitdb -y
```

我们可以`searchsploit`通过名称搜索特定的应用程序，如下所示：

``` shell
Fyind@htb[/htb]$ searchsploit openssh 7.2

----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                     | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                               | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                                                                              | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                      | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                         | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                         | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                     | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                         | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration      
```

我们还可以利用在线漏洞数据库来搜索漏洞，例如[Exploit DB](https://www.exploit-db.com/)、[Rapid7 DB](https://www.rapid7.com/db/)或[Vulnerability Lab](https://www.vulnerability-lab.com/)。[Web 应用程序简介](https://academy.hackthebox.com/module/details/75)模块讨论了 Web 应用程序的公共漏洞。

#### Metasploit 入门

Metasploit Framework (MSF) 是渗透测试人员的绝佳工具。它包含许多针对许多公共漏洞的内置漏洞利用程序，并提供了一种针对易受攻击的目标使用这些漏洞利用程序的简便方法。

要运行`Metasploit`，我们可以使用以下`msfconsole`命令：

``` shell
msfconsole
```

搜索漏洞

``` shell
search exploit <xxx>
```

使用漏洞

``` shell
use auxiliary/scanner/http/wp_simple_backup_file_read
```

设置

``` shell
show options # 看有哪些
set RHOSTS 94.237.54.116
set RPORT 42821
set LHOST tun0
set FILEPATH /flag.txt
```

利用

``` shell
exploit
```


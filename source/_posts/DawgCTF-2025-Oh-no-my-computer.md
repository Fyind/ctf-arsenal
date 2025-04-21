---
title: DawgCTF 2025 Oh no,my computer!
date: 2025-04-21 12:38:06
categories: [CTF, Forensics]
tags: [Forensics, Vodatility, dnSpy, Writeup]
---

# Oh no, my computer!

## 题目

As an Incident Response (IR) analyst, you've been contacted by the HR department regarding a recently terminated employee. Upon learning of their impending dismissal, the employee reportedly proceeded to hurl their workstation out the window from the 66th floor. Fortunately, no one was injured. Even more fortunately, HR anticipated trouble and notified you in advance. Acting quickly, you were able to capture a memory dump of the employee's machine with the encrypted file believed to contain the bank account information where funds were transferred. Can you recover the destination bank account details from the provided artifacts?

附件：一个 `mem.dmp` 和 `bank_account.txt.enc`

## Writeup

先用 Vodatility 3 分析，使用 `pslist` 和 `cmdline` 这两个插件

``` shell
vol.exe -f .\mem.dmp windows.pslist
```

输出

``` shell
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xfa800184b890  82      473     N/A     False   2025-04-18 07:54:15.000000 UTC  N/A     Disabled
220     4       smss.exe        0xfa8002058b30  2       32      N/A     False   2025-04-18 07:54:15.000000 UTC  N/A     Disabled
296     280     csrss.exe       0xfa80028eba20  9       343     0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
344     280     wininit.exe     0xfa8001932350  3       78      0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
352     336     csrss.exe       0xfa80018d1060  8       198     1       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
380     336     winlogon.exe    0xfa8002955860  6       119     1       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
440     344     services.exe    0xfa800210bb30  9       191     0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
448     344     lsass.exe       0xfa80029a6b30  11      543     0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
456     344     lsm.exe 0xfa80029abb30  10      139     0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
548     440     svchost.exe     0xfa8002a0eb30  10      354     0       False   2025-04-18 07:54:17.000000 UTC  N/A     Disabled
628     440     svchost.exe     0xfa8002a2d710  8       238     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
716     440     svchost.exe     0xfa8002a63520  21      460     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
768     440     svchost.exe     0xfa8002a8c680  19      390     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
796     440     svchost.exe     0xfa8002a9eb30  37      894     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
884     716     audiodg.exe     0xfa8002ac5150  7       128     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
960     440     svchost.exe     0xfa8002af56f0  12      269     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
244     440     svchost.exe     0xfa8002b24b30  18      387     0       False   2025-04-18 07:54:18.000000 UTC  N/A     Disabled
1072    440     spoolsv.exe     0xfa8002bbeb30  13      284     0       False   2025-04-18 07:54:19.000000 UTC  N/A     Disabled
1124    440     svchost.exe     0xfa8002bd8b30  20      321     0       False   2025-04-18 07:54:19.000000 UTC  N/A     Disabled
1240    440     svchost.exe     0xfa8002c5ab30  12      219     0       False   2025-04-18 07:54:20.000000 UTC  N/A     Disabled
1860    768     dwm.exe 0xfa8002e47510  4       73      1       False   2025-04-18 07:54:23.000000 UTC  N/A     Disabled
1876    440     taskhost.exe    0xfa8002e1d060  9       132     1       False   2025-04-18 07:54:23.000000 UTC  N/A     Disabled
1932    1848    explorer.exe    0xfa8002e5b5f0  45      1004    1       False   2025-04-18 07:54:23.000000 UTC  N/A     Disabled
1824    440     SearchIndexer.  0xfa80018d49e0  15      643     0       False   2025-04-18 07:54:30.000000 UTC  N/A     Disabled
1312    1824    SearchFilterHo  0xfa8002f4e060  6       101     0       False   2025-04-18 07:54:30.000000 UTC  N/A     Disabled
428     1824    SearchProtocol  0xfa8002f91b30  7       275     0       False   2025-04-18 07:54:30.000000 UTC  N/A     Disabled
1840    440     sppsvc.exe      0xfa800191e770  6       158     0       False   2025-04-18 07:56:21.000000 UTC  N/A     Disabled
2188    440     svchost.exe     0xfa8002fcc510  13      336     0       False   2025-04-18 07:56:21.000000 UTC  N/A     Disabled
```

没有特别的，然后再看看

``` shell
vol.exe -f .\mem.dmp windows.cmdline
```

输出

``` shell
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
PID     Process Args

4       System  Required memory at 0x20 is not valid (process exited?)
220     smss.exe        \SystemRoot\System32\smss.exe
296     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
344     wininit.exe     wininit.exe
352     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
380     winlogon.exe    winlogon.exe
440     services.exe    C:\Windows\system32\services.exe
448     lsass.exe       C:\Windows\system32\lsass.exe
456     lsm.exe C:\Windows\system32\lsm.exe
548     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch
628     svchost.exe     C:\Windows\system32\svchost.exe -k RPCSS
716     svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
768     svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
796     svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs
884     audiodg.exe     C:\Windows\system32\AUDIODG.EXE 0x2b4
960     svchost.exe     C:\Windows\system32\svchost.exe -k LocalService
244     svchost.exe     C:\Windows\system32\svchost.exe -k NetworkService
1072    spoolsv.exe     C:\Windows\System32\spoolsv.exe
1124    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
1240    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
1860    dwm.exe "C:\Windows\system32\Dwm.exe"
1876    taskhost.exe    "taskhost.exe"
1932    explorer.exe    C:\Windows\Explorer.EXE
1824    SearchIndexer.  C:\Windows\system32\SearchIndexer.exe /Embedding
1312    SearchFilterHo  "C:\Windows\system32\SearchFilterHost.exe" 0 516 520 528 65536 524
428     SearchProtocol  "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe2_ Global\UsGthrCtrlFltPipeMssGthrPipe2 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"
1840    sppsvc.exe      C:\Windows\system32\sppsvc.exe
2188    svchost.exe     C:\Windows\System32\svchost.exe -k secsvcs
```

这些没有什么值得怀疑的

### filescan

然后使用filescan插件试试

``` shell
vol.exe -f .\mem.dmp windows.filescan > res.txt
```

> 这里windows的终端发生了gbk错误，在控制面版设置：
>
> 1. 打开 **控制面板** → **时钟和区域** → **区域**。
> 2. 点击 **“管理”** 标签页。
> 3. 点击 **“更改系统区域设置...”**
> 4. 勾选 **“Beta: 使用 Unicode UTF-8 提供全球语言支持”**
> 5. 确认并重启电脑。

用ChatGPT帮忙分析，发现一些值得怀疑的目录

``` shell
\Users\dawg\Desktop\win7-x64\api-ms-win-crt-heap-l1-1-0.dll
```

在桌面出现的win7值得怀疑

``` shell
0x7eaecb30	\Users\dawg\Desktop\win7-x64.zip
```

### dumpfile

我们可以dump一下这个zip文件， 先创建文件夹 `output` 然后

``` shell
vol.exe -f .\mem.dmp -o output windows.dumpfiles --physaddr 0x7eaecb30
```

发现dump下来的只有4B，重新搜索发现3个zip，换一个dump

``` shell
0x7eaecb30	\Users\dawg\Desktop\win7-x64.zip
0x7ef72e60	\Users\dawg\Desktop\win7-x64.zip
```

### dnSpy

然后文件大小就正常了，然后解压到当前位置，然后分析 `cma.dll` 

用 ILSpy 不管用，用 dnSpy 可以正常打开

发现2个函数

``` csharp
// cma.Program
// Token: 0x06000001 RID: 1 RVA: 0x00002048 File Offset: 0x00000248
private static void Main(string[] args)
{
	string ms = (string)Registry.GetValue("HKEY_LOCAL_MACHINE\\SECURITY\\Apple\\Sause", "sec", false);
	string[] files = Directory.GetFiles(".");
	foreach (string f in files)
	{
		string[] a2 = f.Split(".", StringSplitOptions.None);
		string t = a2[1];
		string[] array2 = a2;
		string t2 = array2[array2.Length - 1];
		bool flag = t.Equals(".txt") && !t2.Equals(".enc");
		if (flag)
		{
			byte[] fb = File.ReadAllBytes(f);
			byte[] sb = Encoding.UTF8.GetBytes(ms);
			sb = SHA256.Create().ComputeHash(sb);
			byte[] eb = Program.QiDlvAfIm(fb, sb);
			File.WriteAllBytes(f, eb);
		}
	}
}
```

还有

``` csharp
// cma.Program
// Token: 0x06000002 RID: 2 RVA: 0x0000211C File Offset: 0x0000031C
public static byte[] QiDlvAfIm(byte[] fileBytes, byte[] init)
{
	byte[] result;
	using (MemoryStream memoryStream = new MemoryStream())
	{
		using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
		{
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.BlockSize = 128;
			Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(init, init, 1000);
			rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
			rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
			rijndaelManaged.Mode = CipherMode.CBC;
			using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
			{
				cryptoStream.Write(fileBytes, 0, fileBytes.Length);
				cryptoStream.Close();
			}
			result = memoryStream.ToArray();
		}
	}
	return result;
}

```

这个逻辑就是关于加密算法的，它拿了 `"HKEY_LOCAL_MACHINE\\SECURITY\\Apple\\Sause"` 的值作为AES的key和IV

所以接下来提取registery

``` shell
vol.exe -f .\mem.dmp windows.registry.printkey
```

输出

``` shell
010-11-21 07:16:59.000000 UTC  0xf8a0001d9010  Key     \SystemRoot\System32\Config\SOFTWARE    Sonic           False
2025-04-18 07:54:16.000000 UTC  0xf8a0001d9010  Key     \SystemRoot\System32\Config\SOFTWARE    Wow6432Node             False
2025-04-18 06:38:57.000000 UTC  0xf8a000e97010  Key     \SystemRoot\System32\Config\SECURITY    Apple           False
2025-04-18 06:38:34.000000 UTC  0xf8a000e97010  Key     \SystemRoot\System32\Config\SECURITY    Policy          False
2025-04-18 06:38:34.000000 UTC  0xf8a000e97010  Key     \SystemRoot\System32\Config\SECURITY    RXACT           False
2025-04-18 07:54:17.000000 UTC  0xf8a000e97010  Key     \SystemRoot\System32\Config\SECURITY    SAM             True
```

发现这里有 `SECURITY APPLE`

所以提取这里的 `Apple\Sause`

``` shell
vol.exe -f .\mem.dmp windows.registry.printkey --offset 0xf8a000e97010 --key 'Apple\Sause'
```

然后发现key是 `by3_by3_c0mput3r` 

所以写个python 提取就可以了

### 逆向

首先这个密钥是被sha256hash之后传入的，可以用ChatGPT 逆向

``` python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

key = b"by3_by3_c0mput3r"
key = hashlib.sha256(key).digest()
key_iv = PBKDF2(key, key, dkLen=32+16, count=1000)  # Key: 32, IV: 16
key = key_iv[:32]
iv = key_iv[32:]

ciphertext = open("bank_account.txt.enc","rb").read()
print(ciphertext)
cipher = AES.new(key, AES.MODE_CBC, iv)

pt = cipher.decrypt(ciphertext)
print(pt)
```

最后得到

``` shell
b'DawgCTF{R121145145_A00001966}\x03\x03\x03'
```


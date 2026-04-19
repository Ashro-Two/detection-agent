# 高频工具研判

## 1. 代理工具

### 1.1 ReGeorg

**工具描述**：
通过webshell实现内网SOCK4/5代理

**分析研判**：
- 请求URL访问返回"UTF-8"
- GET请求：`tunnel.jsp`等
- 响应包含reGeorg特征

---

### 1.2 Neo-ReGeorg

**工具描述**：
ReGeorg的改进版，更强隐蔽性

**分析研判**：
- 请求参数包含`cmd`、`u`等
- 响应内容加密

---

### 1.3 Tini

**工具描述**：
简单内网代理工具

**分析研判**：
- 请求参数简单
- 流量特征不明显

---

### 1.4 sSocks

**工具描述**：
Linux平台SOCKS代理工具

**分析研判**：
- TCP连接特征
- 端口监听

---

### 1.5 mssql_proxy

**工具描述**：
MSSQL内网代理工具

**分析研判**：
- MSSQL协议特征
- 端口复用

---

### 1.6 nps

**工具描述**：
功能强大的内网穿透代理工具

**分析研判**：
- 支持多种协议
- 配置文件特征

---

### 1.7 frp

**工具描述**：
快速反向代理工具

**分析研判**：
- HTTP/HTTPS特征
- 配置文件中的服务器地址

---

### 1.8 ew

**工具描述**：
EarthWorm内网穿透工具

**分析研判**：
- SOCKS v5协议
- 端口映射特征

---

### 1.9蜥蜴

**工具描述**：
Windows内网穿透工具

**分析研判**：
- 进程特征
- 网络连接特征

---

### 1.10 pystinger

**工具描述**：
通过webshell实现内网SOCK4代理

**分析研判**：
- 上传后访问返回"UTF-8"
- 请求参数：`SENDDATA`、`Endpoint`、`Remoteserver`
- Endpoint值固定：`/check/`、`/2Fdata_sync/`
- 响应内容`ey`开头（base64加密的JSON）

**图片参考**：
- pystinger分析：image_143 ~ image_152

---

## 2. 后渗透工具

### 2.1 Cobalt Strike

**工具描述**：
全平台后渗透攻击框架，集成了端口转发、端口扫描、socks代理、提权、钓鱼、远控木马等功能

**分析研判**：

**DNS Beacon**：
- DNS查询包含`aaa.stage.*`特征
- 目的地址为DNS服务器

**HTTP Beacon**：
- GET请求发送元数据
- Cookie为加密元数据

**Web Delivery**：
- 响应内容包含`New-Object`（PowerShell脚本投递）
- 响应经过base64编码

**检测关键点**：
- Malleable C2默认配置有明显特征
- 如出现Cobalt Strike告警，主机大概率已失陷

**排查方向**：
- 登录主机排查异常进程
- 排查异常文件
- 提取样本分析

**图片参考**：
- Cobalt Strike分析：image_153 ~ image_158

---

### 2.2 Metasploit

**工具描述**：
强大的渗透测试框架，集成众多攻击程序及辅助工具

**分析研判**：
- 与Cobalt Strike类似
- 出现告警需特别留意
- 流量层面分析较难
- 建议登录主机排查异常进程和文件

**图片参考**：
- Metasploit分析：image_159

---

## 3. DNSLog平台

**用途**：
反序列化、命令执行等漏洞无回显时进行验证

**常见平台**：
- ceye.io
- dnslog.cn
- dnslog.io
- dnslog.xyz
- burpcollaborator.net
- dig.pm
- tu4.org
- h.i.ydscan.net
- dnsbin.zhack.ca
- s0x.cn

**研判要点**：
- 有主动发起DNSLog访问的源主机大概率被攻击成功或存在漏洞
- 需进一步对源主机进行排查

**图片参考**：
- DNSLog分析：image_151 ~ image_152

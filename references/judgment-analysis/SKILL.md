---
name: judgment-analysis
description: "Security alert judgment and analysis knowledge base. Invoke when analyzing security alerts, determining attack success, identifying false positives, or investigating incidents. Both for AI agents and human analysts."
license: MIT
---

# 安全事件研判分析

## 概述

本技能提供完整的安全事件研判分析知识体系，用于：
1. 教会AI智能体进行智能分析处置
2. 作为人工分析师的参考手册
3. 作为检测、调查等智能体的共享分析能力

## 核心分析框架（三步法）

面对安全告警时，按以下顺序逐步分析：

```
┌─────────────────────────────────────────────────────────────┐
│                    安全事件研判三步法                         │
├─────────────────────────────────────────────────────────────┤
│  Step 1: 是否为误报？                                         │
│          ↓ 是 → 记录并忽略   ↓ 否 → 继续Step 2               │
│                                                             │
│  Step 2: 是否为攻防演习攻击？                                  │
│          ↓ 否 → 真实攻击处置   ↓ 是 → 继续Step 3             │
│                                                             │
│  Step 3: 攻击是否成功？                                       │
│          ↓ 否 → 威胁预警   ↓ 是 → 应急响应                   │
└─────────────────────────────────────────────────────────────┘
```

## Layer 1: 快速参考（始终加载）

### 判断误报的要点

| 误报原因 | 特征 | 排查方法 |
|---------|------|---------|
| 规则宽泛 | 流量正常但触发规则 | 检查请求内容是否含攻击载荷 |
| 算法误判 | 正常业务流量触发 | 分析上下文业务场景 |
| 正常行为 | 重复出现的告警 | 查看历史告警比对 |

**判断方法**：分析告警详情的请求头、请求体，确认是否包含实际攻击载荷。

### 攻防演习攻击判断

**攻击事件类型**：
- WEB应用攻击：文件上传、命令执行、代码执行、反序列化、WebShell、SQL注入
- Windows攻击：口令暴力破解、MS17-010、CVE-2019-0708
- Linux攻击：SSH弱口令、SSH口令复用

**攻击IP来源**：
- 威胁情报黑IP
- 攻防演习IP名单
- 已被披露的恶意IP（挖矿、勒索、僵尸网络）

### 攻击成功判断

**响应状态码分析**：

| 状态码 | 含义 | 判断规则 |
|-------|------|---------|
| 404 | 资源不存在 | 直接判断攻击失败 |
| 200 | 请求成功 | 需结合响应内容判断 |
| 401 | 未授权 | 判断认证是否成功 |
| 500 | 服务器错误 | 需结合上下文判断 |

**请求响应分析**：
1. 分析攻击请求载荷
2. 检查响应是否包含预期回显
3. 对于无回显：使用DNSLog、流量重放等方法验证

## Layer 2: 执行指南（触发加载）

### WEB漏洞攻击研判

#### SQL注入漏洞

**特征识别**：
- 响应状态码 + 响应内容分析
- 布尔盲注：条件语句导致页面差异
- 时间盲注：SLEEP()延迟
- UNION注入：联合查询回显

**攻击成功判断**：
1. 重放数据包验证漏洞存在
2. 根据User-Agent识别sqlmap工具特征
3. 查看数据库操作类型（SELECT/INSERT/UPDATE）

**利用检测**：
- MySQL写入WebShell：`INTO OUTFILE`
- MSSQL执行命令：`xp_cmdshell`

#### 文件上传漏洞

**恶意文件特征**：
- 后缀：`.php/.php3/.phtml/.asp/.aspx/.jsp/.war`
- 内容：`eval、call_user_func、system、exec`

**成功判断**：
1. 响应包返回上传路径
2. 访问上传文件URL可解析
3. 服务器排查：`find / -name "*.php*" -ctime -3`

#### 命令执行漏洞

**有回显**：
- 直接查看响应内容中的命令执行结果

**无回显（OOB方法）**：
- DNSLog带外检测
- 流量回溯查询DNS请求
- 服务器文件落地排查

#### 反序列化漏洞

**Shiro反序列化**：
- 判断：Cookie中`rememberMe=xxx`，响应`rememberMe=deleteMe`
- 解密后分析：`ysoserial`、`BeanComparator`等特征

**WebLogic反序列化**：
- T3协议流量
- `Commons.collections`组件特征
- 排查`/tmp/`或`C:/windows/temp/`下的临时文件

### 非WEB攻击研判

**内网渗透攻击关注点**：
- SSH/RDP口令暴力破解
- MS17-010(永恒之蓝)
- CVE-2019-0708(BlueKeep)
- 域管理员权限获取

**高置信度告警组合**：
- MS17-010 + Doublepulsar后门 → 主机失陷

## Layer 3: 参考资料（按需加载）

详细技术内容请查看references目录：

```
references/
├── vulnerability_analysis.md    # 漏洞详细研判
├── tool_detection.md            # 高频工具研判
├── command_detection.md         # 高频命令研判
└── attack_techniques.md         # 攻击技术参考
```

### 图片参考资料

与本技能关联的图片位于：
`E:\test\aifile\skills\手册\研判分析指导手册\image\`

关键图片索引：
- 响应状态码示例：image_5_YZUnJwkEap.png ~ image_12_qZZol5DYtf.png
- SQL注入分析：image_8_H4scZm62Y3.png ~ image_21_WaftDXMPdu.png
- 命令执行分析：image_26_27ldo2KEoJ.png ~ image_32_Gb2r8XvDjj.png
- Shiro反序列化：image_33_fTc3m-3PJS.png ~ image_42_bTbPX26Y4t.png

## 最佳实践

1. **人机协同**：AI初判 + 人工确认，避免完全自主决策
2. **上下文注入**：结合企业资产信息、用户角色、历史告警
3. **可解释性**：输出判断依据和置信度，让分析师理解AI推理
4. **反馈闭环**：建立分析师反馈机制，持续优化判断准确率

## 与其他智能体的协作

本技能作为**共享分析知识库**，被以下智能体调用：

| 智能体 | 调用场景 |
|-------|---------|
| 检测智能体 | 告警分诊、误报判断、风险评估 |
| 调查智能体 | 深度调查、攻击链构建、上下文分析 |
| 响应智能体 | 响应策略生成、攻击成功确认 |
| 情报智能体 | 威胁情报关联、攻击者画像 |
| 合规智能体 | 事件分类、监管报告 |
| 报告智能体 | 分析报告生成、事件摘要 |

## 输入输出格式

**输入**：
```json
{
  "alert": {
    "alert_id": "ALT-xxx",
    "event_type": "SQL注入",
    "src_ip": "x.x.x.x",
    "dst_ip": "x.x.x.x",
    "request": "...",
    "response": "...",
    "status_code": 200
  },
  "context": {
    "asset_info": {},
    "user_info": {},
    "threat_intel": {}
  }
}
```

**输出**：
```json
{
  "is_false_positive": false,
  "is_red_team": true,
  "attack_success": true,
  "risk_level": "HIGH",
  "confidence": 0.85,
  "analysis": "判断依据说明",
  "recommendations": ["建议1", "建议2"]
}
```

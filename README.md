# Detection Agent (检测智能体)

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Ollama](https://img.shields.io/badge/Ollama-Supported-orange.svg)

一个基于Python、Ollama的智能告警分析检测智能体，具备并行处理、智能缓存、自适应规则、实时监控和本地大模型集成能力。


## ✨ 功能特性

### 🚀 核心能力
- **并行处理**: 使用ThreadPoolExecutor实现多线程并行告警分析，提升吞吐量
- **智能缓存**: MD5哈希缓存告警分析结果，支持TTL过期和LRU淘汰策略
- **自适应风险评分**: 根据攻击类型、资产重要性等因素计算风险评分
- **白名单规则引擎**: 支持IP白名单、URL白名单和动态抑制规则
- **攻击成功判定**: 基于签名的攻击检测（SQL注入、命令执行、文件上传、XSS）
- **实时监控仪表盘**: 实时统计吞吐量、处理时间、缓存命中率和风险分布

### 🤖 大模型集成
- **本地LLM支持**: 集成Ollama + DeepSeek进行深度告警分析
- **RAG架构**: 历史案例检索与分析，提升分析准确性
- **智能触发**: 仅对高风险告警（评分>=50）调用大模型
- **中文支持**: 完整的中文分析报告输出

## 📷 运行截图

### 命令行运行效果

```
=== Detection Agent v2.3 (优化版) ===
启动时间: 2026-04-19 21:41:01
优化特性: 并行处理 | 智能缓存 | 自适应规则 | 实时监控 | 大模型集成

加载测试案例: 22 条
============================================================
ALT-001: L2_HIGH (85分) [LLM]
ALT-002: L3_MEDIUM (65分) [LLM]
ALT-003: L3_MEDIUM (65分)
ALT-004: L2_HIGH (75分) [LLM]
ALT-005: L2_HIGH (75分) [LLM]
ALT-006: L3_MEDIUM (65分)
ALT-007: L3_MEDIUM (55分)
ALT-008: L2_HIGH (75分)
ALT-009: L3_MEDIUM (55分) [WL]
ALT-010: L4_LOW (35分) [FP]
ALT-011: L4_LOW (15分) [FP][WL]
ALT-012: L4_LOW (15分) [FP]
ALT-013: L2_HIGH (75分)
ALT-014: L4_LOW (0分) [WL]
ALT-015: L4_LOW (0分) [WL]
ALT-016: L4_LOW (0分) [WL]
ALT-017: L4_LOW (30分) [FP]
ALT-018: L4_LOW (15分) [FP]
ALT-019: L4_LOW (15分) [FP][WL]
ALT-020: L4_LOW (15分) [FP][WL]
ALT-021: L2_HIGH (75分) [LLM]
ALT-022: L2_HIGH (80分) [LLM]

============================================================
=== 分析完成 ===
结果文件: ../assets/output/analysis_results_20260419_214101.json
处理耗时: 0.00 秒

[监控报告]:
  吞吐量: 44.4 条/秒
  平均处理时间: 0.05 ms
  缓存命中率: 0.0%
  LLM调用: 6 次

[风险等级分布]:
  L2_HIGH: 8 条
  L3_MEDIUM: 5 条
  L4_LOW: 9 条

[统计]:
  误报: 6 条
  白名单匹配: 7 条

[监控指标已保存到]: ../assets/metrics/metrics_20260419.json
```

### 图例说明

| 标记 | 含义 |
|-----|------|
| `[LLM]` | 调用了大模型进行深度分析 |
| `[FP]` | 识别为误报 |
| `[WL]` | 匹配白名单规则 |

## 🚀 快速开始

### 安装要求

```bash
Python 3.8+
pip install pyyaml
```

### 安装依赖

```bash
cd detection-agent
pip install -r requirements.txt
```

### 大模型配置（可选但推荐）

1. **安装 Ollama**
```bash
# Windows (PowerShell)
iwr https://ollama.com/install.ps1 -useb | iex

# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh
```

2. **拉取 DeepSeek 模型**
```bash
ollama pull deepseek-chat
```

3. **启动 Ollama 服务**
```bash
ollama serve
```

### 运行方式

```bash
cd scripts
python main.py
```

## 📋 使用示例

```python
from alert_analyzer import DetectionAgent

# 初始化检测智能体（启用大模型）
agent = DetectionAgent(max_workers=10, enable_cache=True, enable_llm=True)

# 分析告警（并行模式）
results = agent.analyze_alerts(alerts, parallel=True)

# 获取监控报告
monitor_report = agent.get_monitor_report()

# 查看大模型分析结果
for result in results:
    if result.get('llm_analysis'):
        print(f"告警 {result['alert_id']} 的LLM分析:")
        print(result['llm_analysis'])
```

## ⚙️ 配置说明

### config.yaml

```yaml
risk_weights:
  attack_success: 50
  asset_criticality:
    critical: 35
    important: 20
    normal: 10
    edge: 5
  attack_type:
    command_execution: 30
    sql_injection: 25
    xss: 15
    file_upload: 25
    scan: 5
    brute_force: 20
    remote_command_execution: 30
    rce: 30
    struts2_rce: 35
    sql_blind_injection: 25
    lateral_movement: 35
    cve_exploit: 30
    password_brute_force: 20
  threat_intel: 20
  frequency: 10
```

### whitelist.yaml

```yaml
ip_whitelist:
  - name: "内部监控服务器"
    source_ip: "10.0.0.50"
    action: "silence"
    note: "内部监控服务定期扫描"

url_whitelist:
  - name: "健康检查URL"
    url_pattern: "/health"
    action: "silence"

suppression_rules:
  - name: "高频误报抑制"
    conditions:
      - field: "count"
        operator: ">"
        value: 1000
    action: "aggregate_delay"
```

## 📊 风险等级定义

| 等级 | 分数范围 | 说明 | LLM调用 |
|-----|---------|------|--------|
| L1_CRITICAL | 90-100 | 严重威胁，需要立即响应 | ✅ |
| L2_HIGH | 70-89 | 高危威胁，需要及时处理 | ✅ |
| L3_MEDIUM | 40-69 | 中等威胁，常规处理 | ✅（>=50） |
| L4_LOW | 0-39 | 低危/误报，记录日志 | ❌ |

## 📁 项目结构

```
detection-agent/
├── SKILL.md                  # 技能定义文件
├── README.md                 # 项目说明文档
├── requirements.txt          # 依赖列表
├── LICENSE                   # 许可证
├── scripts/
│   ├── main.py               # 主入口脚本
│   └── alert_analyzer.py     # 告警分析器核心
├── assets/
│   ├── config.yaml           # 配置文件
│   ├── whitelist.yaml        # 白名单规则
│   ├── asset_mapping.csv     # 资产映射表
│   ├── test_cases.json       # 测试案例
│   ├── history.xlsx          # 历史处置案例（Excel）
│   ├── history_cases.json    # 历史处置案例（JSON）
│   ├── logs/                 # 日志目录
│   ├── metrics/              # 监控指标目录
│   ├── feedback/             # 反馈数据目录
│   └── output/               # 分析结果目录
└── tests/                    # 单元测试目录
```

## 🤖 大模型集成说明

### 工作流程

```
告警输入 → 规则引擎分析 → 风险评分 → 
    ├─ 评分 >= 50 → 检索历史案例 → LLM深度分析 → 输出结果
    └─ 评分 < 50  → 直接输出规则引擎结果
```

### 历史案例格式

**JSON格式** (`assets/history_cases.json`):
```json
[
  {
    "case_id": "CASE-001",
    "attack_type": "SQL注入",
    "description": "针对MySQL数据库的UNION注入攻击",
    "severity": "high",
    "disposition": "立即隔离主机，检查数据库完整性",
    "analysis": "攻击者尝试通过UNION SELECT语句获取数据库信息"
  }
]
```

### LLM分析输出示例

```
1. 攻击分析：
   该告警显示一次成功的SQL注入攻击，攻击者通过构造恶意SQL语句...

2. 风险评估：
   高危威胁，可能导致数据库敏感信息泄露...

3. 处置建议：
   - 立即隔离受影响主机
   - 检查数据库完整性
   - 审查访问日志

4. 溯源建议：
   - 分析攻击源IP的行为模式
   - 检查是否有其他系统受到影响
```

## 📈 性能指标

| 指标 | 数值 |
|-----|------|
| 吞吐量 | >3000条/秒（无LLM） |
| 吞吐量 | ~50条/分钟（含LLM） |
| 平均处理时间 | <0.1ms（无LLM） |
| 缓存命中率 | 可配置TTL自动过期 |
| LLM调用成功率 | 取决于Ollama服务状态 |

## 📊 监控指标

```json
{
  "summary": {
    "total_alerts": 1000,
    "throughput_per_second": 3058.9,
    "avg_processing_time_ms": 0.04,
    "cache_hit_rate": 45.2,
    "llm_calls": 150,
    "llm_success_rate": 98.5
  },
  "risk_distribution": {
    "L1_CRITICAL": 5,
    "L2_HIGH": 45,
    "L3_MEDIUM": 200,
    "L4_LOW": 750
  }
}
```

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

### 开发流程

1. Fork项目
2. 创建功能分支
3. 提交代码
4. 创建Pull Request

### 代码规范

- 使用Python 3.8+
- 遵循PEP 8编码规范
- 添加适当的注释
- 编写单元测试

## 🔧 故障排除

### 常见问题

**Q: Ollama服务无法启动**

A: 请检查以下几点：
- 确保Ollama已正确安装：`ollama --version`
- 检查端口11434是否被占用
- 尝试重启Ollama服务：`ollama serve`

**Q: LLM分析返回空结果**

A: 可能的原因：
- Ollama服务未运行或无法连接
- DeepSeek模型未下载：`ollama pull deepseek-chat`
- 网络超时，检查网络连接

**Q: 白名单规则不生效**

A: 请检查：
- 规则文件路径是否正确
- IP地址格式是否正确（支持CIDR格式）
- 规则条件是否匹配告警字段

**Q: 性能问题**

A: 优化建议：
- 减少max_workers数量（默认10）
- 启用缓存（enable_cache=True）
- 降低LLM调用频率（调整评分阈值）

### 日志查看

```bash
# 查看运行日志
tail -f assets/logs/detection_agent.log

# 查看监控指标
cat assets/metrics/metrics_*.json
```

## 📝 更新日志

### v2.3 (2026-04-19)
- ✨ 新增本地大模型集成（Ollama + DeepSeek）
- ✨ 新增RAG架构支持
- ✨ 新增历史案例检索功能
- ✨ 新增LLM智能触发机制
- 📊 优化监控指标（添加LLM调用统计）
- 🔧 修复IP解析缓存问题

### v2.2 (2026-04-18)
- ✨ 新增正则预编译优化
- ✨ 新增IP解析缓存
- ✨ 新增规则索引优化
- ✨ 完善日志系统
- 🔧 代码结构优化

### v2.1 (2026-04-17)
- ✨ 新增并行处理功能
- ✨ 新增智能缓存机制
- ✨ 新增自适应风险评分
- ✨ 新增实时监控仪表盘
- ✨ 新增白名单规则引擎

### v2.0 (2026-04-16)
- ✨ 重构告警分析器架构
- ✨ 添加攻击成功判定插件
- ✨ 添加动态抑制规则引擎
- ✨ 添加资产管理功能

## 🙏 致谢

### 依赖项目
- **Ollama** - 本地大模型运行框架
- **DeepSeek** - 开源大语言模型
- **PyYAML** - YAML配置文件解析
- **pandas** - Excel文件处理（可选）

### 参考资料
- MITRE ATT&CK - 攻击技术分类
- OWASP Top 10 - Web安全风险
- STIX/TAXII - 威胁情报标准

## ❓ FAQ

**Q: 这个项目可以处理多少告警？**

A: 在不调用LLM的情况下，吞吐量超过3000条/秒。调用LLM时约50条/分钟（取决于模型性能）。

**Q: 是否支持其他大模型？**

A: 当前支持Ollama生态中的所有模型。只需修改`LLMIntegrator`的`model_name`参数即可切换模型。

**Q: 如何添加自定义攻击签名？**

A: 在`AttackSuccessDetector`类的`signatures`字典中添加新的攻击类型和正则表达式模式。

**Q: 白名单规则支持哪些条件？**

A: 支持的操作符：`equals`, `not_equals`, `contains`, `not_contains`, `>`, `>=`, `<`, `<=`

**Q: 是否支持增量更新？**

A: 支持。告警结果会缓存，重复告警直接返回缓存结果，TTL可配置。


---

**项目标签**: `security` `cybersecurity` `alert-analysis` `python` `AI-agent` `threat-detection` `LLM` `Ollama` `RAG`

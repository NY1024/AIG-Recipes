# mini-arch: AI-Infra-Guard 工程架构解析

从 AI-Infra-Guard 代码库中提取 14 个工程架构设计模式，配套 15 个 Python 提取脚本，引导研究者和安全工具开发者学习 AIG 的架构设计优势。

## 文章

- [extract-aig-architecture-patterns.md](extract-aig-architecture-patterns.md) — 主文章（14 个场景）

## 提取脚本

| 脚本 | 分析对象 | 场景 |
|------|---------|------|
| extract_dsl_grammar.py | common/fingerprints/parser/ | 场景一：指纹规则引擎 DSL 设计 |
| extract_scan_engine.py | common/runner/ + preload/ | 场景二：并发扫描引擎架构 |
| extract_version_dsl.py | pkg/vulstruct/ + version_range.go | 场景三：版本比较 DSL 与漏洞建议引擎 |
| extract_server_agent.py | common/websocket/agent.go + common/agent/ | 场景四：Server-Agent 分布式架构 |
| extract_hybrid_arch.py | common/agent/tasks.go | 场景五：Go+Python 混合架构 |
| extract_rule_llm_layered.py | internal/mcp/ | 场景六：Rule-First + LLM-Augmented 分层协作 |
| extract_scoring_algorithm.py | common/runner/runner.go CalcSecScore | 场景七：安全评分算法分析 |
| extract_deployment_profiles.py | common/websocket/server.go + Docker | 场景八：多部署形态架构 |
| extract_database_persistence.py | pkg/database/ | 场景九：数据库持久化与任务状态机 |
| extract_http_probing.py | pkg/httpx/ | 场景十：HTTP 探测引擎与编码韧性 |
| extract_llm_integration.py | common/runner/ai.go | 场景十一：LLM 增强敏感信息检测 |
| extract_tool_system.py | agent-scan/tools/ | 场景十二：Agent 工具系统与 XML Schema 注册 |
| extract_provider_adapter.py | agent-scan/core/adapter.py | 场景十三：多平台 Provider 适配与连接韧性 |
| extract_scan_pipeline.py | agent-scan/core/agent.py | 场景十四：三阶段 Agent 扫描流水线 |

## 设计模式总览

文章从三层架构视角组织 14 个场景：

| 架构层 | 覆盖场景 | 核心设计模式 |
|--------|---------|-------------|
| 数据层 | 场景 1/3/9 | Rule-Engine DSL、Compiled Rule DSL、Event Sourcing |
| 通信层 | 场景 4/5/10/13 | Distributed Task Queue、Language Split by Concern、Multi-Protocol Resilient Probing、Provider Adapter |
| 智能层 | 场景 6/7/11/12/14 | Two-Phase Detection、Absolute Deduction、Screenshot-Augmented LLM、XML Schema Registry、Sequential-Parallel Pipeline |

## 运行方式

```bash
pip install -r requirements.txt
python3 extract_dsl_grammar.py
python3 extract_scan_engine.py
python3 extract_version_dsl.py
python3 extract_server_agent.py
python3 extract_hybrid_arch.py
python3 extract_rule_llm_layered.py
python3 extract_scoring_algorithm.py
python3 extract_deployment_profiles.py
python3 extract_database_persistence.py
python3 extract_http_probing.py
python3 extract_llm_integration.py
python3 extract_tool_system.py
python3 extract_provider_adapter.py
python3 extract_scan_pipeline.py
```

## 输出

每个脚本在 `results/` 目录下生成 `.json`（结构化数据）、`.csv`（表格数据）、`.png`（可视化图表）。

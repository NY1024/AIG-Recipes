# mini-arch: AI-Infra-Guard 工程架构解析

从 AI-Infra-Guard 代码库中提取 8 个工程架构设计模式，配套 9 个 Python 提取脚本。

## 文章

- [extract-aig-architecture-patterns.md](extract-aig-architecture-patterns.md) — 主文章

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
```

## 输出

每个脚本在 `results/` 目录下生成 `.json`（结构化数据）、`.csv`（表格数据）、`.png`（可视化图表）。

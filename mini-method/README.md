# AI-Infra-Guard 方法提取与 Baseline 复用

本目录是 AIG 开源社区教程系列的一部分，聚焦于**如何从 AIG 中提取安全检测方法与攻击算法，作为自身研究的 Baseline**。

与 `mini-data/academic-research-extract-aig-for-experiments/`（关注数据提取）不同，本目录关注的是**方法层面的提取**——攻击算法、检测规则、编排框架、Skill 检测器。

## 目录结构

```
mini-method/
├── README.md                              # 本文件
├── extract-aig-methods-as-baselines.md    # 主文章（10 个场景）
├── extract_jailbreak_attacks.py           # 提取越狱攻击方法清单（场景一）
├── extract_mcp_detection_rules.py         # 提取 MCP 安全检测规则（场景二）
├── extract_redteam_framework.py           # 提取红队编排框架架构（场景三）
├── extract_agent_skill_detectors.py       # 提取 Agent Skill 检测方法（场景四）
├── extract_attack_operators.py            # 提取攻击算子注册表（场景五）
├── extract_eval_datasets.py               # 提取评测基准数据集（场景六）
├── extract_blueteam_methodology.py        # 提取蓝军安全演习方法论（场景七）
├── extract_skill_scanner.py              # 提取 Skill 安全扫描方法（场景八）
├── extract_fingerprints.py               # 提取 AI 基础设施组件指纹（场景九）
├── extract_cve_rules.py                  # 提取 CVE 漏洞检测规则（场景十）
├── requirements.txt                       # Python 依赖
└── results/                               # 脚本运行输出
```

## 快速开始

```bash
git clone https://github.com/Tencent/AI-Infra-Guard.git
cd AI-Infra-Guard/mini-method
pip install -r requirements.txt

# 运行全部 10 个提取脚本
python extract_jailbreak_attacks.py --aig-root ../.. --output-dir ./results
python extract_mcp_detection_rules.py --aig-root ../.. --output-dir ./results
python extract_redteam_framework.py --aig-root ../.. --output-dir ./results
python extract_agent_skill_detectors.py --aig-root ../.. --output-dir ./results
python extract_attack_operators.py --aig-root ../.. --output-dir ./results
python extract_eval_datasets.py --aig-root ../.. --output-dir ./results
python extract_blueteam_methodology.py --aig-root ../.. --output-dir ./results
python extract_skill_scanner.py --aig-root ../.. --output-dir ./results
python extract_fingerprints.py --aig-root ../.. --output-dir ./results
python extract_cve_rules.py --aig-root ../.. --output-dir ./results
```

## 许可证

继承 AIG 主项目的 Apache License 2.0。

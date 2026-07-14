# AIG-Recipes

AI-Infra-Guard (AIG) Recipes — 脚本、数据与图表，服务于学术研究与方法提取。

本仓库从 [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) 项目中提取可复用的数据和检测方法，整理为独立可运行的脚本和配套图表，方便研究者和安全工程师直接使用。

## 仓库结构

```
AIG-Recipes/
├── mini-data/                              # 数据提取教程与脚本
│   ├── README.md
│   ├── academic-research-extract-aig-for-experiments.md   # 技术文章
│   └── academic-research-extract-aig-for-experiments/     # 脚本与输出
│       ├── extract_cve_stats.py
│       ├── analyze_cvss_vectors.py
│       ├── jailbreak_eval_pipeline.py
│       ├── generate_demo_asr_chart.py
│       ├── attack_surface_gap.py
│       ├── analyze_citations.py
│       ├── eval_config.yaml
│       ├── requirements.txt
│       └── results/                        # 生成的图表与 CSV
│
├── mini-method/                            # 方法提取教程与脚本
│   ├── README.md
│   ├── extract-aig-methods-as-baselines.md # 技术文章（10 个场景）
│   ├── extract_jailbreak_attacks.py
│   ├── extract_mcp_detection_rules.py
│   ├── extract_redteam_framework.py
│   ├── extract_agent_skill_detectors.py
│   ├── extract_attack_operators.py
│   ├── extract_eval_datasets.py
│   ├── extract_blueteam_methodology.py
│   ├── extract_skill_scanner.py
│   ├── extract_fingerprints.py
│   ├── extract_cve_rules.py
│   ├── requirements.txt
│   └── results/                            # 生成的图表与 CSV/JSON
│
└── README.md                               # 本文件
```

## 两个教程

| 目录 | 主题 | 关注点 | 场景数 |
|------|------|--------|--------|
| `mini-data/` | AI-Infra-Guard 数据仓库的学术复用 | **数据提取**：漏洞数据集、CVSS 向量、越狱评测基准、攻击面测绘 | 4 + 引用分析 |
| `mini-method/` | AI-Infra-Guard 方法提取与 Baseline 复用 | **方法提取**：攻击算法、检测规则、编排框架、评测基准、指纹库 | 10 |

## 快速开始

```bash
# 克隆本仓库
git clone https://github.com/NY1024/AIG-Recipes.git
cd AIG-Recipes

# 同时需要克隆 AIG 主仓库获取数据源
git clone https://github.com/Tencent/AI-Infra-Guard.git

# --- 数据提取（mini-data）---
cd mini-data/academic-research-extract-aig-for-experiments
pip install -r requirements.txt
python extract_cve_stats.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python analyze_cvss_vectors.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python attack_surface_gap.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python analyze_citations.py --output-dir ./results

# --- 方法提取（mini-method）---
cd ../../mini-method
pip install -r requirements.txt
python extract_jailbreak_attacks.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python extract_mcp_detection_rules.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python extract_fingerprints.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
python extract_cve_rules.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
# ... 运行其他脚本同理
```

## 技术文章

- [AI-Infra-Guard 数据仓库的学术复用：漏洞数据提取、评测基准改造与论文实验方法](mini-data/academic-research-extract-aig-for-experiments.md)
- [AI-Infra-Guard 方法提取与 Baseline 复用：从安全检测规则到越狱攻击算法](mini-method/extract-aig-methods-as-baselines.md)

## 许可证

Apache License 2.0，继承自 AI-Infra-Guard 主项目。

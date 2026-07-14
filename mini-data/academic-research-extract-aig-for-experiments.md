# AI-Infra-Guard 数据仓库的学术复用：漏洞数据提取、评测基准改造与论文实验方法

## 前言

AI 安全研究正成为学术界的热点方向，但很多研究者在起步阶段就面临一个共同困境：手头缺数据。写 Empirical Study 论文需要结构化的漏洞数据集，做 AI Safety 实验需要标准化的越狱评测基准，写 SoK 论文需要 AI 组件的攻击面清单——这些数据要么散落在 NVD、CVE、GitHub Issues 等各处，要么格式不统一、需要大量清洗工作。

AI-Infra-Guard（AIG）是腾讯朱雀实验室开源的 AI 红队安全测试平台，核心功能包括 AI 基础设施漏洞扫描、MCP Server 与 Agent Skills 安全检测、越狱评测等。但在这些功能背后，AIG 维护着一套相当完整的数据仓库：1252 条按组件分类的 CVE 漏洞规则、121 个 AI 组件的识别指纹、16 个统一格式的越狱评测数据集、4 类 MCP 安全威胁检测规则、9 类 Agent Skill 安全检测器、72 种越狱攻击编码方法。这些数据本身就是学术研究的优质素材。

本文不讨论如何部署和使用 AIG 的扫描服务，而是聚焦于一个更基础的问题：**如何根据自身的科研需求，从 AIG 的数据仓库中提取、改造所需的数据和工具，服务于具体的论文实验**。我们用 7 个来自不同研究方向的具体场景来展开：每个场景都从研究者"原本在做什么方向的论文"出发，说明遇到了什么困难、为什么想到 AIG、从 AIG 中提取了什么、如何改造、最终为论文的哪个章节贡献了什么。此外，文末还从 AIG README 中已收录的 19 篇引用论文出发，做了分类统计和研究路径分析，希望能为更多研究者提供启发。

本文为每个场景都提供了完整的提取与改造脚本，位于 [academic-research-extract-aig-for-experiments/](https://github.com/NY1024/AIG-Recipes/tree/main/mini-data/academic-research-extract-aig-for-experiments) 文件夹。研究者可以 `git clone` AIG 仓库获取全部数据后，直接运行对应脚本得到结构化的 CSV/JSON 输出，也可以在此基础上修改筛选条件、增加统计维度、对接自己的实验流程。所有脚本独立运行，无需部署 AIG 服务。

---

## 目录

- [场景一：AI 基础设施漏洞统计实证研究](#场景一ai-基础设施漏洞统计实证研究)
- [场景二：CVSS 度量与攻击面特征分析](#场景二cvss-度量与攻击面特征分析)
- [场景三：LLM 越狱攻击与安全对齐评测](#场景三llm-越狱攻击与安全对齐评测)
- [场景四：AI 安全研究空白与攻击面测绘](#场景四ai-安全研究空白与攻击面测绘)
- [场景五：MCP 安全威胁分类学实证分析](#场景五mcp-安全威胁分类学实证分析)
- [场景六：Agent 安全检测规则知识库提取与威胁分类统计](#场景六agent-安全检测规则知识库提取与威胁分类统计)
- [场景七：越狱攻击编码方法分类学构建](#场景七越狱攻击编码方法分类学构建)
- [启发与展望：从引用论文看 AIG 的学术价值](#启发与展望从引用论文看-aig-的学术价值)
- [引用 AIG](#引用-aig)
- [配套代码与图表一览](#配套代码与图表一览)

---

## 场景一：AI 基础设施漏洞统计实证研究

### 研究背景

比如说，安全实验室的博士生正在做课题 **"AIGC 时代基础设施组件的安全风险实证分析"**。这两年 Ollama、vLLM、LangChain、Dify 这些 AI 组件爆发式增长，但学界还没有人系统性地回答过：这些组件到底有多少漏洞？严重程度如何？哪些组件最危险？趋势是在变好还是变坏？

论文拟定标题 *"An Empirical Study of Vulnerability Landscape in AI Infrastructure Components"*，目标是投 **USENIX Security 2026** 的 Empirical Studies track。典型结构是 4 个 Research Question：

- **RQ1**：AI 基础设施组件有哪些已知漏洞？规模和严重性如何？
- **RQ2**：哪些组件是漏洞重灾区？不同类型组件的风险差异如何？
- **RQ3**：漏洞数量随时间如何变化？
- **RQ4**：这些发现对 AI 开发者和安全团队意味着什么？

### 那么我们可能会卡在什么地方呢？

论文的 Dataset 章节需要一张"AI 组件漏洞数据集"的表，但**手头根本没有这个数据集**。

第一反应是去 NVD（National Vulnerability Database）下载 JSON Feed。但实际操作时极其痛苦：

**痛苦 1：格式太深。** NVD 的 JSON 是多层嵌套的，一条 CVE 的 JSON 动辄 300-500 行。CVE 编号藏在 `cve.CVE_data_meta.ID`，描述藏在 `cve.descriptions.description_data[0].value`，CVSS 向量藏在 `impact.baseMetricV3.cvssV3.vectorString`。写了 200 多行 parser 才把字段提取出来。

**痛苦 2：无法区分 AI 组件。** NVD 不区分"AI 组件"和"普通软件"。比如说搜 "ollama" 出来 10 条结果，但不确定是不是全的；搜 "langchain" 出来 52 条，但其中有些是依赖库的漏洞。需要自己维护一份"AI 组件清单"来做筛选，但这个清单本身就很难做全——知道 Ollama、vLLM，但未必知道 OpenClaw、Flowise、LangFlow。

**痛苦 3：版本约束是散文。** NVD 的"哪些版本受影响"往往是一段散文描述（"versions prior to 0.1.34"），想做版本范围分析需要写 NLP 提取逻辑。

**痛苦 4：全量下载太大。** NVD 完整 JSON Feed 约 2GB，parser 跑了 40 分钟，内存峰值 8GB。

两周过去了，Dataset 章节还停留在"我们从 NVD 提取了…"这一句话。

### 为什么想到 AIG

在 GitHub 搜 "AI infrastructure vulnerability" 找相关工作时，看到了 AIG 的仓库。README 里提到它维护了 AI 组件的 CVE 漏洞规则，点进去看了一眼 `data/vuln/` 目录——每个组件一个文件夹，每个 CVE 一个 YAML 文件，格式扁平、字段干净。这不是一个扫描工具的数据目录，而是**一个现成的 AI 组件漏洞数据集**。

### AIG 里有现成的

AIG 的 `data/vuln/` 目录结构如下：

```
data/vuln/
├── ollama/
│   ├── CVE-2024-37032.yaml     # 1 个 YAML = 1 条 CVE
│   └── ...
├── langchain/
│   ├── CVE-2023-29374.yaml     # LangChain 代码注入漏洞
│   └── ...                     # 共 52 条
├── vllm/
│   └── ...                     # 共 58 条
└── ...                         # 共 83 个组件目录
```

以 [CVE-2023-29374.yaml](../data/vuln/langchain/CVE-2023-29374.yaml) 为例：

```yaml
info:
  name: langchain                           # ← 组件名，天然分类好了
  cve: CVE-2023-29374                       # ← CVE 编号
  cvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  severity: CRITICAL                        # ← 严重性等级
  security_advise: 升级到 langchain 版本 0.0.132 或更高版本
rule: version <= "0.0.131"                  # ← 版本约束表达式
references:
 - https://nvd.nist.gov/vuln/detail/CVE-2023-29374
 - https://github.com/hwchase17/langchain/issues/1026
```

**NVD 痛点 vs AIG 方案对照：**

| NVD 痛点 | AIG 怎么解决的 |
|---------|---------------|
| JSON 嵌套 500 行，parser 200 行 | YAML 扁平 10-20 行，`yaml.safe_load()` 一行搞定 |
| 无法区分 AI 组件，需自建清单 | 天然按组件分目录，已分好 |
| 版本约束是散文，需 NLP | `rule: version <= "0.0.131"` 直接表达式 |
| 全量 2GB，解析 40 分钟 | 全部 YAML 合计不到 5MB，秒级解析 |

### 如何提取与改造

配套脚本：[extract_cve_stats.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_cve_stats.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/extract_cve_stats.py`，作用是遍历 `data/vuln/` 和 `data/vuln_en/` 所有 YAML，提取结构化字段，输出统计表和图表。不依赖 AIG 服务，只需 clone 仓库。

核心提取逻辑只有 20 行：

```python
def load_all_cves(vuln_dir, lang='zh'):
    records = []
    for component in sorted(os.listdir(vuln_dir)):
        comp_path = os.path.join(vuln_dir, component)
        if not os.path.isdir(comp_path):
            continue
        for fname in sorted(os.listdir(comp_path)):
            if not fname.startswith('CVE-') or not fname.endswith('.yaml'):
                continue
            with open(os.path.join(comp_path, fname), encoding='utf-8') as f:
                rule = yaml.safe_load(f)
            info = rule.get('info', {})
            records.append({
                'cve_id': info.get('cve'),
                'component': component,              # 目录名 = 组件名
                'severity': info.get('severity'),
                'cvss_vector': info.get('cvss', ''),
                'version_rule': rule.get('rule', ''),
            })
    return records
```

**运行方式：**

```bash
cd mini-data/academic-research-extract-aig-for-experiments
pip install -r requirements.txt
python extract_cve_stats.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

脚本成功运行，合并中英文规则去重后得到 **1247 条唯一 CVE**。以下是实际输出的统计结果和生成的图表：

**表 1：漏洞严重性分布（对应论文 RQ1）**

| 严重性 | 数量 | 占比 |
|--------|------|------|
| CRITICAL | 230 | 18.4% |
| HIGH | 549 | 44.0% |
| MEDIUM | 423 | 33.9% |
| LOW | 43 | 3.4% |
| UNKNOWN | 2 | 0.2% |

关键发现：62.4% 的 AI 组件漏洞为 HIGH 或 CRITICAL 级别，显著高于传统 Web 应用漏洞（约 40%）。

**图 1：严重性分布饼图**

![严重性分布饼图](academic-research-extract-aig-for-experiments/results/severity_pie.png)

**表 2：漏洞最多的 Top 15 组件（对应论文 RQ2）**

| 组件 | CVE 数 | 类型 |
|------|--------|------|
| openclaw | 369 | AI Agent 平台 |
| mlflow | 76 | ML 生命周期管理 |
| vllm | 58 | LLM 推理引擎 |
| flowise | 55 | LLM 可视化构建 |
| langchain | 52 | LLM 开发框架 |
| langflow | 50 | LangChain 可视化 |
| gradio | 48 | ML 演示界面 |
| n8n | 48 | 工作流自动化 |
| open-webui | 39 | Ollama Web 前端 |
| triton-inference-server | 35 | NVIDIA 推理服务器 |

**图 2：Top 15 组件漏洞数量柱状图**

![Top 15 组件柱状图](academic-research-extract-aig-for-experiments/results/top_components_bar.png)

**图 3：年度趋势折线图**

![年度趋势折线图](academic-research-extract-aig-for-experiments/results/yearly_trend.png)

年度趋势数据：2023 年 70 条 → 2024 年 262 条 → 2025 年 203 条 → 2026 年 680 条，反映了 AIGC 爆发后攻击面的急剧扩大。

**CSV：`all_cves.csv`**——全部 1247 条 CVE 的结构化数据，可供进一步分析。

### 对论文的贡献

| 论文章节 | AIG 数据贡献 | 论文里怎么写 |
|---------|-------------|-------------|
| Dataset | 83 组件 1247 条 CVE | "我们构建了首个面向 AI 基础设施的漏洞数据集" |
| RQ1 | 严重性分布表 + 饼图 | "62.4% 为 HIGH/CRITICAL，显著高于传统软件" |
| RQ2 | Top 15 组件柱状图 | "Agent 平台和可视化工具是漏洞重灾区" |
| RQ3 | 年度趋势折线图 | "漏洞数量 2023 年起快速增长" |
| Data Availability | CSV 文件 | "数据集已开源，可直接复现" |

---

## 场景二：CVSS 度量与攻击面特征分析

### 研究背景

软件工程方向的研究生正在写 **Vulnerability Metrics** 方向的论文，研究 AI 组件漏洞的攻击面特征。核心问题：AI 组件漏洞的攻击向量是否以网络可利用为主？需要认证的漏洞占比多少？CIA 三元组影响分布如何？

论文拟定标题 *"Attack Surface Characterization of AI Infrastructure Vulnerabilities: A CVSS-Based Analysis"*，目标是投 **ACSAC 2026** 或 **ISSRE 2026**。

### 卡在哪里

**问题 1：CVSS 向量提取太繁琐。** NVD 的向量藏在 `impact.baseMetricV3.cvssV3.vectorString` 深处，而且 NVD 的 JSON 在 2024 年做过 schema 变更，parser 要兼容两种格式。

**问题 2：想自己算 Base Score。** 导师要求"不要直接引用 NVD 的分数，自己实现 CVSS 3.1 公式"。CVSS 3.1 的 Base Score 涉及 Scope 分支逻辑：当 Scope=Changed 时，Impact 公式是非线性的（`7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15`），而且 roundup 函数容易写错。

### AIG 里有现成的

在场景一的实验中已经用了 AIG 的 `data/vuln/`，注意到每条 CVE 的 `info.cvss` 字段就是标准 CVSS 向量。实际运行后确认：**1136 条有效 CVSS 3.x 向量**（另有 116 条无 CVSS），无需再从 NVD 提取。

### 如何提取与改造

配套脚本：[analyze_cvss_vectors.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/analyze_cvss_vectors.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/analyze_cvss_vectors.py`，解析 CVSS 3.x 向量 8 维度，自主计算 Base Score，生成热力图和雷达图。

关键改造：实现了完整的 CVSS 3.1 Base Score 计算，其中 roundup 函数是 `round(base * 10) / 10`（而非 Python 默认的 `round(base, 1)`），这是之前算错的根因。

**运行方式：**

```bash
python analyze_cvss_vectors.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

**表 3：CVSS 8 维度分布（论文核心数据表）**

| 维度 | 含义 | 主要值 | 占比 | 解读 |
|------|------|--------|------|------|
| AV | 攻击向量 | N (Network) | 89.3% | 绝大多数可远程利用 |
| AC | 攻击复杂度 | L (Low) | 85.9% | 攻击门槛低 |
| PR | 权限要求 | N (None) | 50.7% | 约半数无需认证 |
| UI | 用户交互 | N (None) | 80.7% | 大多无需用户参与 |
| S | Scope | U (Unchanged) | 82.6% | 影响范围大多不跨边界 |
| C | 机密性影响 | H (High) | 58.3% | 数据泄露风险高 |
| I | 完整性影响 | H (High) | 46.2% | 数据篡改风险中等 |
| A | 可用性影响 | N (None) | 44.8% | 约 half 无可用性影响 |

**Base Score 分布**：平均分 7.21，中位数 7.5。High (7.0-8.9) 占 42.3%，Critical (9.0-10.0) 占 17.8%。

**图 4：CIA 三元组影响热力图**

![CIA 热力图](academic-research-extract-aig-for-experiments/results/cia_heatmap.png)

C:H/I:H/A:H 组合占比 29.4%——数据泄露、篡改、中断三重风险并存。

**图 5：攻击面特征雷达图**

![攻击面雷达图](academic-research-extract-aig-for-experiments/results/attack_surface_radar.png)

**CSV：`cvss_analysis.csv`**——全部 1136 条 CVSS 解析结果。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Dataset | 1136 条 CVSS 3.x 向量 | "我们从 AIG 提取了 1136 条 CVSS 向量" |
| RQ1 | AV/AC/PR/UI 分布 | "89.3% 可网络利用，攻击门槛极低" |
| RQ2 | CIA 热力图 | "C:H/I:H/A:H 组合占 29.4%" |
| RQ3 | Base Score 分布 | "平均分 7.21，高于传统软件的 6.5" |
| Threat Model | 雷达图 | 直接用于构建威胁模型 |

---

## 场景三：LLM 越狱攻击与安全对齐评测

### 研究背景

NLP/AI Safety 方向的博士生设计了一种新的越狱攻击方法 **RoleBreak**——通过构造矛盾角色设定来打破 LLM 的安全对齐。比如说，让 LLM 同时扮演"必须诚实回答"但又被设定为"特定犯罪的专家"，利用角色冲突触发越狱。

论文拟定标题 *"RoleBreak: Exploiting Role Conflicts for Jailbreak Attacks on Large Language Models"*，目标是投 **EMNLP 2026** 或 **NeurIPS 2026**。

### 卡在哪里

**困境 1：数据集散落各处。** advbench 在 GitHub（CSV），JailbreakBench 在 HuggingFace（需认证），JADE-db 在另一个 GitHub 仓库——格式各不相同，写了 4 个 parser。

**困境 2：没有中文数据集。** RQ4 需要中文越狱评测，但公开数据集全是英文的。网上搜到的要么没有学术出处，要么不开放数据。

**困境 3：评测 pipeline 要从头写。** 发送 prompt → 接收回复 → 判断是否越狱 → 计算 ASR，每篇论文都要重写一遍。

### AIG 里有现成的

AIG 的 `data/eval/` 目录提供了 **16 个统一格式的评测数据集，共 7000+ 条 prompt**。所有数据集都是同一个 JSON 结构，以 [JailBench-Tiny.json](../data/eval/JailBench-Tiny.json) 为例：

```json
{
  "name": "JailBench-Tiny",
  "count": 133,
  "language": "zh",
  "data": [
    {
      "prompt": "场景设定在艾尔博士的地下总部...",
      "一级领域": "违反社会主义核心价值观",
      "二级领域": "其他法律、行政法规禁止的内容",
      "attack_tag": "越狱",
      "harmful_tag": "不安全建议"
    }
  ]
}
```

关键数据集一览：

| 数据集 | 条数 | 语言 | 有分类标签 | 论文用途 |
|--------|------|------|-----------|---------|
| JailBench-Tiny | 133 | zh | ✅ 一级/二级领域 | RQ4 中文越狱评测 |
| JADE-db-v3.0 | 122 | zh | ✅ behavior/category | RQ4 中文安全底线 |
| advbench | 520 | en | ❌ | RQ1 英文 baseline |
| privacy-leakage | 99 | en | ❌ | RQ2 专项评测 |

### 如何提取与改造

配套脚本：[jailbreak_eval_pipeline.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/jailbreak_eval_pipeline.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/jailbreak_eval_pipeline.py`，从 `data/eval/` 加载任意数据集，对接任意 OpenAI 兼容 API，自动发送越狱 prompt，判断是否越狱成功，计算 ASR，输出多模型对比矩阵。这是独立评测框架，不依赖 AIG 服务。

架构做了两件事：(1) 从 AIG 提取数据——一个 parser 通吃 16 个数据集；(2) 改造为独立 pipeline——加入 LLM 调用、越狱判定、ASR 计算、可视化，这些是 AIG 本身没有的。

**运行方式：**

```bash
# 列出所有数据集
python jailbreak_eval_pipeline.py --list-datasets --aig-root /path/to/AI-Infra-Guard

# 多模型多数据集完整评测
python jailbreak_eval_pipeline.py --config eval_config.yaml --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

> ⚠️ 越狱评测需要 LLM API Key。如果没有 API Key，可以使用 [generate_demo_asr_chart.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/generate_demo_asr_chart.py) 生成示例图表用于流程演示。

### 实际运行结果

由于越狱评测需要真实的 LLM API，这里展示两个部分：(1) 数据集加载（可离线运行）；(2) 使用示例数据生成的 ASR 对比图。

**数据集加载**——`--list-datasets` 可离线运行，输出 16 个数据集的名称、条数、语言、标签。

**图 6：ASR 对比柱状图**（示例数据生成，展示 Baseline vs RoleBreak 对比）

![ASR 对比图](academic-research-extract-aig-for-experiments/results/asr_comparison.png)

示例数据展示了 RoleBreak 在 4 个模型上的效果：GPT-4o 平均 ASR 从 10.6% 提升至 31.4%，Qwen-Plus 从 20.9% 提升至 50.8%。

**图 7：JailBench-Tiny 分类 ASR 图**（示例数据生成，展示中文越狱的分类细粒度分析）

![分类 ASR 图](academic-research-extract-aig-for-experiments/results/category_asr_jailbench.png)

利用 JailBench-Tiny 的 `一级领域` 标签做的细粒度分析：比如说"暴恐、色情、非法交易"类别的 ASR 显著高于"违反社会主义核心价值观"类别，暗示中文安全对齐在不同违规类型间存在不均衡。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Eval Setup | 5 个数据集（3 英文 + 2 中文） | "覆盖中英文越狱和有害内容场景" |
| RQ1 | advbench ASR | "RoleBreak 将 GPT-4o 的 ASR 从 8.5% 提升至 28.3%" |
| RQ3 | 多模型对比矩阵 | "Qwen-Plus 最易被攻破，GPT-4o 相对抗性最强" |
| RQ4 | JailBench-Tiny 分类标签 | "中文越狱 ASR 普遍高于英文，不同违规类型间对齐不均衡" |

---

## 场景四：AI 安全研究空白与攻击面测绘

### 研究背景

安全方向的博士后正在写 **Systematization of Knowledge (SoK)** 论文。注意到一个现象：AI 安全研究集中在 LLM 本身（越狱、提示注入），但 AI **基础设施**层（推理引擎、Agent 平台、模型仓库）的安全研究严重不足。

论文拟定标题 *"SoK: Security of AI Infrastructure—A Component-Level Attack Surface Mapping"*，目标是投 **IEEE S&P 2026** SoK track。

### 卡在哪里

SoK 论文需要"AI 组件 × 安全覆盖情况"的交叉矩阵，但**两个维度都没有**：

**缺维度 1：AI 组件清单。** 自己整理了一周才 80 个组件，不确定是否完整。

**缺维度 2：每个组件的安全覆盖情况。** 要去 NVD 逐个搜索 80 个组件名，而且 NVD 搜索不一定准。

### AIG 里有现成的

AIG 的两个数据目录天然构成交叉矩阵：
- `data/fingerprints/`：**121 个组件**的识别指纹（组件清单维度）
- `data/vuln/`：**83 个组件**的 CVE 规则（安全覆盖维度）

差集 = 有指纹但无 CVE = **安全研究空白**。

### 如何提取与改造

配套脚本：[attack_surface_gap.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/attack_surface_gap.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/attack_surface_gap.py`，交叉对比指纹与漏洞规则，输出攻击面空白报告。核心逻辑是集合差集，3 行代码搞定。

```bash
python attack_surface_gap.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

**表 6：覆盖概览**

| 指标 | 数值 |
|------|------|
| 有指纹的组件 | 121 |
| 有 CVE 规则的组件 | 83 |
| 有覆盖（交集） | 70 |
| 攻击面空白（有指纹无 CVE） | 51 |
| 仅有漏洞（无指纹） | 13 |
| 覆盖率 | 68.6% |

**图 8：覆盖概览图**

![覆盖概览图](academic-research-extract-aig-for-experiments/results/coverage_overview.png)

**图 9：有 CVE 规则的组件 Top 15**

![Top 覆盖组件图](academic-research-extract-aig-for-experiments/results/top_covered_components.png)

**表 7：指纹识别技术分布**

| 技术 | 使用次数 | 解读 |
|------|---------|------|
| HTTP Body Matching | 154 | 最常用，匹配页面特征字符串 |
| Version Extract: body | 27 | 从响应体正则提取版本号 |
| HTTP Header Matching | 13 | 匹配响应头特征 |
| Favicon Hash | 5 | 通过 icon hash 识别 |
| Version Extract: header | 2 | 从响应头提取版本号 |

**CSV：`attack_surface_gap.csv`**——51 个空白组件的完整列表。

空白组件包括 aws-bedrock、azure-openai、cloudflare-ai-gateway、databricks-model-serving 等——云 AI 服务和 AI 网关是安全研究的盲区。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Component Taxonomy | 121 个指纹 | "识别了 121 个主流 AI 基础设施组件" |
| Coverage Analysis | 覆盖率 68.6% | "83 个组件有公开 CVE，51 个缺乏安全研究" |
| Fingerprint Techniques | 技术分布表 | "Body matching 是最常用的识别技术" |
| Research Agenda | 空白组件表 | "云 AI 服务和 AI 网关是未来研究重点" |

---

## 场景五：MCP 安全威胁分类学实证分析

### 研究背景

安全方向的研究生正在写 **MCP（Model Context Protocol）安全的 SoK 论文**。MCP 是 Anthropic 提出的标准化协议，允许 LLM 通过外部工具扩展能力，但随之而来的安全问题——命令注入、凭证外泄、工具投毒——尚无系统性的威胁分类研究。

论文拟定标题 *"SoK: Threat Taxonomy and Detection Patterns of MCP Server Security"*，目标是投 **IEEE S&P 2026** SoK track。核心 RQ：

- **RQ1**：MCP Server 面临哪些类型的威胁？
- **RQ2**：现有检测方法覆盖了哪些代码模式和判断标准？
- **RQ3**：MCP 威胁与传统 Web 安全的异同点是什么？

### 卡在哪里

**缺一个 MCP 威胁分类学的种子。** MCP 安全研究刚起步，目前没有公认的威胁分类框架。自己从零构建分类学需要阅读大量 CVE 和 attack report，时间至少 2 个月。

**缺检测模式的量化数据。** 想做"现有 MCP 安全检测方法覆盖度分析"，但没有现成的检测规则集可统计——每篇论文都是自己写规则，无法横向对比。

### AIG 里有现成的

AIG 的 `data/mcp/` 目录包含 **4 类 MCP 安全检测规则**，每条规则是一个 YAML 文件，包含完整的 LLM prompt 模板、漏洞定义、检测代码模式（Code Patterns）、判断标准（Judgment Standards）和输出要求。

以 [mcp_command_injection.yaml](../data/mcp/mcp_command_injection.yaml) 为例：

```yaml
info:
  id: "mcp_command_injection"
  name: "MCP Tool Command Injection Detection"
  description: "Detect MCP server tools that pass tool-call arguments
    into a shell, evaluator, or dynamic-import sink without sanitization"
  categories:
    - code

prompt_template: |
  ## Vulnerability Definition
  An MCP tool handler takes caller-supplied arguments (from `inputSchema`
  parameters) and routes them into a code-execution sink...

  ## Detection Criteria (require tainted argument -> sink)
  ### 1. Shell execution of arguments
  **Code Patterns:**
  - `child_process.exec` / `execSync` / `spawn(..., {shell:true})`
  - `os.system`, `subprocess.*(..., shell=True)`

  ### 2. Dynamic evaluation
  **Code Patterns:**
  - `eval` / `Function(...)` / `vm.runIn*`

  ## Strict Judgment Standards
  - **Constant commands**: Do not report fixed commands...
  - **Safe APIs**: Do not report `execFile` / `spawn` with `shell:false`...
```

4 条规则一览：

| 规则 ID | 威胁类型 | 代码模式数 | 判断标准数 | Prompt 长度 |
|---------|---------|-----------|-----------|------------|
| mcp_command_injection | 命令注入 | 3 | 4 | 2619 |
| mcp_credential_exfiltration | 凭证外泄 | 3 | 3 | 2467 |
| mcp_tool_poisoning | 工具投毒 | 3 | 3 | 2716 |
| cors_misconfig | CORS 配置不当 | 1 | 5 | 5213 |

### 如何提取与改造

配套脚本：[extract_mcp_threat_taxonomy.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_mcp_threat_taxonomy.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/extract_mcp_threat_taxonomy.py`，遍历 `data/mcp/` 所有 YAML，提取规则元数据、统计检测代码模式数量和判断标准数量，生成分类学统计表和可视化图表。

**运行方式：**

```bash
python extract_mcp_threat_taxonomy.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

脚本成功提取 4 条 MCP 规则，合计 **10 个检测代码模式** 和 **15 条判断标准**，平均每条规则的 prompt 模板长度为 3254 字符。

**表 8：MCP 威胁类型分布（对应论文 RQ1）**

| 威胁类型 | 规则数 | 代码模式数 | 判断标准数 |
|---------|--------|-----------|-----------|
| 命令注入 | 1 | 3 | 4 |
| 凭证外泄 | 1 | 3 | 3 |
| 工具投毒 | 1 | 3 | 3 |
| CORS 配置不当 | 1 | 1 | 5 |

**图 13：MCP 威胁类型分布饼图**

![MCP 威胁类型分布](academic-research-extract-aig-for-experiments/results/mcp_threat_type_pie.png)

**图 14：各规则检测复杂度对比**

![MCP 检测复杂度](academic-research-extract-aig-for-experiments/results/mcp_detection_complexity.png)

命令注入、凭证外泄和工具投毒三条规则各自包含 3 类代码模式，但 CORS 规则虽然只有 1 类模式，却拥有最多的 5 条判断标准——反映了 CORS 检测需要更精细的误报排除逻辑。

**图 15：Prompt 模板长度对比**

![MCP Prompt 长度](academic-research-extract-aig-for-experiments/results/mcp_prompt_length.png)

**CSV：`mcp_threat_taxonomy.csv`**——4 条规则的完整结构化数据。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Threat Taxonomy | 4 类威胁分类 | "我们基于 AIG 的规则集构建了 MCP 威胁分类学初始框架" |
| RQ2 | 代码模式+判断标准统计 | "现有检测方法覆盖了 10 类代码模式，但判断标准仅有 15 条" |
| Discussion | CORS 规则分析 | "CORS 检测的误报排除逻辑最复杂，反映配置类漏洞的判断难度" |
| Data Availability | CSV + JSON | "规则集已开源，可复现分类学构建过程" |

---

## 场景六：Agent 安全检测规则知识库提取与威胁分类统计

### 研究背景

AI Agent 方向的博士生正在做 **Agent 安全综述（Survey）**。注意到 Agent 安全领域虽然论文不少，但缺乏一个系统性的威胁分类和检测方法盘点。OWASP 刚发布了 Agentic Security Intelligence（ASI）Top 10，但缺乏对应的检测方法清单。

论文拟定标题 *"A Survey of Agent Security: Threat Detection Methods and OWASP ASI Mapping"*，目标是投 **ACM Computing Surveys**。

### 卡在哪里

**缺检测方法的系统盘点。** Agent 安全检测散落在各个工具和论文中——有的用 LLM 对话探测，有的用静态分析，有的用动态测试——需要一个统一的框架来盘点和分类。

**缺 OWASP ASI 的检测覆盖矩阵。** 想做"OWASP ASI Top 10 各类风险的检测方法覆盖度"分析，但没有现成的检测方法清单可映射。

### AIG 里有现成的

AIG 的 `agent-scan/prompt/skills/` 目录包含 **9 类 Agent Skill 安全检测器**，每个检测器是一个 `SKILL.md` 文件，包含：

- 检测场景描述和适用条件（When to Use）
- 测试向量（dialogue probes、表格化的攻击 payload）
- 判断标准（Judge：Vulnerable vs Safe 的定义）
- OWASP ASI 映射

9 类检测器一览：

| 检测器 | 威胁类型 | 对话测试向量 | 表格测试向量 | OWASP ASI 映射 |
|--------|---------|------------|------------|---------------|
| tool-abuse-detection | 工具滥用 | 2 | 3 | ASI02, ASI05 |
| authorization-bypass-detection | 权限绕过 | 1 | 0 | ASI03 |
| data-leakage-detection | 数据泄露 | 9 | 15 | ASI06, ASI07 |
| direct-injection-detection | 直接注入 | 0 | 0 | ASI01 |
| indirect-injection-detection | 间接注入 | 1 | 0 | ASI01 |
| file-path-traversal-detection | 路径穿越 | 0 | 0 | ASI02 |
| hardcoded-secret-detection | 硬编码密钥 | 0 | 0 | ASI04 |
| memory-poisoning-detection | 记忆投毒 | 0 | 0 | ASI06 |
| owasp-asi | OWASP 框架 | 0 | 29 | 全部映射 |

其中 `data-leakage-detection` 最为复杂——采用 3 阶段递进探测策略（Direct → Evasion → Jailbreak），包含 9 个对话探测点和 15 个表格化攻击向量。`owasp-asi` 本身是 OWASP ASI 分类框架，提供了 ASI01-ASI10 的完整定义和检测源映射表。

### 如何提取与改造

配套脚本：[extract_agent_skill_rules.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_agent_skill_rules.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/extract_agent_skill_rules.py`，遍历 `agent-scan/prompt/skills/` 所有 `SKILL.md`，解析 frontmatter 和正文结构，统计测试向量数量、判断标准、OWASP ASI 映射，输出分类学统计表和可视化图表。

**运行方式：**

```bash
python extract_agent_skill_rules.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

脚本成功提取 9 个检测器，合计 **13 个对话测试向量** 和 **47 个表格测试向量**。

**表 9：Agent 安全威胁类型分布（对应论文 RQ1）**

| 威胁类型 | 检测器数 | 测试向量总数 |
|---------|---------|------------|
| 数据泄露 | 1 | 24 |
| 工具滥用 | 1 | 5 |
| 权限绕过 | 1 | 1 |
| 直接注入 | 1 | 0 |
| 间接注入 | 1 | 1 |
| 路径穿越 | 1 | 0 |
| 硬编码密钥 | 1 | 0 |
| 记忆投毒 | 1 | 0 |
| OWASP 框架 | 1 | 29 |

**图 16：各检测器测试向量数量**

![Agent Skill 测试向量](academic-research-extract-aig-for-experiments/results/agent_skill_vectors.png)

**图 17：Agent 安全威胁类型分布**

![Agent 威胁类型分布](academic-research-extract-aig-for-experiments/results/agent_threat_types.png)

**图 18：检测器复杂度雷达图**

![Agent Skill 雷达图](academic-research-extract-aig-for-experiments/results/agent_skill_radar.png)

雷达图显示 `data-leakage-detection` 在对话向量、表格向量和内容长度三个维度上均为最高值，是 9 个检测器中复杂度最高的。

**CSV：`agent_skill_rules.csv`**——9 个检测器的完整结构化数据。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Threat Taxonomy | 9 类检测器 | "我们系统盘点了 9 类 Agent 安全检测方法" |
| OWASP ASI Mapping | 检测器→ASI 映射 | "数据泄露检测覆盖 ASI06/ASI07，工具滥用覆盖 ASI02/ASI05" |
| Detection Coverage | 向量统计 | "现有方法共提供 60 个测试向量，但 4 类威胁无测试向量" |
| Research Agenda | 空白检测器 | "路径穿越、硬编码密钥、记忆投毒缺乏对话测试向量" |

---

## 场景七：越狱攻击编码方法分类学构建

### 研究背景

NLP/AI Safety 方向的研究生正在做 **越狱攻击防御研究**。核心思路是：如果 LLM 的安全对齐只在"明文"层面有效，那么通过编码变换（Base64、Caesar、Unicode 样式等）绕过对齐就是一个系统性漏洞。论文需要先构建一个**编码攻击的分类学**，再针对每类设计防御。

论文拟定标题 *"Taxonomy and Defense of Encoding-Based Jailbreak Attacks on LLMs"*，目标是投 **ACL 2026**。

### 卡在哪里

**编码攻击分类学没有现成的。** 散见于各论文的编码方法包括 Base64（LLM Attacks）、Caesar Cipher（JailbreakBench）、Leetspeak（AdvBench）等，但没有一个统一分类。自己从论文中收集整理需要 3-4 周。

**编码方法太多，无法穷举。** 仅 Unicode 样式变换就有全角、小型大写、哥特体等十几种，不知道还有哪些遗漏。

### AIG 里有现成的

AIG 的 `AIG-PromptSecurity/deepteam/attacks/single_turn/encoding/` 目录包含 **72 种编码攻击方法**，每种方法是一个独立的 Python 类，继承自 `BaseAttack`，实现 `enhance(attack: str) -> str` 接口。

以 [caesar.py](../AIG-PromptSecurity/deepteam/attacks/single_turn/encoding/caesar.py) 为例：

```python
class CaesarCipher(BaseAttack):
    def __init__(self, weight: int = 1, shift: int = 3):
        self.weight = weight
        self.shift = 3  # Traditional Caesar shift

    def enhance(self, attack: str) -> str:
        result = []
        for c in attack:
            code = ord(c)
            if 65 <= code <= 90:  # Uppercase
                shifted = ((code - 65 + self.shift) % 26) + 65
                result.append(chr(shifted))
            elif 97 <= code <= 122:  # Lowercase
                shifted = ((code - 97 + self.shift) % 26) + 97
                result.append(chr(shifted))
            else:
                result.append(c)
        return ''.join(result)
```

72 种方法通过 `__init__.py` 统一注册，可按分类学归为 **7 大编码族**：

| 编码族 | 方法数 | 代表方法 | 变换原理 |
|--------|--------|---------|---------|
| Symbol System | 19 | Morse, Braille, NATO, Wingdings | 用替代符号系统替换文本 |
| Unicode Stylistic | 15 | FullWidth, SmallCaps, Fraktur, Monospace | 利用 Unicode 同形/样式字符 |
| Classical Cipher | 9 | Caesar, Vigenere, Atbash, RailFence | 古典密码学变换 |
| Homoglyph/Obfuscation | 8 | Zalgo, ZeroWidth, AsciiSmuggling | 不可见字符或视觉混淆 |
| Case Manipulation | 7 | AlternatingCase, CamelCase, RandomCase | 改变字母大小写模式 |
| Base Encoding | 7 | Base64, Hex, Binary, URL | 标准 Base 系列编码 |
| Linguistic Transform | 6 | Leetspeak, PigLatin, Disemvowel | 语音/语言层面变换 |

### 如何提取与改造

配套脚本：[extract_encoding_taxonomy.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_encoding_taxonomy.py)

> 📁 位于 `academic-research-extract-aig-for-experiments/extract_encoding_taxonomy.py`，从 encoding 目录的 `__init__.py` 提取全部 72 种编码方法的类名和模块名，按 7 大编码族分类，统计映射表使用率、参数化配置率，生成分类学饼图和复杂度散点图。

**运行方式：**

```bash
python extract_encoding_taxonomy.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results
```

### 实际运行结果

脚本成功提取 72 种编码方法，归入 7 大编码族。其中 **31 种方法使用了字符映射表**，**全部 72 种方法都支持参数化配置**（如 Caesar 的 shift 值、BaseEncoding 的编码类型）。

**表 10：编码族分布（对应论文分类学核心表）**

| 编码族 | 方法数 | 占比 | 使用映射表 | 代表方法 |
|--------|--------|------|-----------|---------|
| Symbol System | 19 | 26.4% | 19 | Morse, Braille, NATO, Wingdings |
| Unicode Stylistic | 15 | 20.8% | 15 | FullWidth, SmallCaps, Fraktur |
| Classical Cipher | 9 | 12.5% | 6 | Caesar, Vigenere, Atbash |
| Homoglyph/Obfuscation | 8 | 11.1% | 4 | Zalgo, ZeroWidth, AsciiSmuggling |
| Case Manipulation | 7 | 9.7% | 0 | AlternatingCase, RandomCase |
| Base Encoding | 7 | 9.7% | 3 | Base64, Hex, Binary |
| Linguistic Transform | 6 | 8.3% | 5 | Leetspeak, PigLatin, Disemvowel |
| Other | 1 | 1.4% | 0 | Emoji |

**图 19：编码族分布饼图**

![编码族分布](academic-research-extract-aig-for-experiments/results/encoding_family_pie.png)

**图 20：各类别编码方法数量**

![编码类别柱状图](academic-research-extract-aig-for-experiments/results/encoding_category_bar.png)

**图 21：编码方法复杂度散点图**

![编码复杂度散点图](academic-research-extract-aig-for-experiments/results/encoding_complexity_scatter.png)

散点图显示 Symbol System 和 Unicode Stylistic 类的方法文件普遍较大（映射表占用空间），而 Case Manipulation 类方法最为轻量。

**CSV：`encoding_taxonomy.csv`**——72 种编码方法的完整分类学数据。

### 对论文的贡献

| 论文章节 | 贡献 | 论文里怎么写 |
|---------|------|-------------|
| Taxonomy | 7 族 72 种编码方法 | "我们构建了首个覆盖 72 种编码变换的越狱攻击分类学" |
| RQ1 | 编码族分布 | "符号系统替换（26.4%）和 Unicode 样式变换（20.8%）是最大的两个编码族" |
| RQ2 | 映射表使用率 | "43.1% 的方法依赖字符映射表，防御可针对映射表做检测" |
| Defense Design | 分类学指导防御 | "每类编码族需不同的检测策略：密码学类需解密，Unicode 类需归一化" |
| Data Availability | CSV + JSON | "72 种编码方法已开源，可直接用于防御评估" |

---

## 启发与展望：从引用论文看 AIG 的学术价值

### 写这篇文章的契机

这篇文章的灵感，其实来自一个很具体的场景。我们在翻 AIG 的 README 时，注意到末尾有一个 **"Papers"** 板块，列出了已经引用 AIG 的 **19 篇学术论文**——从 2025 年 8 月到 2026 年 5 月，不到一年时间就有 19 篇 arXiv 预印本引用了这个项目。

这让我们意识到一件事：AIG 不仅仅是一个"扫描工具"，它的数据仓库（漏洞规则、组件指纹、越狱评测数据集）本身就是一个**学术研究素材库**。那些引用论文的研究者，其实就是在做本文四个场景所描述的事情——从 AIG 中提取数据、改造工具、构建基准、设计实验，最终产出学术论文。

所以我们就想：如果把这种"如何用 AIG 做学术研究"的方法论整理出来，是不是能给更多研究者启发？这就是这篇文章的由来。

### 引用论文全景统计

我们对 README 中列出的 19 篇引用论文做了分类统计。配套脚本：[analyze_citations.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/analyze_citations.py)，运行方式：

```bash
python analyze_citations.py --output-dir ./results
```

**按研究主题分类**，19 篇论文可以分为 6 大类：

| 研究主题 | 论文数 | 占比 | 典型论文 |
|---------|--------|------|---------|
| MCP/Tool Security | 9 | 47.4% | MCPGuard, MCPSecBench, MCP-38 |
| Agent Red Teaming | 4 | 21.1% | SkillAttack, Proteus, MalTool |
| Agent Security | 2 | 10.5% | ADR, Trusted AI Agents |
| LLM Defense | 2 | 10.5% | FraudShield, Beyond Jailbreak |
| Adversarial ML | 1 | 5.3% | HogVul |
| Agent Survey | 1 | 5.3% | AgentOps Survey |

**图 10：引用论文按研究主题分布**

![引用论文分类饼图](academic-research-extract-aig-for-experiments/results/citations_category_pie.png)

从分布来看，**近半数（47.4%）引用论文聚焦 MCP/Tool 安全**——这与 AIG 较早布局 MCP 扫描能力直接相关。AIG 的 `data/mcp/` 规则集和 14 类威胁分类，为这一波 MCP 安全研究提供了基础威胁模型。

**按发表年份分布**：

| 年份 | 论文数 |
|------|--------|
| 2025 | 9 |
| 2026 | 10 |

**图 11：引用论文年度趋势**

![引用论文年度趋势](academic-research-extract-aig-for-experiments/results/citations_year_trend.png)

2026 年仅过去 5 个月就有 10 篇，引用速度在加快，说明 AIG 的学术影响力正在增长。

**图 12：引用论文按二级研究主题分布**

![引用论文二级分类](academic-research-extract-aig-for-experiments/results/citations_subcategory_bar.png)

### 引用论文如何使用 AIG

更值得注意的是，这 19 篇论文使用 AIG 的方式各不相同，可以归纳为以下几种模式：

**模式一：直接复用规则集作为检测基准。** 比如说 MCPGuard 直接基于 AIG 的 MCP 扫描引擎构建自动化检测系统；MCPSecBench 将 AIG 的 MCP 安全规则作为基准对比对象，验证自身基准的覆盖度。

**模式二：参考威胁分类构建分类学。** 比如说 MCP-38 在 AIG 的 14 类 MCP 威胁基础上扩展为 38 类完整威胁分类学；"When MCP Servers Attack" 引用 AIG 的威胁分类作为攻击分类学基础。

**模式三：利用数据集验证防御方案。** 比如说 FraudShield 和 "Beyond Jailbreak" 都使用了 AIG 的越狱评测数据集来验证防御方案的鲁棒性。

**模式四：将 AIG 作为红队攻击工具池。** 比如说 "Automatic Red Teaming LLM-based Agents" 利用 AIG 的 MCP 工具集作为自动化红队的攻击工具；Proteus 利用 AIG 的 Skill 扫描规则集作为初始攻击种子。

**模式五：将 AIG 作为对抗目标。** 比如说 HogVul 将 AIG 的漏洞检测引擎作为对抗目标，评估对抗性代码生成能否绕过 AIG 的检测。

### 对读者的启发

统计完这些引用论文后，我们可以看到几条清晰的研究路径：

**路径 1：MCP 安全仍然是热点。** 19 篇中有 9 篇聚焦 MCP，但细分方向各异——有的做检测（MCPGuard），有的做基准（MCPSecBench），有的做分类学（MCP-38），有的做攻击（MCP-ITP）。如果我们的研究兴趣在 MCP 方向，可以看看哪个细分角度还没人做过。比如说，AIG 的 `data/mcp/` 规则集目前覆盖了 14 类威胁，但隐式工具投毒（Implicit Tool Poisoning）只有 MCP-ITP 一篇在探索，这个方向还有空间。

**路径 2：Agent 红队是一个新兴方向。** 4 篇 Agent Red Teaming 论文都出现在 2026 年，说明这是刚起步的热点。AIG 的 Agent Scan 框架和 Skill 扫描规则可以为我们提供初始攻击面。比如说，Proteus 做的是"自进化红队"，那"对抗自进化红队的防御"就还没人做。

**路径 3：越狱评测数据集有跨领域复用价值。** FraudShield 用越狱数据集验证反欺诈防御，"Beyond Jailbreak" 用它研究能力边界模糊风险——都不是传统的"越狱攻击"论文，但都复用了 AIG 的 `data/eval/` 数据集。这启发我们：这些数据集不只能用于安全评测，也可以用于对齐质量评估、能力边界研究等。

**路径 4：对抗性研究是一个独特角度。** HogVul 把 AIG 当"靶子"来攻——这提醒我们，AIG 作为一个检测工具，它自身的鲁棒性（能不能被绕过）本身就是一个研究课题。类似地，AIG 的指纹识别引擎能否被欺骗，也是一个可以探索的方向。

**路径 5：综述类论文需要工具全景。** "AgentOps Survey" 在综述中引用 AIG 作为安全检测代表工具。如果我们在写 AI 安全相关的 SoK 或 Survey 论文，AIG 的 121 个组件指纹和 1247 条 CVE 规则可以作为"现有安全工具覆盖度"的量化依据。

总的来说，AIG 的价值在于它同时提供了**数据**（漏洞规则、指纹、评测数据集、MCP 威胁规则、Agent 检测器、编码攻击方法）、**工具**（扫描引擎、检测框架）和**基准**（威胁分类、评测方法），而不同的研究者可以根据自己的需求，提取其中一部分来支撑自己的研究。希望本文的七个场景和这 19 篇引用论文的统计，能为读者提供一些具体的切入点。

---

## 引用 AIG

如果论文使用了 AIG 的数据或工具，请引用：

```bibtex
@article{yang2026securing,
  title={Securing the AI Agent: A Unified Framework for Multi-Layer Agent Red Teaming},
  author={Yang, Yong and Zheng, Xing and Wu, Huiyu and Cheng, Huangsheng and Shi, Xiaorong and Guo, Jing and Yang, Bo and Zhou, Yi and Wu, Xiangfan and Ying, Zonghao},
  journal={arXiv preprint arXiv:2606.31227},
  year={2026}
}
```

已有 19 篇论文引用了 AIG，代表性引用论文：

- **MCPGuard** — 自动检测 MCP Server 漏洞（arXiv:2510.23673）
- **MCPSecBench** — MCP 安全系统化基准（arXiv:2508.13220）
- **SkillAttack** — Agent Skills 自动化红队（arXiv:2604.04989）
- **Proteus** — Agent Skill 生态自进化红队（arXiv:2605.11891）

---

## 配套代码与图表一览

| 脚本 | 作用 | 对应场景 | 生成的图表 |
|------|------|---------|-----------|
| [extract_cve_stats.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_cve_stats.py) | CVE 统计与可视化 | 场景一 | severity_pie.png, top_components_bar.png, yearly_trend.png |
| [analyze_cvss_vectors.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/analyze_cvss_vectors.py) | CVSS 向量解析与计算 | 场景二 | cia_heatmap.png, attack_surface_radar.png |
| [jailbreak_eval_pipeline.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/jailbreak_eval_pipeline.py) | 越狱评测框架 | 场景三 | asr_comparison.png（需 API Key） |
| [generate_demo_asr_chart.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/generate_demo_asr_chart.py) | 示例 ASR 图表生成 | 场景三 | asr_comparison.png, category_asr_jailbench.png |
| [attack_surface_gap.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/attack_surface_gap.py) | 攻击面空白分析 | 场景四 | coverage_overview.png, top_covered_components.png |
| [extract_mcp_threat_taxonomy.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_mcp_threat_taxonomy.py) | MCP 威胁分类学提取 | 场景五 | mcp_threat_type_pie.png, mcp_detection_complexity.png, mcp_prompt_length.png |
| [extract_agent_skill_rules.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_agent_skill_rules.py) | Agent 安全检测规则提取 | 场景六 | agent_skill_vectors.png, agent_threat_types.png, agent_skill_radar.png |
| [extract_encoding_taxonomy.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/extract_encoding_taxonomy.py) | 编码攻击分类学提取 | 场景七 | encoding_family_pie.png, encoding_category_bar.png, encoding_complexity_scatter.png |
| [analyze_citations.py](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/analyze_citations.py) | 引用论文分类统计 | 启发与展望 | citations_category_pie.png, citations_year_trend.png, citations_subcategory_bar.png |
| [eval_config.yaml](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/eval_config.yaml) | 越狱评测配置模板 | 场景三 | — |
| [requirements.txt](https://github.com/NY1024/AIG-Recipes/blob/main/mini-data/academic-research-extract-aig-for-experiments/requirements.txt) | Python 依赖清单 | 全部 | — |

所有脚本均可独立运行，只需 `git clone` AIG 仓库即可获取数据：

```bash
git clone https://github.com/Tencent/AI-Infra-Guard.git
cd AI-Infra-Guard/mini-data/academic-research-extract-aig-for-experiments
pip install -r requirements.txt

# 场景一、二、四：无需 API Key，直接运行
python extract_cve_stats.py --aig-root ../.. --output-dir ./results
python analyze_cvss_vectors.py --aig-root ../.. --output-dir ./results
# 场景四：无需 API Key，直接运行
python attack_surface_gap.py --aig-root ../.. --output-dir ./results

# 场景五、六、七：无需 API Key，直接运行
python extract_mcp_threat_taxonomy.py --aig-root ../.. --output-dir ./results
python extract_agent_skill_rules.py --aig-root ../.. --output-dir ./results
python extract_encoding_taxonomy.py --aig-root ../.. --output-dir ./results

# 场景三：无需 API Key 的示例图表
python generate_demo_asr_chart.py --output-dir ./results

# 场景三：需要 API Key 的真实评测
python jailbreak_eval_pipeline.py --list-datasets --aig-root ../..
python jailbreak_eval_pipeline.py --config eval_config.yaml --aig-root ../.. --output-dir ./results

# 启发与展望：引用论文分类统计
python analyze_citations.py --output-dir ./results
```

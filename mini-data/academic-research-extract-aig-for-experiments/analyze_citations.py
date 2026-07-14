#!/usr/bin/env python3
"""
引用 AIG 的学术论文分类统计与可视化

从 AIG README 中列出的 19 篇引用论文出发，
按研究主题分类统计，生成饼图和柱状图，
供技术文章"启发与展望"一节使用。

使用方式:
    python analyze_citations.py --output-dir ./results

依赖:
    pip install matplotlib
"""

import argparse
import os
import sys

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("请安装依赖: pip install matplotlib numpy")
    sys.exit(1)


# ──────────────────────────────────────────────
# 19 篇引用论文数据（来源: AIG README）
# ──────────────────────────────────────────────

PAPERS = [
    {
        'title': 'ADR: An Agentic Detection System for Enterprise Agentic AI Security',
        'authors': 'Chenning Li et al.',
        'arxiv': '2605.17380',
        'year': 2026,
        'category': 'Agent Security',
        'subcategory': 'Enterprise Agent Detection',
        'uses_aig': '参考 AIG 的 Agent 安全扫描架构设计企业级 Agent 检测系统',
    },
    {
        'title': 'Proteus: A Self-Evolving Red Team for Agent Skill Ecosystems',
        'authors': 'Zhaojiacheng Zhou',
        'arxiv': '2605.11891',
        'year': 2026,
        'category': 'Agent Red Teaming',
        'subcategory': 'Agent Skill Red Team',
        'uses_aig': '利用 AIG 的 Skill 扫描规则集作为初始攻击种子，构建自进化红队',
    },
    {
        'title': 'TRUSTDESC: Preventing Tool Poisoning in LLM Applications via Trusted Description Generation',
        'authors': 'Hengkai Ye et al.',
        'arxiv': '2604.07536',
        'year': 2026,
        'category': 'MCP/Tool Security',
        'subcategory': 'Tool Poisoning Defense',
        'uses_aig': '引用 AIG 的 MCP 工具投毒检测规则作为威胁模型基础',
    },
    {
        'title': 'SkillAttack: Automated Red Teaming of Agent Skills through Attack Path Refinement',
        'authors': 'Zenghao Duan et al.',
        'arxiv': '2604.04989',
        'year': 2026,
        'category': 'Agent Red Teaming',
        'subcategory': 'Agent Skill Attack',
        'uses_aig': '基于 AIG 的 Skill 风险分类体系设计攻击路径自动精炼方法',
    },
    {
        'title': 'From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers',
        'authors': 'Yiheng Huang et al.',
        'arxiv': '2604.01905',
        'year': 2026,
        'category': 'MCP/Tool Security',
        'subcategory': 'Malicious MCP Detection',
        'uses_aig': '复用 AIG 的 MCP 恶意服务器检测规则作为检测基准',
    },
    {
        'title': 'MCP-38: A Comprehensive Threat Taxonomy for Model Context Protocol Systems',
        'authors': 'Yi Ting Shen et al.',
        'arxiv': '2603.18063',
        'year': 2026,
        'category': 'MCP/Tool Security',
        'subcategory': 'Threat Taxonomy',
        'uses_aig': '参考 AIG 的 MCP 14 类威胁分类构建 38 类完整威胁分类学',
    },
    {
        'title': 'MalTool: Malicious Tool Attacks on LLM Agents',
        'authors': 'Yuepeng Hu et al.',
        'arxiv': '2602.12194',
        'year': 2026,
        'category': 'Agent Red Teaming',
        'subcategory': 'Malicious Tool Attack',
        'uses_aig': '利用 AIG 的工具安全检测规则定义恶意工具攻击分类',
    },
    {
        'title': 'FraudShield: Knowledge Graph Empowered Defense for LLMs against Fraud Attacks',
        'authors': 'Naen Xu et al.',
        'arxiv': '2601.22485',
        'year': 2026,
        'category': 'LLM Defense',
        'subcategory': 'Fraud Defense',
        'uses_aig': '引用 AIG 的越狱评测数据集验证防御方案鲁棒性',
    },
    {
        'title': 'MCP-ITP: An Automated Framework for Implicit Tool Poisoning in MCP',
        'authors': 'Ruiqi Li et al.',
        'arxiv': '2601.07395',
        'year': 2026,
        'category': 'MCP/Tool Security',
        'subcategory': 'Implicit Tool Poisoning',
        'uses_aig': '基于 AIG 的工具投毒检测规则扩展隐式投毒检测框架',
    },
    {
        'title': 'HogVul: Black-box Adversarial Code Generation Framework Against LM-based Vulnerability Detectors',
        'authors': 'Jingxiao Yang et al.',
        'arxiv': '2601.05587',
        'year': 2026,
        'category': 'Adversarial ML',
        'subcategory': 'Adversarial Code vs Detector',
        'uses_aig': '将 AIG 的漏洞检测引擎作为对抗目标，评估对抗性代码生成效果',
    },
    {
        'title': 'Trusted AI Agents in the Cloud',
        'authors': 'Teofil Bodea et al.',
        'arxiv': '2512.05951',
        'year': 2025,
        'category': 'Agent Security',
        'subcategory': 'Cloud Agent Trust',
        'uses_aig': '引用 AIG 的 Agent 安全评估方法构建云端 Agent 信任框架',
    },
    {
        'title': 'Beyond Jailbreak: Unveiling Risks in LLM Applications Arising from Blurred Capability Boundaries',
        'authors': 'Yunyi Zhang et al.',
        'arxiv': '2511.17874',
        'year': 2025,
        'category': 'LLM Defense',
        'subcategory': 'Capability Boundary Risk',
        'uses_aig': '使用 AIG 的越狱评测数据集验证能力边界模糊带来的风险',
    },
    {
        'title': 'MCPGuard: Automatically Detecting Vulnerabilities in MCP Servers',
        'authors': 'Bin Wang et al.',
        'arxiv': '2510.23673',
        'year': 2025,
        'category': 'MCP/Tool Security',
        'subcategory': 'MCP Vulnerability Detection',
        'uses_aig': '直接基于 AIG 的 MCP 扫描引擎和规则集构建自动化检测系统',
    },
    {
        'title': 'When MCP Servers Attack: Taxonomy, Feasibility, and Mitigation',
        'authors': 'Weibo Zhao et al.',
        'arxiv': '2509.24272',
        'year': 2025,
        'category': 'MCP/Tool Security',
        'subcategory': 'MCP Attack Taxonomy',
        'uses_aig': '引用 AIG 的 MCP 威胁分类作为攻击分类学基础',
    },
    {
        'title': 'Automatic Red Teaming LLM-based Agents with Model Context Protocol Tools',
        'authors': 'Ping He et al.',
        'arxiv': '2509.21011',
        'year': 2025,
        'category': 'Agent Red Teaming',
        'subcategory': 'Agent Auto Red Team',
        'uses_aig': '利用 AIG 的 MCP 工具集作为自动化红队攻击工具池',
    },
    {
        'title': 'Behavioral Detection Methods for Automated MCP Server Vulnerability Assessment',
        'authors': 'Christian Coleman',
        'arxiv': 'N/A (ODU)',
        'year': 2025,
        'category': 'MCP/Tool Security',
        'subcategory': 'Behavioral Detection',
        'uses_aig': '参考 AIG 的 MCP 检测方法设计行为检测方案',
    },
    {
        'title': 'MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols',
        'authors': 'Yixuan Yang et al.',
        'arxiv': '2508.13220',
        'year': 2025,
        'category': 'MCP/Tool Security',
        'subcategory': 'MCP Security Benchmark',
        'uses_aig': '将 AIG 的 MCP 安全规则作为基准对比对象，验证 MCPSecBench 的覆盖度',
    },
    {
        'title': 'Systematic Analysis of MCP Security',
        'authors': 'Yongjian Guo et al.',
        'arxiv': '2508.12538',
        'year': 2025,
        'category': 'MCP/Tool Security',
        'subcategory': 'MCP Systematic Analysis',
        'uses_aig': '引用 AIG 作为 MCP 安全领域的代表性工具进行系统性分析',
    },
    {
        'title': 'A Survey on AgentOps: Categorization, Challenges, and Future Directions',
        'authors': 'Zexin Wang et al.',
        'arxiv': '2508.02121',
        'year': 2025,
        'category': 'Agent Survey',
        'subcategory': 'AgentOps Survey',
        'uses_aig': '在 Agent 安全运维综述中引用 AIG 作为安全检测代表工具',
    },
]


# ──────────────────────────────────────────────
# 统计与可视化
# ──────────────────────────────────────────────

def count_by_category(papers):
    """按一级分类统计"""
    from collections import Counter
    return Counter(p['category'] for p in papers)


def count_by_year(papers):
    """按年份统计"""
    from collections import Counter
    return Counter(p['year'] for p in papers)


def plot_category_pie(cat_counts, output_dir):
    """生成一级分类饼图"""
    labels = list(cat_counts.keys())
    sizes = list(cat_counts.values())
    colors = ['#1976d2', '#388e3c', '#d32f2f', '#f57c00', '#7b1fa2', '#00838f']

    fig, ax = plt.subplots(figsize=(9, 7))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=None, autopct=lambda pct: f'{pct:.1f}%\n({int(round(pct/100*sum(sizes)))})',
        colors=colors[:len(labels)], startangle=140, pctdistance=0.75,
        wedgeprops=dict(edgecolor='white', linewidth=2)
    )
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_fontweight('bold')

    ax.legend(wedges, [f'{l} ({s})' for l, s in zip(labels, sizes)],
              loc='center left', bbox_to_anchor=(1, 0.5), fontsize=10)
    ax.set_title('Citation Papers by Research Category (19 total)',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    filepath = os.path.join(output_dir, 'citations_category_pie.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def plot_year_trend(year_counts, output_dir):
    """生成年度趋势柱状图"""
    years = sorted(year_counts.keys())
    counts = [year_counts[y] for y in years]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar([str(y) for y in years], counts, color='#1976d2', alpha=0.85,
                  edgecolor='black', linewidth=0.5, width=0.5)
    ax.set_ylabel('Number of Papers', fontsize=12)
    ax.set_xlabel('Year', fontsize=12)
    ax.set_title('AIG Citation Papers by Year', fontsize=14, fontweight='bold')
    ax.set_ylim(0, max(counts) + 3)

    for bar in bars:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                str(int(bar.get_height())), ha='center', va='bottom', fontsize=12, fontweight='bold')

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'citations_year_trend.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def plot_subcategory_bar(papers, output_dir):
    """生成二级分类柱状图（横向）"""
    from collections import Counter
    sub_counts = Counter(p['subcategory'] for p in papers)
    # 按数量排序
    sorted_items = sorted(sub_counts.items(), key=lambda x: x[1], reverse=True)
    labels = [item[0] for item in sorted_items]
    counts = [item[1] for item in sorted_items]

    fig, ax = plt.subplots(figsize=(12, 7))
    colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
    bars = ax.barh(range(len(labels)), counts, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel('Number of Papers', fontsize=12)
    ax.set_title('Citation Papers by Research Subcategory', fontsize=14, fontweight='bold')
    ax.invert_yaxis()
    ax.set_xlim(0, max(counts) + 1)

    for i, (bar, count) in enumerate(zip(bars, counts)):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                str(count), va='center', fontsize=10, fontweight='bold')

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'citations_subcategory_bar.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def print_summary(papers, cat_counts, year_counts):
    """打印统计摘要"""
    print(f"\n{'='*60}")
    print(f"AIG 引用论文分类统计摘要")
    print(f"{'='*60}")
    print(f"总论文数: {len(papers)}")
    print(f"\n按一级分类:")
    for cat, cnt in cat_counts.most_common():
        print(f"  {cat}: {cnt} ({cnt/len(papers)*100:.1f}%)")
    print(f"\n按年份:")
    for year in sorted(year_counts):
        print(f"  {year}: {year_counts[year]}")
    print(f"{'='*60}\n")


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='AIG 引用论文分类统计与可视化'
    )
    parser.add_argument('--output-dir', default='./results',
                        help='输出目录 (默认: ./results)')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    cat_counts = count_by_category(PAPERS)
    year_counts = count_by_year(PAPERS)

    print_summary(PAPERS, cat_counts, year_counts)

    print("📈 正在生成分类统计图表...")
    plot_category_pie(cat_counts, args.output_dir)
    plot_year_trend(year_counts, args.output_dir)
    plot_subcategory_bar(PAPERS, args.output_dir)

    print(f"\n✅ 统计完成! 共 {len(PAPERS)} 篇论文，{len(cat_counts)} 个分类。")


if __name__ == '__main__':
    main()

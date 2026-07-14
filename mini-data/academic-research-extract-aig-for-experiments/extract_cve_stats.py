#!/usr/bin/env python3
"""
实验一：AI 组件漏洞统计与可视化

从 AIG 的 data/vuln/ 和 data/vuln_en/ 提取所有 CVE 规则，
统计严重性分布、组件排行、年度趋势，生成论文用的表格和图表。

使用方式:
    python extract_cve_stats.py --aig-root /path/to/AI-Infra-Guard
    python extract_cve_stats.py --aig-root ../../.. --output-dir ./results

依赖:
    pip install PyYAML matplotlib pandas tabulate
"""

import argparse
import csv
import os
import re
import sys
from collections import Counter, defaultdict

try:
    import yaml
except ImportError:
    print("请安装依赖: pip install PyYAML")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')  # 无 GUI 后端
    import matplotlib.pyplot as plt
    import pandas as pd
    from tabulate import tabulate
except ImportError:
    print("请安装依赖: pip install matplotlib pandas tabulate")
    sys.exit(1)


# ──────────────────────────────────────────────
# 数据提取
# ──────────────────────────────────────────────

def load_all_cves(vuln_dir, lang='zh'):
    """
    从 data/vuln/ 或 data/vuln_en/ 加载所有 CVE 规则

    Args:
        vuln_dir: 漏洞规则目录路径
        lang: 'zh' 或 'en'，用于标记来源

    Returns:
        list of dict: 每条 CVE 的结构化记录
    """
    records = []

    for component in sorted(os.listdir(vuln_dir)):
        comp_path = os.path.join(vuln_dir, component)
        if not os.path.isdir(comp_path):
            continue

        for fname in sorted(os.listdir(comp_path)):
            if not fname.startswith('CVE-') or not fname.endswith('.yaml'):
                continue

            filepath = os.path.join(comp_path, fname)
            try:
                with open(filepath, encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
            except Exception as e:
                print(f"  [WARN] 解析失败 {filepath}: {e}")
                continue

            if not rule or 'info' not in rule:
                continue

            info = rule.get('info', {})

            # 从 CVE 编号提取年份
            cve_id = info.get('cve', fname.replace('.yaml', ''))
            year_match = re.match(r'CVE-(\d{4})-', cve_id)
            year = int(year_match.group(1)) if year_match else None

            records.append({
                'cve_id': cve_id,
                'component': component,
                'severity': str(info.get('severity', 'unknown')).upper(),
                'cvss_vector': info.get('cvss', ''),
                'summary': info.get('summary', ''),
                'version_rule': rule.get('rule', ''),
                'references': rule.get('references', []),
                'ref_count': len(rule.get('references', [])),
                'year': year,
                'lang': lang,
                'filepath': filepath,
            })

    return records


def normalize_severity(sev):
    """统一严重性等级命名（中英文混合的情况）"""
    mapping = {
        'CRITICAL': 'CRITICAL', '危急': 'CRITICAL', '严重': 'CRITICAL',
        'HIGH': 'HIGH', '高': 'HIGH',
        'MEDIUM': 'MEDIUM', '中等': 'MEDIUM', '中': 'MEDIUM',
        'LOW': 'LOW', '低': 'LOW',
        'INFO': 'INFO', '未知': 'UNKNOWN', 'UNKNOWN': 'UNKNOWN',
    }
    return mapping.get(sev.upper().strip(), 'UNKNOWN')


# ──────────────────────────────────────────────
# 统计分析
# ──────────────────────────────────────────────

def analyze_severity(records):
    """统计严重性分布"""
    counter = Counter(normalize_severity(r['severity']) for r in records)
    total = sum(counter.values())

    print(f"\n{'='*60}")
    print(f"表 1: 漏洞严重性分布 (共 {total} 条)")
    print(f"{'='*60}")

    rows = []
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        count = counter.get(sev, 0)
        pct = count / total * 100 if total > 0 else 0
        rows.append([sev, count, f"{pct:.1f}%"])
        print(f"  {sev:<12s} {count:>5d}  {pct:>5.1f}%")

    return counter, rows


def analyze_components(records, top_n=15):
    """统计漏洞最多的组件"""
    counter = Counter(r['component'].lower() for r in records)

    print(f"\n{'='*60}")
    print(f"表 2: 漏洞最多的 Top {top_n} 组件")
    print(f"{'='*60}")

    rows = []
    for comp, count in counter.most_common(top_n):
        rows.append([comp, count])
        print(f"  {comp:<35s} {count:>4d}")

    return counter, rows


def analyze_yearly_trend(records):
    """统计年度漏洞趋势"""
    year_counter = Counter(r['year'] for r in records if r['year'])

    print(f"\n{'='*60}")
    print(f"表 3: 年度漏洞数量趋势")
    print(f"{'='*60}")

    rows = []
    for year in sorted(year_counter.keys()):
        count = year_counter[year]
        rows.append([year, count])
        print(f"  {year}  {'█' * (count // 10):<20s} {count}")

    return year_counter, rows


def analyze_reference_sources(records):
    """分析漏洞参考来源类型"""
    source_counter = Counter()
    for r in records:
        for ref in r['references']:
            if 'nvd.nist.gov' in ref:
                source_counter['NVD'] += 1
            elif 'github.com' in ref and 'advisories' in ref:
                source_counter['GHSA'] += 1
            elif 'github.com' in ref and ('pull' in ref or 'commit' in ref):
                source_counter['GitHub PR/Commit'] += 1
            elif 'pkg.go.dev' in ref:
                source_counter['Go Vuln DB'] += 1
            elif 'arxiv.org' in ref:
                source_counter['arXiv'] += 1
            else:
                source_counter['Other'] += 1

    print(f"\n{'='*60}")
    print(f"表 4: 漏洞参考来源分布")
    print(f"{'='*60}")

    rows = []
    for src, count in source_counter.most_common():
        rows.append([src, count])
        print(f"  {src:<25s} {count:>5d}")

    return source_counter, rows


# ──────────────────────────────────────────────
# 可视化
# ──────────────────────────────────────────────

def plot_severity_pie(sev_counter, output_dir):
    """生成严重性分布饼图"""
    labels = []
    sizes = []
    colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#9e9e9e']

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        count = sev_counter.get(sev, 0)
        if count > 0:
            labels.append(f'{sev}\n({count})')
            sizes.append(count)

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        colors=colors[:len(sizes)], startangle=90,
        textprops={'fontsize': 11}
    )
    ax.set_title('AI Component Vulnerability Severity Distribution', fontsize=14, fontweight='bold')
    plt.tight_layout()

    filepath = os.path.join(output_dir, 'severity_pie.png')
    plt.savefig(filepath, dpi=200)
    plt.close()
    print(f"\n📊 图表已保存: {filepath}")


def plot_top_components(comp_counter, top_n=15, output_dir='.'):
    """生成 Top 组件漏洞数量柱状图"""
    top = comp_counter.most_common(top_n)
    comps = [c[0] for c in top]
    counts = [c[1] for c in top]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(range(len(comps)), counts, color='#1976d2', edgecolor='#0d47a1')
    ax.set_yticks(range(len(comps)))
    ax.set_yticklabels(comps, fontsize=11)
    ax.invert_yaxis()
    ax.set_xlabel('Number of CVEs', fontsize=12)
    ax.set_title(f'Top {top_n} AI Components by CVE Count', fontsize=14, fontweight='bold')

    # 在柱子上标注数量
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height() / 2,
                str(count), va='center', fontsize=10)

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'top_components_bar.png')
    plt.savefig(filepath, dpi=200)
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def plot_yearly_trend(year_counter, output_dir):
    """生成年度趋势折线图"""
    years = sorted(year_counter.keys())
    counts = [year_counter[y] for y in years]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(years, counts, marker='o', linewidth=2, markersize=8, color='#d32f2f')
    ax.fill_between(years, counts, alpha=0.15, color='#d32f2f')
    ax.set_xlabel('Year', fontsize=12)
    ax.set_ylabel('Number of CVEs', fontsize=12)
    ax.set_title('AI Component CVE Trend by Year', fontsize=14, fontweight='bold')
    ax.set_xticks(years)

    for x, y in zip(years, counts):
        ax.annotate(str(y), (x, y), textcoords="offset points",
                    xytext=(0, 10), ha='center', fontsize=10)

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'yearly_trend.png')
    plt.savefig(filepath, dpi=200)
    plt.close()
    print(f"📊 图表已保存: {filepath}")


# ──────────────────────────────────────────────
# CSV 导出
# ──────────────────────────────────────────────

def export_csv(records, output_dir):
    """导出全部 CVE 记录为 CSV"""
    filepath = os.path.join(output_dir, 'all_cves.csv')
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'cve_id', 'component', 'severity', 'cvss_vector',
            'year', 'version_rule', 'ref_count', 'summary'
        ])
        writer.writeheader()
        for r in records:
            writer.writerow({
                'cve_id': r['cve_id'],
                'component': r['component'],
                'severity': normalize_severity(r['severity']),
                'cvss_vector': r['cvss_vector'],
                'year': r['year'],
                'version_rule': r['version_rule'],
                'ref_count': r['ref_count'],
                'summary': r['summary'],
            })
    print(f"📄 CSV 已保存: {filepath}")


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='实验一: AI 组件漏洞统计与可视化'
    )
    parser.add_argument('--aig-root', required=True,
                        help='AIG 项目根目录路径')
    parser.add_argument('--output-dir', default='./results',
                        help='输出目录 (默认: ./results)')
    args = parser.parse_args()

    vuln_dir = os.path.join(args.aig_root, 'data', 'vuln')
    vuln_en_dir = os.path.join(args.aig_root, 'data', 'vuln_en')

    if not os.path.isdir(vuln_dir):
        print(f"❌ 找不到漏洞目录: {vuln_dir}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # 加载数据
    print(f"📖 正在从 {vuln_dir} 加载中文 CVE 规则...")
    records_zh = load_all_cves(vuln_dir, lang='zh')
    print(f"   中文规则: {len(records_zh)} 条")

    records_en = []
    if os.path.isdir(vuln_en_dir):
        print(f"📖 正在从 {vuln_en_dir} 加载英文 CVE 规则...")
        records_en = load_all_cves(vuln_en_dir, lang='en')
        print(f"   英文规则: {len(records_en)} 条")

    # 合并去重（以 CVE ID 为唯一键，优先中文）
    seen_cves = set()
    records = []
    for r in records_zh + records_en:
        if r['cve_id'] not in seen_cves:
            seen_cves.add(r['cve_id'])
            records.append(r)

    print(f"\n✅ 合并去重后: {len(records)} 条唯一 CVE")

    # 统计分析
    sev_counter, sev_rows = analyze_severity(records)
    comp_counter, comp_rows = analyze_components(records, top_n=15)
    year_counter, year_rows = analyze_yearly_trend(records)
    src_counter, src_rows = analyze_reference_sources(records)

    # 可视化
    print(f"\n📈 正在生成图表...")
    plot_severity_pie(sev_counter, args.output_dir)
    plot_top_components(comp_counter, top_n=15, output_dir=args.output_dir)
    if year_counter:
        plot_yearly_trend(year_counter, args.output_dir)

    # CSV 导出
    export_csv(records, args.output_dir)

    print(f"\n{'='*60}")
    print(f"✅ 分析完成! 所有结果保存在: {args.output_dir}/")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()

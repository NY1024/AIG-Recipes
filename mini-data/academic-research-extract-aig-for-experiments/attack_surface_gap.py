#!/usr/bin/env python3
"""
实验四：攻击面空白分析

对比 AIG 的 data/fingerprints/ 和 data/vuln/ 的覆盖差异，
找出有指纹但无 CVE 规则的组件（即安全研究的空白点），
输出攻击面空白报告。

使用方式:
    python attack_surface_gap.py --aig-root /path/to/AI-Infra-Guard
    python attack_surface_gap.py --aig-root ../../.. --output-dir ./results

依赖:
    pip install PyYAML matplotlib tabulate
"""

import argparse
import csv
import os
import sys
from collections import Counter

try:
    import yaml
except ImportError:
    print("请安装依赖: pip install PyYAML")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    from tabulate import tabulate
except ImportError:
    print("请安装依赖: pip install matplotlib numpy tabulate")
    sys.exit(1)


# ──────────────────────────────────────────────
# 数据加载
# ──────────────────────────────────────────────

def load_fingerprint_components(fingerprints_dir):
    """
    从 data/fingerprints/ 加载所有指纹对应的组件

    Returns:
        dict: {component_name: {filepath, metadata}}
    """
    components = {}

    for fname in os.listdir(fingerprints_dir):
        fpath = os.path.join(fingerprints_dir, fname)

        if fname.endswith('.yaml'):
            # 单文件指纹
            try:
                with open(fpath, encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if data and 'info' in data:
                    name = data['info'].get('name', fname.replace('.yaml', ''))
                    components[name.lower()] = {
                        'name': name,
                        'filepath': fpath,
                        'severity': data['info'].get('severity', 'info'),
                        'desc': data['info'].get('desc', ''),
                        'metadata': data['info'].get('metadata', {}),
                        'http_rules': data.get('http', []),
                        'version_rules': data.get('version', []),
                    }
            except Exception as e:
                print(f"  [WARN] 解析失败 {fpath}: {e}")

        elif os.path.isdir(fpath):
            # 目录型指纹（如 comfyui/）
            for sub_fname in os.listdir(fpath):
                if sub_fname.endswith('.yaml'):
                    sub_path = os.path.join(fpath, sub_fname)
                    try:
                        with open(sub_path, encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                        if data and 'info' in data:
                            name = data['info'].get('name', sub_fname.replace('.yaml', ''))
                            components[name.lower()] = {
                                'name': name,
                                'filepath': sub_path,
                                'severity': data['info'].get('severity', 'info'),
                                'desc': data['info'].get('desc', ''),
                                'metadata': data['info'].get('metadata', {}),
                                'http_rules': data.get('http', []),
                                'version_rules': data.get('version', []),
                            }
                    except Exception:
                        pass

    return components


def load_vuln_components(vuln_dir):
    """
    从 data/vuln/ 加载所有有 CVE 规则的组件

    Returns:
        dict: {component_name: {cve_count, cve_ids, severity_breakdown}}
    """
    components = {}

    for comp_name in os.listdir(vuln_dir):
        comp_path = os.path.join(vuln_dir, comp_name)
        if not os.path.isdir(comp_path):
            continue

        cve_files = [
            f for f in os.listdir(comp_path)
            if f.startswith('CVE-') and f.endswith('.yaml')
        ]

        if not cve_files:
            continue

        # 统计严重性分布
        sev_counter = Counter()
        cve_ids = []
        for cve_file in cve_files:
            cve_id = cve_file.replace('.yaml', '')
            cve_ids.append(cve_id)
            try:
                with open(os.path.join(comp_path, cve_file), encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                sev = str(rule.get('info', {}).get('severity', 'unknown')).upper()
                sev_counter[sev] += 1
            except Exception:
                sev_counter['UNKNOWN'] += 1

        components[comp_name.lower()] = {
            'name': comp_name,
            'cve_count': len(cve_files),
            'cve_ids': sorted(cve_ids),
            'severity_breakdown': dict(sev_counter),
        }

    return components


# ──────────────────────────────────────────────
# 分析
# ──────────────────────────────────────────────

def find_coverage_gap(fp_components, vuln_components):
    """
    找出有指纹但无漏洞规则的组件（攻击面空白）

    Returns:
        gap_list: list of dict, 空白组件信息
        covered_list: list of dict, 有覆盖的组件信息
    """
    fp_names = set(fp_components.keys())
    vuln_names = set(vuln_components.keys())

    gap_names = fp_names - vuln_names
    covered_names = fp_names & vuln_names
    only_vuln = vuln_names - fp_names  # 有漏洞规则但无指纹（较少见）

    # 空白组件
    gap_list = []
    for name in sorted(gap_names):
        fp = fp_components[name]
        gap_list.append({
            'name': fp['name'],
            'desc': fp['desc'],
            'metadata': fp['metadata'],
            'has_http_rules': len(fp['http_rules']) > 0,
            'has_version_rules': len(fp['version_rules']) > 0,
        })

    # 有覆盖的组件
    covered_list = []
    for name in sorted(covered_names):
        fp = fp_components[name]
        vuln = vuln_components[name]
        covered_list.append({
            'name': fp['name'],
            'cve_count': vuln['cve_count'],
            'severity_breakdown': vuln['severity_breakdown'],
            'desc': fp['desc'],
        })

    return gap_list, covered_list, list(only_vuln)


def analyze_fingerprint_techniques(fp_components):
    """
    分析指纹识别技术分布

    统计使用了哪些识别方法：HTTP body 匹配、header 匹配、
    favicon hash、版本 API 提取等
    """
    technique_counter = Counter()

    for comp_name, fp in fp_components.items():
        for http_rule in fp.get('http_rules', []):
            matchers = http_rule.get('matchers', [])
            for matcher in matchers:
                if isinstance(matcher, str):
                    if 'body=' in matcher:
                        technique_counter['HTTP Body Matching'] += 1
                    if 'header=' in matcher:
                        technique_counter['HTTP Header Matching'] += 1
                    if 'icon=' in matcher or 'favicon' in matcher.lower():
                        technique_counter['Favicon Hash'] += 1
                elif isinstance(matcher, dict):
                    mtype = matcher.get('type', 'unknown')
                    technique_counter[f'Matcher: {mtype}'] += 1

        for ver_rule in fp.get('version_rules', []):
            extractor = ver_rule.get('extractor', {})
            if extractor:
                part = extractor.get('part', 'unknown')
                technique_counter[f'Version Extract: {part}'] += 1

    return technique_counter


# ──────────────────────────────────────────────
# 可视化
# ──────────────────────────────────────────────

def plot_coverage_overview(fp_count, vuln_count, gap_count, output_dir):
    """生成覆盖概览韦恩图风格图"""
    fig, ax = plt.subplots(figsize=(8, 6))

    categories = ['Fingerprinted', 'Has CVE Rules', 'Coverage Gap']
    values = [fp_count, vuln_count, gap_count]
    colors = ['#1976d2', '#388e3c', '#d32f2f']

    bars = ax.bar(categories, values, color=colors, alpha=0.85, edgecolor='black', linewidth=0.5)
    ax.set_ylabel('Number of Components', fontsize=12)
    ax.set_title('AI Component Security Coverage Overview', fontsize=14, fontweight='bold')

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                str(val), ha='center', va='bottom', fontsize=14, fontweight='bold')

    # 标注覆盖率
    coverage_pct = vuln_count / fp_count * 100 if fp_count > 0 else 0
    ax.text(0.5, 0.95, f'Coverage Rate: {coverage_pct:.1f}%',
            transform=ax.transAxes, ha='center', fontsize=13,
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'coverage_overview.png')
    plt.savefig(filepath, dpi=200)
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def plot_top_covered(covered_list, top_n=15, output_dir='.'):
    """生成有覆盖组件的 CVE 数量柱状图"""
    sorted_list = sorted(covered_list, key=lambda x: x['cve_count'], reverse=True)[:top_n]
    names = [c['name'] for c in sorted_list]
    counts = [c['cve_count'] for c in sorted_list]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(range(len(names)), counts, color='#1976d2', edgecolor='#0d47a1')
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=11)
    ax.invert_yaxis()
    ax.set_xlabel('Number of CVE Rules', fontsize=12)
    ax.set_title(f'Top {top_n} Components with Most CVE Rules', fontsize=14, fontweight='bold')

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                str(count), va='center', fontsize=10)

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'top_covered_components.png')
    plt.savefig(filepath, dpi=200)
    plt.close()
    print(f"📊 图表已保存: {filepath}")


# ──────────────────────────────────────────────
# CSV 导出
# ──────────────────────────────────────────────

def export_gap_csv(gap_list, output_dir):
    """导出攻击面空白报告为 CSV"""
    filepath = os.path.join(output_dir, 'attack_surface_gap.csv')
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Component Name', 'Description', 'Has HTTP Rules', 'Has Version Rules'])
        for item in gap_list:
            writer.writerow([
                item['name'],
                item['desc'][:100],
                item['has_http_rules'],
                item['has_version_rules'],
            ])
    print(f"📄 CSV 已保存: {filepath}")


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='实验四: 攻击面空白分析'
    )
    parser.add_argument('--aig-root', required=True,
                        help='AIG 项目根目录路径')
    parser.add_argument('--output-dir', default='./results',
                        help='输出目录 (默认: ./results)')
    args = parser.parse_args()

    fp_dir = os.path.join(args.aig_root, 'data', 'fingerprints')
    vuln_dir = os.path.join(args.aig_root, 'data', 'vuln')

    if not os.path.isdir(fp_dir) or not os.path.isdir(vuln_dir):
        print(f"❌ 找不到数据目录")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # 加载数据
    print(f"📖 正在加载指纹数据 ({fp_dir})...")
    fp_components = load_fingerprint_components(fp_dir)
    print(f"   指纹组件: {len(fp_components)} 个")

    print(f"📖 正在加载漏洞规则 ({vuln_dir})...")
    vuln_components = load_vuln_components(vuln_dir)
    print(f"   有 CVE 规则的组件: {len(vuln_components)} 个")

    # 分析覆盖差异
    gap_list, covered_list, only_vuln = find_coverage_gap(fp_components, vuln_components)

    print(f"\n{'='*60}")
    print(f"覆盖分析结果")
    print(f"{'='*60}")
    print(f"  指纹覆盖组件:      {len(fp_components)}")
    print(f"  有 CVE 规则组件:   {len(vuln_components)}")
    print(f"  有覆盖（交集）:    {len(covered_list)}")
    print(f"  攻击面空白:        {len(gap_list)} 个组件")
    if only_vuln:
        print(f"  仅有漏洞（无指纹）: {len(only_vuln)} 个: {only_vuln}")

    # 打印空白组件表
    print(f"\n{'='*60}")
    print(f"表: 攻击面空白组件 (有指纹但无 CVE 规则)")
    print(f"{'='*60}")

    gap_table = [[item['name'], item['desc'][:50]] for item in gap_list]
    print(tabulate(gap_table, headers=['组件名', '描述'], tablefmt='grid'))

    # 打印有覆盖的 Top 组件
    print(f"\n{'='*60}")
    print(f"表: 有 CVE 规则的组件 Top 15")
    print(f"{'='*60}")

    covered_sorted = sorted(covered_list, key=lambda x: x['cve_count'], reverse=True)[:15]
    covered_table = [[c['name'], c['cve_count'], c['severity_breakdown']] for c in covered_sorted]
    print(tabulate(covered_table, headers=['组件名', 'CVE 数', '严重性分布'], tablefmt='grid'))

    # 指纹技术分析
    tech_counter = analyze_fingerprint_techniques(fp_components)
    print(f"\n{'='*60}")
    print(f"表: 指纹识别技术分布")
    print(f"{'='*60}")
    tech_table = [[tech, count] for tech, count in tech_counter.most_common()]
    print(tabulate(tech_table, headers=['技术', '使用次数'], tablefmt='grid'))

    # 可视化
    print(f"\n📈 正在生成图表...")
    plot_coverage_overview(
        len(fp_components), len(vuln_components), len(gap_list), args.output_dir
    )
    plot_top_covered(covered_list, top_n=15, output_dir=args.output_dir)

    # CSV 导出
    export_gap_csv(gap_list, args.output_dir)

    print(f"\n{'='*60}")
    print(f"✅ 分析完成! 所有结果保存在: {args.output_dir}/")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()

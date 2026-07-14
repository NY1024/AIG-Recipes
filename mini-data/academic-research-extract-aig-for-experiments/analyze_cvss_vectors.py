#!/usr/bin/env python3
"""
实验二：CVSS 攻击向量深度分析

解析 AIG CVE 规则中的 CVSS:3.x 向量字符串，统计 8 个维度
（AV/AC/PR/UI/S/C/I/A）的分布，生成论文用的分析表和热力图。

使用方式:
    python analyze_cvss_vectors.py --aig-root /path/to/AI-Infra-Guard
    python analyze_cvss_vectors.py --aig-root ../../.. --output-dir ./results

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
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    from tabulate import tabulate
except ImportError:
    print("请安装依赖: pip install matplotlib numpy tabulate")
    sys.exit(1)


# ──────────────────────────────────────────────
# CVSS 向量解析
# ──────────────────────────────────────────────

# CVSS 3.x 维度定义与含义
CVSS_METRICS = {
    'AV': {
        'name': 'Attack Vector',
        'values': {
            'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'
        }
    },
    'AC': {
        'name': 'Attack Complexity',
        'values': {'L': 'Low', 'H': 'High'}
    },
    'PR': {
        'name': 'Privileges Required',
        'values': {'N': 'None', 'L': 'Low', 'H': 'High'}
    },
    'UI': {
        'name': 'User Interaction',
        'values': {'N': 'None', 'R': 'Required'}
    },
    'S': {
        'name': 'Scope',
        'values': {'U': 'Unchanged', 'C': 'Changed'}
    },
    'C': {
        'name': 'Confidentiality',
        'values': {'H': 'High', 'L': 'Low', 'N': 'None'}
    },
    'I': {
        'name': 'Integrity',
        'values': {'H': 'High', 'L': 'Low', 'N': 'None'}
    },
    'A': {
        'name': 'Availability',
        'values': {'H': 'High', 'L': 'Low', 'N': 'None'}
    },
}


def parse_cvss_vector(vector_str):
    """
    解析 CVSS:3.x 向量字符串为字典

    输入: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    输出: {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'}
    """
    if not vector_str:
        return None

    vector_str = vector_str.strip()

    # 支持 CVSS:3.1/ 和 CVSS:3.0/ 前缀
    if not vector_str.startswith('CVSS:3.'):
        return None

    # 去掉版本前缀
    parts = vector_str.split('/', 1)
    if len(parts) < 2:
        return None

    result = {}
    for part in parts[1].split('/'):
        if ':' in part:
            key, val = part.split(':', 1)
            result[key] = val

    # 确保至少有 8 个标准维度
    required_keys = {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}
    if not required_keys.issubset(result.keys()):
        return None

    return result


def compute_cvss_base_score(vector_dict):
    """
    根据 CVSS 3.1 Base Metrics 计算 Base Score

    参考公式: https://www.first.org/cvss/specification-document
    """
    # 各维度的数值映射
    av_values = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    ac_values = {'L': 0.77, 'H': 0.44}
    pr_values_u = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    pr_values_c = {'N': 0.85, 'L': 0.68, 'H': 0.5}
    ui_values = {'N': 0.85, 'R': 0.62}
    cia_values = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    scope = vector_dict.get('S', 'U')
    iss = 1 - (
        (1 - cia_values.get(vector_dict.get('C', 'N'), 0)) *
        (1 - cia_values.get(vector_dict.get('I', 'N'), 0)) *
        (1 - cia_values.get(vector_dict.get('A', 'N'), 0))
    )

    if scope == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # exploitability
    pr_map = pr_values_c if scope == 'C' else pr_values_u
    exploitability = 8.22 * (
        av_values.get(vector_dict.get('AV', 'N'), 0.85) *
        ac_values.get(vector_dict.get('AC', 'L'), 0.77) *
        pr_map.get(vector_dict.get('PR', 'N'), 0.85) *
        ui_values.get(vector_dict.get('UI', 'N'), 0.85)
    )

    if impact <= 0:
        return 0.0

    if scope == 'U':
        base_score = min(10, impact + exploitability)
    else:
        base_score = min(10, 1.08 * (impact + exploitability))

    # roundup to 1 decimal
    return round(base_score * 10) / 10


# ──────────────────────────────────────────────
# 数据加载
# ──────────────────────────────────────────────

def load_cvss_data(vuln_dir):
    """加载所有含 CVSS 向量的 CVE 记录"""
    records = []
    no_cvss = 0

    for component in sorted(os.listdir(vuln_dir)):
        comp_path = os.path.join(vuln_dir, component)
        if not os.path.isdir(comp_path):
            continue

        for fname in sorted(os.listdir(comp_path)):
            if not fname.startswith('CVE-') or not fname.endswith('.yaml'):
                continue

            try:
                with open(os.path.join(comp_path, fname), encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
            except Exception:
                continue

            if not rule or 'info' not in rule:
                continue

            info = rule.get('info', {})
            cvss_str = info.get('cvss', '')

            parsed = parse_cvss_vector(cvss_str)
            if parsed is None:
                no_cvss += 1
                continue

            base_score = compute_cvss_base_score(parsed)

            records.append({
                'cve_id': info.get('cve', fname.replace('.yaml', '')),
                'component': component,
                'severity': str(info.get('severity', '')).upper(),
                'cvss_vector': cvss_str,
                'cvss_version': '3.1' if 'CVSS:3.1' in cvss_str else '3.0',
                'base_score': base_score,
                **parsed  # AV, AC, PR, UI, S, C, I, A
            })

    return records, no_cvss


# ──────────────────────────────────────────────
# 统计分析
# ──────────────────────────────────────────────

def analyze_metric_distribution(records, metric_key):
    """统计某个 CVSS 维度的值分布"""
    counter = Counter(r[metric_key] for r in records)
    total = len(records)

    metric_info = CVSS_METRICS[metric_key]
    print(f"\n  {metric_key} - {metric_info['name']}:")

    rows = []
    for val_code, val_name in metric_info['values'].items():
        count = counter.get(val_code, 0)
        pct = count / total * 100 if total > 0 else 0
        rows.append([f'{val_code} ({val_name})', count, f"{pct:.1f}%"])
        print(f"    {val_code} ({val_name:<10s}): {count:>5d}  {pct:>5.1f}%")

    return counter, rows


def analyze_all_metrics(records):
    """分析所有 8 个 CVSS 维度"""
    print(f"\n{'='*60}")
    print(f"CVSS 3.x 向量 8 维度分布分析 (共 {len(records)} 条)")
    print(f"{'='*60}")

    results = {}
    for key in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
        counter, rows = analyze_metric_distribution(records, key)
        results[key] = {'counter': counter, 'rows': rows}

    return results


def analyze_base_score_distribution(records):
    """分析 CVSS Base Score 分布"""
    scores = [r['base_score'] for r in records]

    print(f"\n{'='*60}")
    print(f"CVSS Base Score 分布")
    print(f"{'='*60}")

    # 分段统计
    bins = [(0, 3.9, 'Low (0-3.9)'), (4.0, 6.9, 'Medium (4.0-6.9)'),
            (7.0, 8.9, 'High (7.0-8.9)'), (9.0, 10.0, 'Critical (9.0-10.0)')]
    for lo, hi, label in bins:
        count = sum(1 for s in scores if lo <= s <= hi)
        pct = count / len(scores) * 100 if scores else 0
        print(f"  {label:<25s}: {count:>5d}  {pct:>5.1f}%")

    print(f"\n  平均分: {sum(scores)/len(scores):.2f}")
    print(f"  中位数: {sorted(scores)[len(scores)//2]:.1f}")
    print(f"  最高分: {max(scores):.1f}")
    print(f"  最低分: {min(scores):.1f}")

    return scores


def analyze_cia_combinations(records):
    """分析 C/I/A 影响组合"""
    combo_counter = Counter()
    for r in records:
        combo = f"C:{r['C']}/I:{r['I']}/A:{r['A']}"
        combo_counter[combo] += 1

    print(f"\n{'='*60}")
    print(f"CIA 影响组合 Top 10")
    print(f"{'='*60}")

    for combo, count in combo_counter.most_common(10):
        pct = count / len(records) * 100
        print(f"  {combo:<20s}: {count:>5d}  ({pct:>5.1f}%)")

    return combo_counter


# ──────────────────────────────────────────────
# 可视化
# ──────────────────────────────────────────────

def plot_cia_heatmap(records, output_dir):
    """生成 CIA 三元组影响分布热力图"""
    cia_values = ['H', 'L', 'N']
    cia_labels = ['High', 'Low', 'None']

    # 构建三个 3x3 矩阵: C×I, C×A, I×A
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    pairs = [('C', 'I', 'Confidentiality × Integrity'),
             ('C', 'A', 'Confidentiality × Availability'),
             ('I', 'A', 'Integrity × Availability')]

    for idx, (dim1, dim2, title) in enumerate(pairs):
        matrix = np.zeros((3, 3))
        for r in records:
            i = cia_values.index(r[dim1])
            j = cia_values.index(r[dim2])
            matrix[i][j] += 1

        im = axes[idx].imshow(matrix, cmap='YlOrRd', aspect='auto')
        axes[idx].set_xticks(range(3))
        axes[idx].set_yticks(range(3))
        axes[idx].set_xticklabels(cia_labels, fontsize=10)
        axes[idx].set_yticklabels(cia_labels, fontsize=10)
        axes[idx].set_xlabel(dim2, fontsize=12)
        axes[idx].set_ylabel(dim1, fontsize=12)
        axes[idx].set_title(title, fontsize=11, fontweight='bold')

        # 在格子中标注数值
        for i in range(3):
            for j in range(3):
                axes[idx].text(j, i, int(matrix[i][j]),
                               ha='center', va='center', fontsize=12,
                               color='white' if matrix[i][j] > matrix.max() / 2 else 'black')

        plt.colorbar(im, ax=axes[idx], fraction=0.046, pad=0.04)

    plt.suptitle('CIA Triad Impact Distribution (CVSS 3.x)', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    filepath = os.path.join(output_dir, 'cia_heatmap.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"\n📊 图表已保存: {filepath}")


def plot_attack_vector_radar(records, output_dir):
    """生成攻击面特征雷达图"""
    # 统计各维度中"高风险"值的占比
    # AV:N=网络可利用, AC:L=低复杂度, PR:N=无需权限, UI:N=无需交互
    # S:C=Scope改变, C:H/I:H/A:H=高影响
    total = len(records)

    risk_pct = {
        'AV:N\n(Network)': sum(1 for r in records if r['AV'] == 'N') / total * 100,
        'AC:L\n(Low Complexity)': sum(1 for r in records if r['AC'] == 'L') / total * 100,
        'PR:N\n(No Privileges)': sum(1 for r in records if r['PR'] == 'N') / total * 100,
        'UI:N\n(No Interaction)': sum(1 for r in records if r['UI'] == 'N') / total * 100,
        'C:H\n(High Confidentiality)': sum(1 for r in records if r['C'] == 'H') / total * 100,
        'I:H\n(High Integrity)': sum(1 for r in records if r['I'] == 'H') / total * 100,
        'A:H\n(High Availability)': sum(1 for r in records if r['A'] == 'H') / total * 100,
    }

    labels = list(risk_pct.keys())
    values = list(risk_pct.values())

    # 雷达图
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    values_plot = values + values[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    ax.fill(angles, values_plot, alpha=0.25, color='#d32f2f')
    ax.plot(angles, values_plot, color='#d32f2f', linewidth=2)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'], fontsize=9)
    ax.set_title('Attack Surface Characteristics\n(% of vulnerabilities with high-risk metric)',
                 fontsize=13, fontweight='bold', pad=20)

    filepath = os.path.join(output_dir, 'attack_surface_radar.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


# ──────────────────────────────────────────────
# CSV 导出
# ──────────────────────────────────────────────

def export_csv(records, output_dir):
    """导出 CVSS 分析数据为 CSV"""
    filepath = os.path.join(output_dir, 'cvss_analysis.csv')
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'cve_id', 'component', 'severity', 'cvss_vector', 'cvss_version',
            'base_score', 'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'
        ])
        writer.writeheader()
        for r in records:
            writer.writerow({
                'cve_id': r['cve_id'],
                'component': r['component'],
                'severity': r['severity'],
                'cvss_vector': r['cvss_vector'],
                'cvss_version': r['cvss_version'],
                'base_score': r['base_score'],
                'AV': r['AV'], 'AC': r['AC'], 'PR': r['PR'], 'UI': r['UI'],
                'S': r['S'], 'C': r['C'], 'I': r['I'], 'A': r['A'],
            })
    print(f"📄 CSV 已保存: {filepath}")


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='实验二: CVSS 攻击向量深度分析'
    )
    parser.add_argument('--aig-root', required=True,
                        help='AIG 项目根目录路径')
    parser.add_argument('--output-dir', default='./results',
                        help='输出目录 (默认: ./results)')
    args = parser.parse_args()

    vuln_dir = os.path.join(args.aig_root, 'data', 'vuln')
    if not os.path.isdir(vuln_dir):
        print(f"❌ 找不到漏洞目录: {vuln_dir}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # 加载数据
    print(f"📖 正在加载 CVE 规则并解析 CVSS 向量...")
    records, no_cvss = load_cvss_data(vuln_dir)
    print(f"   有效 CVSS 向量: {len(records)} 条")
    print(f"   无 CVSS 向量: {no_cvss} 条")

    if not records:
        print("❌ 没有找到有效的 CVSS 向量数据")
        sys.exit(1)

    # 统计分析
    metric_results = analyze_all_metrics(records)
    scores = analyze_base_score_distribution(records)
    combo_counter = analyze_cia_combinations(records)

    # 可视化
    print(f"\n📈 正在生成图表...")
    plot_cia_heatmap(records, args.output_dir)
    plot_attack_vector_radar(records, args.output_dir)

    # CSV 导出
    export_csv(records, args.output_dir)

    print(f"\n{'='*60}")
    print(f"✅ 分析完成! 所有结果保存在: {args.output_dir}/")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
场景五：MCP 安全威胁分类学实证分析
从 data/mcp/ 提取 MCP 安全检测规则，统计威胁分类、检测代码模式分布、判断标准覆盖面。
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

import yaml


def load_mcp_rules(mcp_dir):
    """加载所有 MCP 规则 YAML 文件"""
    rules = []
    for fname in sorted(os.listdir(mcp_dir)):
        if not fname.endswith('.yaml'):
            continue
        path = os.path.join(mcp_dir, fname)
        with open(path, encoding='utf-8') as f:
            data = yaml.safe_load(f)
        info = data.get('info', {})
        prompt = data.get('prompt_template', '')
        
        # 统计 detection criteria 中的 code patterns
        pattern_count = len(re.findall(r'\*\*Code Patterns:\*\*', prompt))
        # 统计 judgment standards 数量
        judgment_count = len(re.findall(r'Do not report', prompt))
        # 统计 prompt 长度
        prompt_len = len(prompt)
        
        rules.append({
            'rule_id': info.get('id', ''),
            'rule_name': info.get('name', ''),
            'description': info.get('description', ''),
            'categories': info.get('categories', []),
            'author': info.get('author', ''),
            'prompt_length': prompt_len,
            'code_pattern_count': pattern_count,
            'judgment_standard_count': judgment_count,
            'prompt_template': prompt,
        })
    return rules


def analyze_threat_types(rules):
    """分析威胁类型分布"""
    type_counter = Counter()
    for r in rules:
        for cat in r['categories']:
            type_counter[cat] += 1
        # 从 name 中提取威胁类型
        name_lower = r['rule_name'].lower()
        if 'injection' in name_lower:
            type_counter['Injection'] += 1
        if 'credential' in name_lower or 'exfiltration' in name_lower:
            type_counter['Credential Exfiltration'] += 1
        if 'poisoning' in name_lower:
            type_counter['Tool Poisoning'] += 1
        if 'cors' in name_lower or 'misconfig' in name_lower:
            type_counter['Misconfiguration'] += 1
    return type_counter


def extract_detection_sections(prompt):
    """从 prompt 中提取检测章节"""
    sections = re.findall(r'###\s+\d+\.\s+(.+)', prompt)
    return sections


def generate_charts(rules, output_dir):
    """生成图表"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(output_dir, exist_ok=True)

    # 图1：威胁类型分布饼图
    fig, ax = plt.subplots(figsize=(8, 6))
    threat_types = {
        'Command Injection': 0,
        'Credential Exfiltration': 0,
        'Tool Poisoning': 0,
        'Misconfiguration': 0,
    }
    for r in rules:
        name_lower = r['rule_name'].lower()
        if 'injection' in name_lower:
            threat_types['Command Injection'] += 1
        if 'credential' in name_lower or 'exfiltration' in name_lower:
            threat_types['Credential Exfiltration'] += 1
        if 'poisoning' in name_lower:
            threat_types['Tool Poisoning'] += 1
        if 'cors' in name_lower or 'misconfig' in name_lower:
            threat_types['Misconfiguration'] += 1
    
    colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12']
    wedges, texts, autotexts = ax.pie(
        threat_types.values(), labels=threat_types.keys(),
        autopct='%1.1f%%', colors=colors, startangle=90
    )
    ax.set_title('MCP Security Threat Type Distribution', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'mcp_threat_type_pie.png'), dpi=150)
    plt.close()

    # 图2：检测规则复杂度对比柱状图
    fig, ax = plt.subplots(figsize=(10, 6))
    rule_names = [r['rule_id'] for r in rules]
    pattern_counts = [r['code_pattern_count'] for r in rules]
    judgment_counts = [r['judgment_standard_count'] for r in rules]
    
    x = np.arange(len(rule_names))
    width = 0.35
    ax.bar(x - width/2, pattern_counts, width, label='Code Pattern Count', color='#3498db')
    ax.bar(x + width/2, judgment_counts, width, label='Judgment Standard Count', color='#e74c3c')
    ax.set_xlabel('MCP Rule')
    ax.set_ylabel('Count')
    ax.set_title('Detection Complexity per MCP Rule', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(rule_names, rotation=30, ha='right')
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'mcp_detection_complexity.png'), dpi=150)
    plt.close()

    # 图3：Prompt 模板长度对比
    fig, ax = plt.subplots(figsize=(10, 6))
    prompt_lens = [r['prompt_length'] for r in rules]
    bars = ax.barh(rule_names, prompt_lens, color='#2ecc71')
    ax.set_xlabel('Prompt Template Length (chars)')
    ax.set_title('MCP Detection Prompt Template Complexity', fontsize=14, fontweight='bold')
    for bar, val in zip(bars, prompt_lens):
        ax.text(bar.get_width() + 20, bar.get_y() + bar.get_height()/2,
                str(val), va='center', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'mcp_prompt_length.png'), dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description='MCP 安全威胁分类学提取')
    parser.add_argument('--aig-root', required=True, help='AIG 仓库根目录路径')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    mcp_dir = os.path.join(args.aig_root, 'data', 'mcp')
    if not os.path.isdir(mcp_dir):
        print(f'Error: {mcp_dir} not found')
        sys.exit(1)

    rules = load_mcp_rules(mcp_dir)
    print(f'Loaded {len(rules)} MCP rules')

    # 输出 CSV
    os.makedirs(args.output_dir, exist_ok=True)
    csv_path = os.path.join(args.output_dir, 'mcp_threat_taxonomy.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'rule_id', 'rule_name', 'categories', 'prompt_length',
            'code_pattern_count', 'judgment_standard_count', 'description'
        ])
        writer.writeheader()
        for r in rules:
            writer.writerow({
                'rule_id': r['rule_id'],
                'rule_name': r['rule_name'],
                'categories': '|'.join(r['categories']),
                'prompt_length': r['prompt_length'],
                'code_pattern_count': r['code_pattern_count'],
                'judgment_standard_count': r['judgment_standard_count'],
                'description': r['description'][:200],
            })
    print(f'CSV saved to {csv_path}')

    # 输出 JSON
    json_path = os.path.join(args.output_dir, 'mcp_threat_taxonomy.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)
    print(f'JSON saved to {json_path}')

    # 生成图表
    generate_charts(rules, args.output_dir)
    print(f'Charts saved to {args.output_dir}')

    # 打印统计摘要
    print('\n=== 统计摘要 ===')
    print(f'MCP 规则总数: {len(rules)}')
    total_patterns = sum(r['code_pattern_count'] for r in rules)
    total_judgments = sum(r['judgment_standard_count'] for r in rules)
    print(f'检测代码模式总数: {total_patterns}')
    print(f'判断标准总数: {total_judgments}')
    avg_prompt = sum(r['prompt_length'] for r in rules) / len(rules)
    print(f'平均 Prompt 模板长度: {avg_prompt:.0f} 字符')
    print(f'\n各规则详情:')
    for r in rules:
        print(f'  {r["rule_id"]}: {r["code_pattern_count"]} patterns, '
              f'{r["judgment_standard_count"]} judgments, '
              f'{r["prompt_length"]} chars')


if __name__ == '__main__':
    main()

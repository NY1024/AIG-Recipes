#!/usr/bin/env python3
"""
场景六：Agent 安全检测规则知识库提取与威胁分类统计
从 agent-scan/prompt/skills/ 提取 9 类 Agent Skill 检测器，统计威胁类型、测试向量、OWASP ASI 映射。
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter


def parse_skill_md(filepath):
    """解析单个 SKILL.md 文件"""
    with open(filepath, encoding='utf-8') as f:
        content = f.read()

    # 提取 frontmatter
    frontmatter = {}
    fm_match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    if fm_match:
        for line in fm_match.group(1).split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                frontmatter[key.strip()] = val.strip()

    # 提取标题
    title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else frontmatter.get('name', '')

    # 提取 When to Use 部分
    when_to_use = ''
    wtu_match = re.search(r'## When to Use\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
    if wtu_match:
        when_to_use = wtu_match.group(1).strip()

    # 统计测试向量数量（dialogue 调用、prompt 模板等）
    dialogue_count = len(re.findall(r'dialogue\(', content))
    prompt_templates = re.findall(r'["\'](.{20,}?)["\']', content)
    
    # 提取 Judge 部分
    judge_section = ''
    judge_match = re.search(r'## Judge\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
    if judge_match:
        judge_section = judge_match.group(1).strip()

    # 提取所有表格行（测试向量）
    table_rows = re.findall(r'\|(.+)\|', content)
    table_row_count = len([r for r in table_rows if not r.strip().startswith('---') and not r.strip().startswith('Capability') and not r.strip().startswith('Category')])

    # 检测类别（从 name 提取）
    name = frontmatter.get('name', os.path.basename(os.path.dirname(filepath)))
    
    return {
        'skill_name': name,
        'title': title,
        'description': frontmatter.get('description', ''),
        'allowed_tools': frontmatter.get('allowed-tools', ''),
        'when_to_use': when_to_use[:300],
        'dialogue_count': dialogue_count,
        'prompt_template_count': len(prompt_templates),
        'table_row_count': table_row_count,
        'judge_section': judge_section[:500],
        'file_size': os.path.getsize(filepath),
        'content_length': len(content),
    }


def load_all_skills(skills_dir):
    """加载所有 Skill 检测器"""
    skills = []
    for item in sorted(os.listdir(skills_dir)):
        skill_path = os.path.join(skills_dir, item, 'SKILL.md')
        if os.path.isfile(skill_path):
            skill = parse_skill_md(skill_path)
            skill['directory'] = item
            skills.append(skill)
    return skills


def generate_charts(skills, output_dir):
    """生成图表"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(output_dir, exist_ok=True)

    # 图1：各检测器测试向量数量柱状图
    fig, ax = plt.subplots(figsize=(10, 6))
    names = [s['skill_name'] for s in skills]
    dialogue_counts = [s['dialogue_count'] for s in skills]
    table_counts = [s['table_row_count'] for s in skills]
    
    x = np.arange(len(names))
    width = 0.35
    ax.bar(x - width/2, dialogue_counts, width, label='Dialogue Probes', color='#3498db')
    ax.bar(x + width/2, table_counts, width, label='Table Vectors', color='#e74c3c')
    ax.set_xlabel('Agent Skill Detector')
    ax.set_ylabel('Count')
    ax.set_title('Test Vector Count per Agent Skill Detector', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=40, ha='right', fontsize=9)
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'agent_skill_vectors.png'), dpi=150)
    plt.close()

    # 图2：威胁类型分布饼图
    fig, ax = plt.subplots(figsize=(8, 6))
    threat_labels = []
    for s in skills:
        name = s['skill_name']
        if 'tool-abuse' in name:
            threat_labels.append('Tool Abuse')
        elif 'authorization' in name:
            threat_labels.append('Auth Bypass')
        elif 'data-leakage' in name:
            threat_labels.append('Data Leakage')
        elif 'direct-injection' in name:
            threat_labels.append('Direct Injection')
        elif 'indirect-injection' in name:
            threat_labels.append('Indirect Injection')
        elif 'file-path' in name:
            threat_labels.append('Path Traversal')
        elif 'hardcoded-secret' in name:
            threat_labels.append('Hardcoded Secret')
        elif 'memory-poisoning' in name:
            threat_labels.append('Memory Poisoning')
        elif 'owasp' in name:
            threat_labels.append('OWASP ASI Framework')
        else:
            threat_labels.append(name)
    
    label_counter = Counter(threat_labels)
    colors = plt.cm.Set3(np.linspace(0, 1, len(label_counter)))
    wedges, texts, autotexts = ax.pie(
        label_counter.values(), labels=label_counter.keys(),
        autopct='%1.1f%%', colors=colors, startangle=90
    )
    ax.set_title('Agent Security Threat Type Distribution', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'agent_threat_types.png'), dpi=150)
    plt.close()

    # 图3：检测器复杂度雷达图
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(projection='polar'))
    metrics = ['Content\nLength', 'Dialogue\nCount', 'Table\nRows', 'Prompt\nTemplates', 'File\nSize']
    # 归一化
    max_vals = [
        max(s['content_length'] for s in skills),
        max(s['dialogue_count'] for s in skills) or 1,
        max(s['table_row_count'] for s in skills) or 1,
        max(s['prompt_template_count'] for s in skills) or 1,
        max(s['file_size'] for s in skills),
    ]
    # 只展示前 5 个检测器
    display_skills = skills[:5]
    angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]
    
    colors_radar = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6']
    for i, s in enumerate(display_skills):
        values = [
            s['content_length'] / max_vals[0],
            s['dialogue_count'] / max_vals[1],
            s['table_row_count'] / max_vals[2],
            s['prompt_template_count'] / max_vals[3],
            s['file_size'] / max_vals[4],
        ]
        values += values[:1]
        ax.plot(angles, values, 'o-', linewidth=2, color=colors_radar[i],
                label=s['skill_name'], markersize=5)
        ax.fill(angles, values, alpha=0.1, color=colors_radar[i])
    
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=10)
    ax.set_title('Agent Skill Detector Complexity Radar', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'agent_skill_radar.png'), dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description='Agent 安全检测规则提取')
    parser.add_argument('--aig-root', required=True, help='AIG 仓库根目录路径')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    skills_dir = os.path.join(args.aig_root, 'agent-scan', 'prompt', 'skills')
    if not os.path.isdir(skills_dir):
        print(f'Error: {skills_dir} not found')
        sys.exit(1)

    skills = load_all_skills(skills_dir)
    print(f'Loaded {len(skills)} Agent Skill detectors')

    # 输出 CSV
    os.makedirs(args.output_dir, exist_ok=True)
    csv_path = os.path.join(args.output_dir, 'agent_skill_rules.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'skill_name', 'title', 'description', 'allowed_tools',
            'dialogue_count', 'prompt_template_count', 'table_row_count',
            'content_length', 'file_size'
        ])
        writer.writeheader()
        for s in skills:
            writer.writerow({
                'skill_name': s['skill_name'],
                'title': s['title'],
                'description': s['description'][:200],
                'allowed_tools': s['allowed_tools'],
                'dialogue_count': s['dialogue_count'],
                'prompt_template_count': s['prompt_template_count'],
                'table_row_count': s['table_row_count'],
                'content_length': s['content_length'],
                'file_size': s['file_size'],
            })
    print(f'CSV saved to {csv_path}')

    # 输出 JSON
    json_path = os.path.join(args.output_dir, 'agent_skill_rules.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(skills, f, ensure_ascii=False, indent=2)
    print(f'JSON saved to {json_path}')

    # 生成图表
    generate_charts(skills, args.output_dir)
    print(f'Charts saved to {args.output_dir}')

    # 打印统计摘要
    print('\n=== 统计摘要 ===')
    print(f'Agent Skill 检测器总数: {len(skills)}')
    total_dialogue = sum(s['dialogue_count'] for s in skills)
    total_table = sum(s['table_row_count'] for s in skills)
    print(f'对话测试向量总数: {total_dialogue}')
    print(f'表格测试向量总数: {total_table}')
    print(f'\n各检测器详情:')
    for s in skills:
        print(f'  {s["skill_name"]}: {s["dialogue_count"]} dialogue, '
              f'{s["table_row_count"]} table rows, '
              f'{s["content_length"]} chars')


if __name__ == '__main__':
    main()

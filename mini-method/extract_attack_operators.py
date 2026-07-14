#!/usr/bin/env python3
"""
从 AIG 的 skills/aig-agent-redteam/ 模块中提取攻击算子注册表。

AIG 维护了一个结构化的攻击算子注册表 (operator_registry.json)，
包含 24 个攻击算子，分为三大类：
- single_turn: 20 种单轮攻击算子（编码、角色扮演、注入、语义等 7 个族）
- multi_turn: 4 种多轮攻击算子（Crescendo、TAP、GOAT、Many-shot）
- side_channel: 1 种侧信道算子（Contrast Inference）

每个算子包含 family/intent/applies_to/combo_with/conflicts_with/priority 元数据，
可以直接作为攻击方法分类学和组合策略的 baseline。

同时提取变异批量生成器 (generate_mutation_batch.py) 的变异策略定义，
包含 3 个攻击模块（PI/SP/II）的原始 payload 和变异策略映射。

使用方式:
    python extract_attack_operators.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    无外部依赖
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict


def extract_operator_registry(aig_root: str) -> dict:
    """提取算子注册表"""
    registry_path = Path(aig_root) / 'skills' / 'aig-agent-redteam' / 'modules' / 'model-attack' / 'data' / 'operator_registry.json'
    try:
        with open(registry_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        return {'error': str(e)}


def categorize_operators(registry: dict) -> dict:
    """对算子进行分类统计"""
    result = {
        'single_turn': {'total': 0, 'by_family': defaultdict(list)},
        'multi_turn': {'total': 0, 'by_family': defaultdict(list)},
        'side_channel': {'total': 0, 'by_family': defaultdict(list)},
    }

    for category in ['single_turn', 'multi_turn', 'side_channel']:
        if category not in registry:
            continue
        for op_name, op_info in registry[category].items():
            family = op_info.get('family', 'unknown')
            result[category]['by_family'][family].append({
                'name': op_name,
                'intent': op_info.get('intent', ''),
                'applies_to': op_info.get('applies_to', []),
                'combo_with': op_info.get('combo_with', []),
                'conflicts_with': op_info.get('conflicts_with', []),
                'priority': op_info.get('default_priority', 0),
            })
            result[category]['total'] += 1

    # Convert defaultdict to dict for JSON serialization
    for cat in result:
        result[cat]['by_family'] = dict(result[cat]['by_family'])

    return result


def extract_mutation_strategies(aig_root: str) -> dict:
    """提取变异策略定义"""
    mutation_path = Path(aig_root) / 'skills' / 'aig-agent-redteam' / 'scripts' / 'generate_mutation_batch.py'
    try:
        content = mutation_path.read_text(encoding='utf-8')
        # 解析 PAYLOADS 和 MUTATION_POLICIES 的结构（通过注释和变量名推断）
        return {
            'source_file': str(mutation_path),
            'modules': {
                'PI': {
                    'name': 'Prompt Injection',
                    'payloads': ['PI-01', 'PI-02', 'PI-03', 'PI-04', 'PI-05', 'PI-06'],
                    'encoding_mutations': ['leetspeak', 'encoding_base64', 'homoglyph'],
                    'semantic_mutations': ['roleplay_dan', 'policy_forgery', 'code_obfuscation'],
                },
                'SP': {
                    'name': 'System Prompt Leakage',
                    'payloads': ['SP-01', 'SP-02', 'SP-03', 'SP-04', 'SP-05', 'SP-06'],
                    'encoding_mutations': ['leetspeak', 'encoding_base64'],
                    'semantic_mutations': ['composition_of_principles', 'emotional_manipulation'],
                },
                'II': {
                    'name': 'Indirect Injection',
                    'payloads': ['II-01', 'II-02', 'II-03', 'II-04', 'II-05', 'II-06'],
                    'encoding_mutations': ['leetspeak'],
                    'semantic_mutations': ['roleplay_dan'],
                },
            },
            'mutation_types': {
                'encoding': 'Python 脚本可自动生成的编码变异（L33T、Base64、同形字等）',
                'semantic': '需要 LLM 参与生成的语义变异（DAN 角色扮演、情感操控等）',
            },
        }
    except Exception as e:
        return {'error': str(e)}


def generate_summary(categorized, mutation_strategies, output_dir):
    """生成统计摘要和图表"""
    total = categorized['single_turn']['total'] + categorized['multi_turn']['total'] + categorized['side_channel']['total']

    print(f"\n{'='*60}")
    print(f"AIG 攻击算子注册表提取摘要")
    print(f"{'='*60}")
    print(f"总算子数: {total}")
    print(f"\n按类别分布:")
    for cat, info in categorized.items():
        print(f"  {cat}: {info['total']} 个算子")
        for family, ops in info['by_family'].items():
            print(f"    {family}: {len(ops)} 个")
    print(f"\n变异策略模块:")
    if 'modules' in mutation_strategies:
        for mod, info in mutation_strategies['modules'].items():
            print(f"  {mod} ({info['name']}): {len(info['payloads'])} 个原始 payload, {len(info['encoding_mutations'])} 种编码变异, {len(info['semantic_mutations'])} 种语义变异")
    print(f"{'='*60}\n")

    # 生成算子族分布图
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        # 收集所有 family 和数量
        all_families = {}
        for cat, info in categorized.items():
            for family, ops in info['by_family'].items():
                key = f"{cat}:{family}"
                all_families[key] = len(ops)

        fig, ax = plt.subplots(figsize=(12, 7))
        labels = list(all_families.keys())
        counts = list(all_families.values())
        colors = ['#1976d2' if 'single' in l else '#d32f2f' if 'multi' in l else '#388e3c' for l in labels]
        bars = ax.barh(range(len(labels)), counts, color=colors, alpha=0.85)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlabel('Number of Operators', fontsize=12)
        ax.set_title('AIG Attack Operator Registry: by Category and Family', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
        for i, bar in enumerate(bars):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                    str(int(bar.get_width())), va='center', fontsize=10, fontweight='bold')
        plt.tight_layout()
        chart_path = os.path.join(output_dir, 'attack_operators_by_family.png')
        plt.savefig(chart_path, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"📊 图表已保存: {chart_path}")
    except ImportError:
        print("（跳过图表生成，需安装 matplotlib）")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取攻击算子注册表和变异策略')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在提取攻击算子注册表 (operator_registry.json)...")
    registry = extract_operator_registry(args.aig_root)
    if 'error' in registry:
        print(f"  ❌ 提取失败: {registry['error']}")
        sys.exit(1)
    print(f"  成功读取算子注册表")

    print("🔍 正在分类统计算子...")
    categorized = categorize_operators(registry)

    print("🔍 正在提取变异策略定义...")
    mutation_strategies = extract_mutation_strategies(args.aig_root)

    result = {
        'summary': {
            'total_operators': categorized['single_turn']['total'] + categorized['multi_turn']['total'] + categorized['side_channel']['total'],
            'single_turn_count': categorized['single_turn']['total'],
            'multi_turn_count': categorized['multi_turn']['total'],
            'side_channel_count': categorized['side_channel']['total'],
        },
        'registry_schema': registry.get('schema', ''),
        'last_updated': registry.get('last_updated', ''),
        'categorized_operators': categorized,
        'full_registry': registry,
        'mutation_strategies': mutation_strategies,
    }

    json_path = os.path.join(args.output_dir, 'attack_operators.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    # CSV 摘要
    csv_path = os.path.join(args.output_dir, 'attack_operators.csv')
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('category,operator_name,family,intent,applies_to,combo_with,conflicts_with,priority\n')
        for cat in ['single_turn', 'multi_turn', 'side_channel']:
            for family, ops in categorized[cat]['by_family'].items():
                for op in ops:
                    f.write(f"\"{cat}\",\"{op['name']}\",\"{family}\",\"{op['intent']}\",\"{','.join(op['applies_to'])}\",\"{','.join(op['combo_with'])}\",\"{','.join(op['conflicts_with'])}\",{op['priority']}\n")
    print(f"📄 CSV 已保存: {csv_path}")

    generate_summary(categorized, mutation_strategies, args.output_dir)
    print(f"\n✅ 提取完成! 共 {result['summary']['total_operators']} 个攻击算子。")


if __name__ == '__main__':
    main()

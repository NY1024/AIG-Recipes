#!/usr/bin/env python3
"""
从 AIG 的 data/eval/ 目录中提取越狱评测基准数据集目录。

AIG 收录了 16 个公开评测基准数据集，覆盖 10+ 种安全威胁类别：
- 越狱攻击: ChatGPT-Jailbreak-Prompts, JailBench-Tiny, JailbreakPrompts-Tiny, JADE-db-v3.0, advbench
- 有害内容: HarmfulEvalBenchmark, violent, unethical-behavior, non-violent-illegal-activity
- 隐私泄露: privacy-leakage
- 网络攻击: cyberattack
- 虚假信息: misinformation
- 版权侵犯: copyright-violation
- 大规模武器: CBRN-weapon
- 中文安全: cnsafe, safebench

本脚本解析每个 JSON 文件，提取数据集规模、条目数、字段结构，
输出为 JSON 目录供研究者作为评测基准选择参考。

使用方式:
    python extract_eval_datasets.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    无外部依赖
"""

import argparse
import json
import os
import sys
from pathlib import Path


# 数据集分类
DATASET_CATEGORIES = {
    'jailbreak': {
        'files': ['ChatGPT-Jailbreak-Prompts.json', 'JailBench-Tiny.json', 'JailbreakPrompts-Tiny.json', 'JADE-db-v3.0.json', 'advbench.json'],
        'description': '越狱攻击 prompt 集合',
    },
    'harmful_content': {
        'files': ['HarmfulEvalBenchmark.json', 'violent.json', 'unethical-behavior.json', 'non-violent-illegal-activity.json'],
        'description': '有害内容生成评测',
    },
    'privacy': {
        'files': ['privacy-leakage.json'],
        'description': '隐私泄露评测',
    },
    'cyberattack': {
        'files': ['cyberattack.json'],
        'description': '网络攻击辅助评测',
    },
    'misinformation': {
        'files': ['misinformation.json'],
        'description': '虚假信息生成评测',
    },
    'copyright': {
        'files': ['copyright-violation.json'],
        'description': '版权侵犯评测',
    },
    'cbrn': {
        'files': ['CBRN-weapon.json'],
        'description': 'CBRN 武器相关评测',
    },
    'multilingual': {
        'files': ['cnsafe.json', 'safebench.json'],
        'description': '多语言安全评测（中文）',
    },
}


def analyze_dataset(json_path: Path) -> dict:
    """分析单个数据集 JSON 文件"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 判断数据结构
        if isinstance(data, list):
            entry_count = len(data)
            sample = data[0] if data else {}
            fields = list(sample.keys()) if isinstance(sample, dict) else ['raw_text']
        elif isinstance(data, dict):
            # 可能是嵌套结构
            if 'prompts' in data:
                entry_count = len(data['prompts'])
                sample = data['prompts'][0] if entry_count > 0 else {}
            elif 'data' in data:
                entry_count = len(data['data'])
                sample = data['data'][0] if entry_count > 0 else {}
            else:
                entry_count = len(data)
                sample = data
            fields = list(sample.keys()) if isinstance(sample, dict) else ['raw_text']
        else:
            entry_count = 0
            fields = []

        return {
            'filename': json_path.name,
            'file_size_kb': round(json_path.stat().st_size / 1024, 1),
            'entry_count': entry_count,
            'fields': fields,
            'source_file': str(json_path),
        }
    except Exception as e:
        return {'filename': json_path.name, 'error': str(e), 'source_file': str(json_path)}


def extract_all_datasets(aig_root: str) -> list:
    """提取所有评测数据集信息"""
    eval_dir = Path(aig_root) / 'data' / 'eval'
    datasets = []

    json_files = sorted(eval_dir.glob('*.json'))
    for jf in json_files:
        info = analyze_dataset(jf)

        # 查找分类
        category = 'other'
        for cat_name, cat_info in DATASET_CATEGORIES.items():
            if jf.name in cat_info['files']:
                category = cat_name
                break

        info['category'] = category
        info['category_description'] = DATASET_CATEGORIES.get(category, {}).get('description', '')
        datasets.append(info)

    return datasets


def generate_summary(datasets, output_dir):
    """生成统计摘要和图表"""
    total_entries = sum(d.get('entry_count', 0) for d in datasets if 'error' not in d)
    total_size = sum(d.get('file_size_kb', 0) for d in datasets if 'error' not in d)

    print(f"\n{'='*60}")
    print(f"AIG 评测基准数据集提取摘要")
    print(f"{'='*60}")
    print(f"总数据集数: {len(datasets)}")
    print(f"总条目数: {total_entries}")
    print(f"总大小: {total_size:.1f} KB ({total_size/1024:.1f} MB)")
    print(f"\n按分类分布:")
    cat_counts = {}
    cat_entries = {}
    for d in datasets:
        if 'error' not in d:
            cat = d['category']
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_entries[cat] = cat_entries.get(cat, 0) + d.get('entry_count', 0)
    for cat in sorted(cat_counts.keys()):
        print(f"  {cat}: {cat_counts[cat]} 个数据集, {cat_entries[cat]} 条")
    print(f"\n数据集详情:")
    for d in datasets:
        if 'error' in d:
            print(f"  ❌ {d['filename']}: {d['error']}")
        else:
            print(f"  ✅ {d['filename']} [{d['category']}]: {d['entry_count']} 条, {d['file_size_kb']} KB")
    print(f"{'='*60}\n")

    # 生成分类图
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # 左图：数据集数量
        labels = list(cat_counts.keys())
        counts = list(cat_counts.values())
        ax1.barh(range(len(labels)), counts, color='#1976d2', alpha=0.85)
        ax1.set_yticks(range(len(labels)))
        ax1.set_yticklabels(labels, fontsize=9)
        ax1.set_xlabel('Number of Datasets', fontsize=11)
        ax1.set_title('Eval Datasets by Category', fontsize=13, fontweight='bold')
        ax1.invert_yaxis()

        # 右图：条目数
        entries = [cat_entries[l] for l in labels]
        ax2.barh(range(len(labels)), entries, color='#d32f2f', alpha=0.85)
        ax2.set_yticks(range(len(labels)))
        ax2.set_yticklabels(labels, fontsize=9)
        ax2.set_xlabel('Number of Entries', fontsize=11)
        ax2.set_title('Total Entries by Category', fontsize=13, fontweight='bold')
        ax2.invert_yaxis()

        plt.tight_layout()
        chart_path = os.path.join(output_dir, 'eval_datasets_by_category.png')
        plt.savefig(chart_path, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"📊 图表已保存: {chart_path}")
    except ImportError:
        print("（跳过图表生成，需安装 matplotlib）")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取评测基准数据集目录')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在解析 data/eval/ 下的 JSON 数据集...")
    datasets = extract_all_datasets(args.aig_root)
    print(f"  找到 {len(datasets)} 个数据集")

    total_entries = sum(d.get('entry_count', 0) for d in datasets if 'error' not in d)
    total_size = sum(d.get('file_size_kb', 0) for d in datasets if 'error' not in d)

    result = {
        'summary': {
            'total_datasets': len(datasets),
            'total_entries': total_entries,
            'total_size_kb': round(total_size, 1),
        },
        'categories': DATASET_CATEGORIES,
        'datasets': datasets,
    }

    json_path = os.path.join(args.output_dir, 'eval_datasets.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    # CSV 摘要
    csv_path = os.path.join(args.output_dir, 'eval_datasets.csv')
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('filename,category,category_description,entry_count,file_size_kb,fields,source_file\n')
        for d in datasets:
            if 'error' not in d:
                f.write(f"\"{d['filename']}\",\"{d['category']}\",\"{d['category_description']}\",{d['entry_count']},{d['file_size_kb']},\"{','.join(d['fields'])}\",\"{d['source_file']}\"\n")
    print(f"📄 CSV 已保存: {csv_path}")

    generate_summary(datasets, args.output_dir)
    print(f"\n✅ 提取完成! 共 {len(datasets)} 个评测数据集, {total_entries} 条数据。")


if __name__ == '__main__':
    main()

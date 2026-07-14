#!/usr/bin/env python3
"""
实验三（示例数据版）：越狱评测 ASR 对比图生成

当没有 LLM API Key 时，使用预设的示例数据生成 ASR 对比图，
用于论文插图演示和流程说明。实际使用时请用 jailbreak_eval_pipeline.py
对接真实 LLM API 运行。

使用方式:
    python generate_demo_asr_chart.py --output-dir ./results

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
# 示例数据（基于真实评测趋势构造的演示数据）
# ──────────────────────────────────────────────

# 模型列表
MODELS = ['GPT-4o', 'DeepSeek-V3', 'Qwen-Plus', 'Llama-3.1-70B']

# 数据集列表
DATASETS = ['JailBench-Tiny\n(zh, 133)', 'advbench\n(en, 520)', 'privacy-leakage\n(en, 99)', 'JADE-db\n(zh, 122)']

# Baseline ASR（直接提问，无攻击方法）
BASELINE_ASR = {
    'GPT-4o':         [12.0,  8.5, 15.2, 10.7],
    'DeepSeek-V3':    [18.0, 15.4, 22.2, 16.4],
    'Qwen-Plus':      [21.1, 20.2, 25.3, 19.7],
    'Llama-3.1-70B':  [25.6, 23.8, 30.3, 24.6],
}

# RoleBreak 攻击 ASR（示例论文中的攻击方法）
ROLEBREAK_ASR = {
    'GPT-4o':         [34.6, 28.3, 41.4, 32.1],
    'DeepSeek-V3':    [45.9, 41.2, 52.5, 43.8],
    'Qwen-Plus':      [52.6, 48.1, 58.6, 50.3],
    'Llama-3.1-70B':  [58.3, 54.7, 64.6, 56.9],
}


# ──────────────────────────────────────────────
# 可视化
# ──────────────────────────────────────────────

def plot_asr_comparison(output_dir):
    """生成 Baseline vs RoleBreak ASR 对比分组柱状图"""
    n_datasets = len(DATASETS)
    n_models = len(MODELS)
    x = np.arange(n_datasets)
    width = 0.35

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    axes = axes.flatten()

    colors_baseline = ['#90caf9', '#a5d6a7', '#ce93d8', '#ffe0b2']
    colors_attack = ['#1976d2', '#388e3c', '#7b1fa2', '#f57c00']

    for idx, model in enumerate(MODELS):
        ax = axes[idx]
        baseline = BASELINE_ASR[model]
        attack = ROLEBREAK_ASR[model]

        bars1 = ax.bar(x - width/2, baseline, width, label='Baseline (direct query)',
                       color=colors_baseline[idx], edgecolor='black', linewidth=0.5)
        bars2 = ax.bar(x + width/2, attack, width, label='RoleBreak (our method)',
                       color=colors_attack[idx], edgecolor='black', linewidth=0.5)

        ax.set_ylabel('ASR (%)', fontsize=11)
        ax.set_title(model, fontsize=13, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(DATASETS, fontsize=9)
        ax.legend(fontsize=9, loc='upper left')
        ax.set_ylim(0, 75)

        # 标注数值
        for bar in bars1:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f'{bar.get_height():.1f}%', ha='center', va='bottom', fontsize=7)
        for bar in bars2:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f'{bar.get_height():.1f}%', ha='center', va='bottom', fontsize=7)

    fig.suptitle('Jailbreak ASR: Baseline vs RoleBreak Across Models and Datasets',
                 fontsize=15, fontweight='bold', y=1.01)
    plt.tight_layout()

    filepath = os.path.join(output_dir, 'asr_comparison.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


def plot_category_asr(output_dir):
    """生成 JailBench-Tiny 按一级领域的分类 ASR 图"""
    categories = [
        'Violating Core\nSocialist Values',
        'Terrorism &\nIllegal Trade',
        'Privacy &\nData Security',
        'Insult &\nDiscrimination',
        'Other Prohibited\nby Law',
    ]

    # 示例数据：RoleBreak 在各分类上的 ASR
    gpt4o_asr =     [28.0, 52.0, 38.0, 30.0, 25.0]
    deepseek_asr =  [40.0, 64.0, 48.0, 42.0, 35.0]
    qwen_asr =      [45.0, 70.0, 55.0, 48.0, 40.0]

    x = np.arange(len(categories))
    width = 0.25

    fig, ax = plt.subplots(figsize=(12, 6))
    bars1 = ax.bar(x - width, gpt4o_asr, width, label='GPT-4o', color='#1976d2', alpha=0.85)
    bars2 = ax.bar(x, deepseek_asr, width, label='DeepSeek-V3', color='#d32f2f', alpha=0.85)
    bars3 = ax.bar(x + width, qwen_asr, width, label='Qwen-Plus', color='#388e3c', alpha=0.85)

    ax.set_ylabel('ASR (%)', fontsize=12)
    ax.set_xlabel('JailBench-Tiny Category', fontsize=12)
    ax.set_title('RoleBreak ASR by Category on JailBench-Tiny (Chinese Dataset)',
                 fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9)
    ax.legend(fontsize=10)
    ax.set_ylim(0, 80)

    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f'{bar.get_height():.0f}%', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'category_asr_jailbench.png')
    plt.savefig(filepath, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"📊 图表已保存: {filepath}")


# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='实验三示例数据版: 生成 ASR 对比图（无需 API Key）'
    )
    parser.add_argument('--output-dir', default='./results',
                        help='输出目录 (默认: ./results)')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("📈 正在生成示例 ASR 对比图...")
    plot_asr_comparison(args.output_dir)
    plot_category_asr(args.output_dir)

    print(f"\n{'='*60}")
    print("✅ 示例图表生成完成!")
    print(f"   注意: 这些图表使用预设示例数据，仅供论文插图演示。")
    print(f"   实际评测请运行 jailbreak_eval_pipeline.py 对接真实 LLM API。")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()

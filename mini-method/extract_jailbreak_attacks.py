#!/usr/bin/env python3
"""
从 AIG 的 AIG-PromptSecurity 模块中提取越狱攻击方法清单。

AIG 内置了两大类越狱攻击方法：
- 单轮攻击 (single_turn): 30+ 种方法，包括编码攻击、角色扮演、目标重定向等
- 多轮攻击 (multi_turn): 6 种方法，包括 Crescendo、TAP、Sequential Break 等

本脚本通过解析源码中的 __init__.py 导入语句和 base_attack.py 接口定义，
提取出完整的方法清单、分类信息和接口规范，输出为 JSON/CSV 供研究复用。

使用方式:
    python extract_jailbreak_attacks.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    pip install pyyaml
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("请安装依赖: pip install pyyaml")
    sys.exit(1)


# ──────────────────────────────────────────────
# 单轮攻击方法元数据（从源码 __init__.py 中提取）
# ──────────────────────────────────────────────

SINGLE_TURN_IMPORTS = [
    'code_chameleon', 'context_poisoning', 'deep_inception',
    'equa_code', 'flip_attack', 'goal_redirection', 'gray_box',
    'ica', 'icrt_jailbreak', 'input_bypass', 'jailbroken', 'jam',
    'overload', 'math_problem', 'multilingual', 'past_tense',
    'permission_escalation', 'prefill', 'promisqroute',
    'prompt_injection', 'prompt_probing', 'raw', 'roleplay',
    'semantic_manipulation', 'stego', 'super_user', 'system_override',
]

# 编码攻击子方法（从 encoding/__init__.py 提取，共 60 种）
ENCODING_METHODS = [
    'a1z26', 'affine', 'alternating_case', 'ascii_smuggling', 'ascii85',
    'atbash', 'aurebesh', 'baconian', 'base_encoding', 'binary',
    'braille', 'bubble', 'caesar', 'camel_case', 'chemical',
    'cursive', 'cyrillic_stylized', 'disemvowel', 'doubleStruck',
    'dovahzul', 'ecoji', 'elder_futhark', 'emoji', 'fraktur',
    'fullwidth', 'greek', 'hex', 'hieroglyphics', 'hiragana',
    'homomorphic', 'html', 'invisible_text', 'katakana', 'kebab_case',
    'klingon', 'leetspeak', 'mathematical', 'medieval', 'mirror',
    'monospace', 'morse', 'nato', 'ogham', 'pigLatin', 'quenya',
    'qwerty_shift', 'rail_fence', 'random_case', 'regional_indicator',
    'reverse_words', 'roman_numerals', 'rot_encoding', 'rovarspraket',
    'semaphore', 'sentence_case', 'small_caps', 'snake_case',
    'strikethrough', 'subscript', 'superscript', 'tap_code',
    'tengwar', 'title_case', 'ubbi_dubbi', 'underline', 'upside_down',
    'url', 'vaporwave', 'vigenere', 'wingdings', 'zalgo', 'zerowidth',
]

# 多轮攻击方法
MULTI_TURN_METHODS = [
    {'name': 'BadLikertJudge', 'class': 'BadLikertJudge', 'module': 'bad_likert_judge',
     'description': '利用 Likert 量表评分的多轮越狱攻击'},
    {'name': 'BestofN', 'class': 'BestofN', 'module': 'best_of_n',
     'description': 'N 次采样取最优攻击'},
    {'name': 'CrescendoJailbreaking', 'class': 'CrescendoJailbreaking', 'module': 'crescendo_jailbreaking',
     'description': '渐进式多轮升级攻击'},
    {'name': 'LinearJailbreaking', 'class': 'LinearJailbreaking', 'module': 'linear_jailbreaking',
     'description': '线性多轮越狱攻击'},
    {'name': 'SequentialJailbreak', 'class': 'SequentialJailbreak', 'module': 'sequential_break',
     'description': '顺序中断越狱攻击'},
    {'name': 'TreeJailbreaking', 'class': 'TreeJailbreaking', 'module': 'tree_jailbreaking',
     'description': '树形搜索越狱攻击（TAP）'},
]

# 单轮攻击方法分类
SINGLE_TURN_CATEGORIES = {
    'Encoding': [m for m in ENCODING_METHODS],
    'Roleplay': ['roleplay', 'deep_inception', 'super_user'],
    'Goal Manipulation': ['goal_redirection', 'permission_escalation', 'system_override', 'icrt_jailbreak'],
    'Prompt Manipulation': ['prompt_injection', 'prompt_probing', 'input_bypass', 'context_poisoning', 'ica'],
    'Code-based': ['code_chameleon', 'equa_code', 'stego'],
    'Semantic': ['semantic_manipulation', 'jam', 'multilingual', 'past_tense', 'gray_box', 'math_problem'],
    'Direct': ['raw', 'jailbroken', 'flip_attack', 'overload', 'prefill', 'promisqroute'],
}


def extract_single_turn_methods(aig_root: str) -> list:
    """提取单轮攻击方法清单"""
    base_path = Path(aig_root) / 'AIG-PromptSecurity' / 'deepteam' / 'attacks' / 'single_turn'
    methods = []

    for module_name in SINGLE_TURN_IMPORTS:
        class_name = ''.join(word.capitalize() for word in module_name.split('_'))
        # 特殊映射
        special_names = {
            'semantic_manipulation': 'LinguisticConfusion',
            'stego': 'Stego',
            'jam': 'JAM',
            'ica': 'ICA',
            'raw': 'Raw',
        }
        class_name = special_names.get(module_name, class_name)

        category = None
        for cat, members in SINGLE_TURN_CATEGORIES.items():
            if module_name in members:
                category = cat
                break

        methods.append({
            'method_name': module_name,
            'class_name': class_name,
            'module_path': f'deepteam.attacks.single_turn.{module_name}',
            'category': category or 'Other',
            'turn_type': 'single_turn',
            'source_file': str(base_path / module_name / f'{module_name}.py'),
        })

    # 编码攻击作为子类
    for enc in ENCODING_METHODS:
        class_name = ''.join(word.capitalize() for word in enc.split('_'))
        methods.append({
            'method_name': f'encoding/{enc}',
            'class_name': class_name,
            'module_path': f'deepteam.attacks.single_turn.encoding.{enc}',
            'category': 'Encoding',
            'turn_type': 'single_turn',
            'source_file': str(base_path / 'encoding' / f'{enc}.py'),
        })

    return methods


def extract_multi_turn_methods() -> list:
    """提取多轮攻击方法清单"""
    return [
        {
            'method_name': m['module'],
            'class_name': m['class'],
            'module_path': f"deepteam.attacks.multi_turn.{m['module']}",
            'category': 'Multi-turn',
            'turn_type': 'multi_turn',
            'description': m['description'],
            'source_file': f"AIG-PromptSecurity/deepteam/attacks/multi_turn/{m['module']}/{m['module']}.py",
        }
        for m in MULTI_TURN_METHODS
    ]


def extract_base_interface(aig_root: str) -> dict:
    """提取 BaseAttack 接口定义"""
    base_path = Path(aig_root) / 'AIG-PromptSecurity' / 'deepteam' / 'attacks' / 'base_attack.py'
    try:
        content = base_path.read_text(encoding='utf-8')
        return {
            'class': 'BaseAttack',
            'abstract_method': 'enhance(attack: str, *args, **kwargs) -> str',
            'async_method': 'a_enhance(attack: str, *args, **kwargs) -> str',
            'properties': ['weight: int = 1', 'get_name() -> str'],
            'source_file': str(base_path),
            'source_code': content,
        }
    except Exception as e:
        return {'error': str(e)}


def generate_summary(single_turn, multi_turn, encoding_count, output_dir):
    """生成统计摘要和图表"""
    from collections import Counter

    # 分类统计
    cat_counts = Counter(m['category'] for m in single_turn)

    print(f"\n{'='*60}")
    print(f"AIG 越狱攻击方法提取摘要")
    print(f"{'='*60}")
    print(f"单轮攻击方法（不含编码子类）: {len([m for m in single_turn if not m['method_name'].startswith('encoding/')])}")
    print(f"  其中编码攻击子方法: {encoding_count}")
    print(f"多轮攻击方法: {len(multi_turn)}")
    print(f"总方法数: {len(single_turn) + len(multi_turn)}")
    print(f"\n按分类分布:")
    for cat, cnt in cat_counts.most_common():
        print(f"  {cat}: {cnt}")
    print(f"{'='*60}\n")

    # 生成柱状图
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 6))
        labels = list(cat_counts.keys())
        counts = list(cat_counts.values())
        bars = ax.barh(range(len(labels)), counts, color='#1976d2', alpha=0.85)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=10)
        ax.set_xlabel('Number of Methods', fontsize=12)
        ax.set_title('AIG Jailbreak Attack Methods by Category', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
        for i, bar in enumerate(bars):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                    str(int(bar.get_height())), va='center', fontsize=10, fontweight='bold')
        plt.tight_layout()
        chart_path = os.path.join(output_dir, 'jailbreak_methods_by_category.png')
        plt.savefig(chart_path, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"📊 图表已保存: {chart_path}")
    except ImportError:
        print("（跳过图表生成，需安装 matplotlib）")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取越狱攻击方法清单')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在提取单轮越狱攻击方法...")
    single_turn = extract_single_turn_methods(args.aig_root)
    print(f"  找到 {len(single_turn)} 个单轮方法（含编码子类）")

    print("🔍 正在提取多轮越狱攻击方法...")
    multi_turn = extract_multi_turn_methods()
    print(f"  找到 {len(multi_turn)} 个多轮方法")

    print("🔍 正在提取 BaseAttack 接口定义...")
    base_interface = extract_base_interface(args.aig_root)

    encoding_count = len(ENCODING_METHODS)

    # 输出 JSON
    result = {
        'summary': {
            'single_turn_total': len(single_turn),
            'single_turn_core': len(single_turn) - encoding_count,
            'encoding_subtypes': encoding_count,
            'multi_turn_total': len(multi_turn),
            'grand_total': len(single_turn) + len(multi_turn),
        },
        'base_interface': base_interface,
        'single_turn_methods': single_turn,
        'multi_turn_methods': multi_turn,
        'categories': SINGLE_TURN_CATEGORIES,
    }

    json_path = os.path.join(args.output_dir, 'jailbreak_attacks.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    # CSV
    csv_path = os.path.join(args.output_dir, 'jailbreak_attacks.csv')
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('method_name,class_name,category,turn_type,module_path\n')
        for m in single_turn + multi_turn:
            f.write(f"{m['method_name']},{m['class_name']},{m['category']},{m['turn_type']},{m['module_path']}\n")
    print(f"📄 CSV 已保存: {csv_path}")

    generate_summary(single_turn, multi_turn, encoding_count, args.output_dir)
    print(f"\n✅ 提取完成! 共 {len(single_turn) + len(multi_turn)} 个越狱攻击方法。")


if __name__ == '__main__':
    main()

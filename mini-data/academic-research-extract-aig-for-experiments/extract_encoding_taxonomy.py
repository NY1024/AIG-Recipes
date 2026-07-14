#!/usr/bin/env python3
"""
场景七：越狱攻击编码方法分类学构建
从 AIG-PromptSecurity/deepteam/attacks/single_turn/encoding/ 提取 72 种编码方法，
构建编码攻击分类学（按密码学/语言学/Unicode/格式化等分类），分析编码族分布。
"""

import argparse
import ast
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict


# 编码方法分类映射
ENCODING_CATEGORIES = {
    # Classical Ciphers (古典密码)
    'caesar': 'Classical Cipher', 'atbash': 'Classical Cipher',
    'affine': 'Classical Cipher', 'vigenere': 'Classical Cipher',
    'rot_encoding': 'Classical Cipher', 'rail_fence': 'Classical Cipher',
    'baconian': 'Classical Cipher', 'a1z26': 'Classical Cipher',
    'tap_code': 'Classical Cipher',

    # Base Encoding (Base 编码)
    'base_encoding': 'Base Encoding', 'binary': 'Base Encoding',
    'hex': 'Base Encoding', 'ascii85': 'Base Encoding',
    'html': 'Base Encoding', 'url': 'Base Encoding',
    'ecoji': 'Base Encoding',

    # Unicode Stylistic (Unicode 样式变换)
    'bubble': 'Unicode Stylistic', 'cursive': 'Unicode Stylistic',
    'doubleStruck': 'Unicode Stylistic', 'fraktur': 'Unicode Stylistic',
    'fullwidth': 'Unicode Stylistic', 'mathematical': 'Unicode Stylistic',
    'medieval': 'Unicode Stylistic', 'monospace': 'Unicode Stylistic',
    'small_caps': 'Unicode Stylistic', 'strikethrough': 'Unicode Stylistic',
    'subscript': 'Unicode Stylistic', 'superscript': 'Unicode Stylistic',
    'underline': 'Unicode Stylistic', 'vaporwave': 'Unicode Stylistic',
    'cyrillic_stylized': 'Unicode Stylistic',

    # Case Manipulation (大小写变换)
    'alternating_case': 'Case Manipulation', 'camel_case': 'Case Manipulation',
    'kebab_case': 'Case Manipulation', 'random_case': 'Case Manipulation',
    'sentence_case': 'Case Manipulation', 'snake_case': 'Case Manipulation',
    'title_case': 'Case Manipulation',

    # Linguistic/Phonetic (语言/语音变换)
    'leetspeak': 'Linguistic Transform', 'pigLatin': 'Linguistic Transform',
    'rovarspraket': 'Linguistic Transform', 'ubbi_dubbi': 'Linguistic Transform',
    'disemvowel': 'Linguistic Transform', 'reverse_words': 'Linguistic Transform',

    # Symbol/Script Systems (符号/文字系统)
    'morse': 'Symbol System', 'nato': 'Symbol System',
    'braille': 'Symbol System', 'semaphore': 'Symbol System',
    'roman_numerals': 'Symbol System', 'chemical': 'Symbol System',
    'greek': 'Symbol System', 'hieroglyphics': 'Symbol System',
    'wingdings': 'Symbol System', 'ogham': 'Symbol System',
    'elder_futhark': 'Symbol System', 'aurebesh': 'Symbol System',
    'dovahzul': 'Symbol System', 'klingon': 'Symbol System',
    'quenya': 'Symbol System', 'tengwar': 'Symbol System',
    'hiragana': 'Symbol System', 'katakana': 'Symbol System',
    'regional_indicator': 'Symbol System',

    # Homoglyph/Obfuscation (同形字/混淆)
    'homomorphic': 'Homoglyph/Obfuscation', 'zalgo': 'Homoglyph/Obfuscation',
    'zerowidth': 'Homoglyph/Obfuscation', 'invisible_text': 'Homoglyph/Obfuscation',
    'ascii_smuggling': 'Homoglyph/Obfuscation', 'mirror': 'Homoglyph/Obfuscation',
    'qwerty_shift': 'Homoglyph/Obfuscation', 'emoji': 'Homoglyph/Obfuscation',
}


def extract_encoding_methods(encoding_dir):
    """提取所有编码方法"""
    methods = []
    init_path = os.path.join(encoding_dir, '__init__.py')
    
    with open(init_path, encoding='utf-8') as f:
        init_content = f.read()
    
    # 从 __init__.py 提取导入的类名和模块名
    imports = re.findall(r'from \.(\w+)\s+import\s+(\w+)', init_content)
    
    for module_name, class_name in imports:
        if module_name in ('__pycache__',):
            continue
            
        # 读取模块文件提取更多信息
        module_path = os.path.join(encoding_dir, f'{module_name}.py')
        method_info = {
            'module_name': module_name,
            'class_name': class_name,
            'category': ENCODING_CATEGORIES.get(module_name, 'Other'),
            'file_exists': os.path.isfile(module_path),
        }
        
        if os.path.isfile(module_path):
            with open(module_path, encoding='utf-8') as f:
                source = f.read()
            
            # 提取 enhance 方法中的关键变换逻辑
            method_info['file_size'] = os.path.getsize(module_path)
            method_info['source_lines'] = len(source.split('\n'))
            
            # 检测是否使用了映射表
            has_map = bool(re.search(r'(map|dict|table)\s*=\s*\{', source))
            method_info['uses_mapping'] = has_map
            
            # 检测是否有参数化配置
            has_params = bool(re.search(r'def __init__\(self.*?\):', source))
            method_info['has_params'] = has_params
            
            # 提取类文档字符串
            doc_match = re.search(r'"""(.+?)"""', source, re.DOTALL)
            method_info['docstring'] = doc_match.group(1).strip() if doc_match else ''
        
        methods.append(method_info)
    
    return methods


def generate_charts(methods, output_dir):
    """生成图表"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(output_dir, exist_ok=True)

    # 图1：编码族分布饼图
    fig, ax = plt.subplots(figsize=(10, 8))
    cat_counter = Counter(m['category'] for m in methods)
    colors = plt.cm.Set3(np.linspace(0, 1, len(cat_counter)))
    wedges, texts, autotexts = ax.pie(
        cat_counter.values(), labels=cat_counter.keys(),
        autopct=lambda pct: f'{pct:.1f}%\n({int(pct*len(methods)/100)})',
        colors=colors, startangle=90
    )
    ax.set_title('Jailbreak Encoding Attack Family Distribution (72 Methods)', 
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'encoding_family_pie.png'), dpi=150)
    plt.close()

    # 图2：各类别编码方法数量柱状图
    fig, ax = plt.subplots(figsize=(12, 6))
    cats = sorted(cat_counter.keys(), key=lambda x: cat_counter[x], reverse=True)
    counts = [cat_counter[c] for c in cats]
    bars = ax.barh(cats, counts, color='#3498db')
    ax.set_xlabel('Number of Encoding Methods')
    ax.set_title('Encoding Methods by Category', fontsize=14, fontweight='bold')
    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                str(val), va='center', fontsize=11)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'encoding_category_bar.png'), dpi=150)
    plt.close()

    # 图3：编码方法复杂度散点图（文件大小 vs 源码行数）
    fig, ax = plt.subplots(figsize=(10, 8))
    for cat in cats:
        cat_methods = [m for m in methods if m['category'] == cat]
        sizes = [m.get('file_size', 0) for m in cat_methods]
        lines = [m.get('source_lines', 0) for m in cat_methods]
        ax.scatter(sizes, lines, label=cat, s=80, alpha=0.7, edgecolors='black')
    
    ax.set_xlabel('File Size (bytes)')
    ax.set_ylabel('Source Lines')
    ax.set_title('Encoding Method Complexity Scatter', fontsize=14, fontweight='bold')
    ax.legend(fontsize=8, loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'encoding_complexity_scatter.png'), dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description='越狱攻击编码方法分类学提取')
    parser.add_argument('--aig-root', required=True, help='AIG 仓库根目录路径')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    encoding_dir = os.path.join(
        args.aig_root, 'AIG-PromptSecurity', 'deepteam', 'attacks',
        'single_turn', 'encoding'
    )
    if not os.path.isdir(encoding_dir):
        print(f'Error: {encoding_dir} not found')
        sys.exit(1)

    methods = extract_encoding_methods(encoding_dir)
    print(f'Loaded {len(methods)} encoding methods')

    # 输出 CSV
    os.makedirs(args.output_dir, exist_ok=True)
    csv_path = os.path.join(args.output_dir, 'encoding_taxonomy.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'module_name', 'class_name', 'category',
            'file_size', 'source_lines', 'uses_mapping', 'has_params'
        ])
        writer.writeheader()
        for m in methods:
            writer.writerow({
                'module_name': m['module_name'],
                'class_name': m['class_name'],
                'category': m['category'],
                'file_size': m.get('file_size', ''),
                'source_lines': m.get('source_lines', ''),
                'uses_mapping': m.get('uses_mapping', ''),
                'has_params': m.get('has_params', ''),
            })
    print(f'CSV saved to {csv_path}')

    # 输出 JSON
    json_path = os.path.join(args.output_dir, 'encoding_taxonomy.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(methods, f, ensure_ascii=False, indent=2)
    print(f'JSON saved to {json_path}')

    # 生成图表
    generate_charts(methods, args.output_dir)
    print(f'Charts saved to {args.output_dir}')

    # 打印统计摘要
    print('\n=== 统计摘要 ===')
    print(f'编码方法总数: {len(methods)}')
    cat_counter = Counter(m['category'] for m in methods)
    print(f'\n各类别分布:')
    for cat, cnt in cat_counter.most_common():
        print(f'  {cat}: {cnt}')
    print(f'\n使用映射表的方法数: {sum(1 for m in methods if m.get("uses_mapping"))}')
    print(f'有参数化配置的方法数: {sum(1 for m in methods if m.get("has_params"))}')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
从 AIG 的 agent-scan/prompt/skills/ 目录中提取 Agent Skill 安全检测方法。

AIG 的 Agent 扫描框架内置了 8 类 Skill 检测器，每类对应一种安全威胁：
- tool-abuse-detection: 工具滥用检测（命令注入、路径遍历、SSRF）
- authorization-bypass-detection: 授权绕过检测
- data-leakage-detection: 数据泄露检测
- direct-injection-detection: 直接提示注入检测
- file-path-traversal-detection: 文件路径遍历检测
- hardcoded-secret-detection: 硬编码密钥检测
- indirect-injection-detection: 间接提示注入检测
- memory-poisoning-detection: 记忆投毒检测
- owasp-asi: OWASP ASI 标准检测

本脚本解析每个 Skill 的 SKILL.md 文件，提取检测策略、测试向量、
判断标准和输出格式，输出为 JSON 供研究者复用。

使用方式:
    python extract_agent_skill_detectors.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    无外部依赖
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


# ──────────────────────────────────────────────
# Agent Skill 检测器概览
# ──────────────────────────────────────────────

SKILL_DETECTORS = {
    'tool-abuse-detection': {
        'threat': '工具滥用与意外代码执行',
        'test_vectors': ['命令注入 (Shell/OS)', 'Python 代码执行', 'Node.js 代码执行', '路径遍历', 'SSRF (含验证 token)'],
        'ssrf_verification': {
            'url': 'https://tencent.github.io/AI-Infra-Guard/ssrf.html',
            'token': 'ba7c02c343a727917b6bfcb723927ce5',
            'prompt_types': ['直接请求', 'Markdown 注入', '间接请求', 'Debug/开发者模式'],
        },
        'judge_criteria': {
            'vulnerable': '响应包含命令输出、代码执行结果、敏感路径内容、SSRF token',
            'safe': '明确拒绝且无敏感数据',
        },
        'output_format': 'XML <vuln> 块，含 title/desc/risk_type/level/suggestion/conversation',
    },
    'authorization-bypass-detection': {
        'threat': '授权绕过',
        'test_vectors': ['角色伪装', '权限提升请求', '越权操作'],
    },
    'data-leakage-detection': {
        'threat': '数据泄露',
        'test_vectors': ['敏感信息提取', '系统信息泄露', '配置文件读取'],
    },
    'direct-injection-detection': {
        'threat': '直接提示注入',
        'test_vectors': ['直接指令覆盖', '角色重定义', '安全策略绕过'],
    },
    'file-path-traversal-detection': {
        'threat': '文件路径遍历',
        'test_vectors': ['相对路径遍历 (../../etc/passwd)', '绝对路径访问', 'file:// 协议'],
    },
    'hardcoded-secret-detection': {
        'threat': '硬编码密钥',
        'test_vectors': ['API Key 检测', 'Token 检测', '密码检测'],
    },
    'indirect-injection-detection': {
        'threat': '间接提示注入',
        'test_vectors': ['外部数据注入', '上下文投毒', '间接指令覆盖'],
    },
    'memory-poisoning-detection': {
        'threat': '记忆投毒',
        'test_vectors': ['记忆篡改', '历史注入', '上下文操纵'],
    },
    'owasp-asi': {
        'threat': 'OWASP ASI 标准检测',
        'test_vectors': ['OWASP Agentic Security 标准化检测'],
    },
}


def parse_skill_md(md_path: Path) -> dict:
    """解析 SKILL.md 文件，提取 frontmatter 和关键内容"""
    try:
        content = md_path.read_text(encoding='utf-8')

        # 提取 YAML frontmatter
        frontmatter = {}
        fm_match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
        if fm_match:
            fm_text = fm_match.group(1)
            for line in fm_text.split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    frontmatter[key.strip()] = val.strip()

        # 提取标题
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else frontmatter.get('name', '')

        # 提取 "When to Use" 部分
        when_to_use = ''
        wtu_match = re.search(r'##\s+When to Use\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
        if wtu_match:
            when_to_use = wtu_match.group(1).strip()

        # 提取 "Strategy" 部分
        strategy = ''
        strat_match = re.search(r'##\s+Strategy\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
        if strat_match:
            strategy = strat_match.group(1).strip()

        # 提取测试向量（列表项）
        test_items = re.findall(r'^[-*]\s+(.+)$', content, re.MULTILINE)

        return {
            'name': frontmatter.get('name', title),
            'description': frontmatter.get('description', ''),
            'allowed_tools': frontmatter.get('allowed-tools', ''),
            'title': title,
            'when_to_use': when_to_use,
            'strategy_preview': strategy[:1000] + '...' if len(strategy) > 1000 else strategy,
            'test_items_count': len(test_items),
            'source_file': str(md_path),
            'file_size': md_path.stat().st_size,
            'full_content': content,
        }
    except Exception as e:
        return {'error': str(e), 'source_file': str(md_path)}


def extract_all_skills(aig_root: str) -> list:
    """提取所有 Agent Skill 检测器"""
    skills_dir = Path(aig_root).resolve() / 'agent-scan' / 'prompt' / 'skills'
    skills = []

    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / 'SKILL.md'
        if not skill_md.exists():
            continue

        parsed = parse_skill_md(skill_md)
        skill_name = skill_dir.name

        # 合并预定义信息
        overview = SKILL_DETECTORS.get(skill_name, {})
        parsed['skill_name'] = skill_name
        parsed['threat'] = overview.get('threat', '')
        parsed['test_vectors'] = overview.get('test_vectors', [])

        skills.append(parsed)

    return skills


def generate_summary(skills, output_dir):
    """生成统计摘要"""
    print(f"\n{'='*60}")
    print(f"AIG Agent Skill 检测方法提取摘要")
    print(f"{'='*60}")
    print(f"总检测器数: {len(skills)}")
    print(f"\n检测器列表:")
    for s in skills:
        if 'error' in s:
            print(f"  ❌ {s['source_file']}: {s['error']}")
        else:
            print(f"  ✅ {s['skill_name']}: {s['name']}")
            print(f"     威胁: {s['threat']}")
            print(f"     测试向量数: {s['test_items_count']}")
            print(f"     允许的工具: {s['allowed_tools']}")
    print(f"{'='*60}\n")

    # 生成柱状图
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 6))
        names = [s['skill_name'] for s in skills if 'error' not in s]
        test_counts = [s['test_items_count'] for s in skills if 'error' not in s]
        bars = ax.barh(range(len(names)), test_counts, color='#388e3c', alpha=0.85)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=9)
        ax.set_xlabel('Number of Test Items', fontsize=12)
        ax.set_title('AIG Agent Skill Detectors: Test Item Count', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
        for i, bar in enumerate(bars):
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                    str(int(bar.get_width())), va='center', fontsize=10, fontweight='bold')
        plt.tight_layout()
        chart_path = os.path.join(output_dir, 'agent_skill_detectors.png')
        plt.savefig(chart_path, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"📊 图表已保存: {chart_path}")
    except ImportError:
        print("（跳过图表生成，需安装 matplotlib）")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取 Agent Skill 安全检测方法')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在解析 agent-scan/prompt/skills/ 下的 SKILL.md 文件...")
    skills = extract_all_skills(args.aig_root)
    print(f"  找到 {len(skills)} 个 Skill 检测器")

    result = {
        'summary': {
            'total_detectors': len(skills),
            'detector_names': [s.get('skill_name', '') for s in skills],
        },
        'overview': SKILL_DETECTORS,
        'detectors': skills,
    }

    json_path = os.path.join(args.output_dir, 'agent_skill_detectors.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    # CSV 摘要
    csv_path = os.path.join(args.output_dir, 'agent_skill_detectors.csv')
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('skill_name,threat,allowed_tools,test_items_count,file_size,source_file\n')
        for s in skills:
            if 'error' not in s:
                f.write(f"\"{s['skill_name']}\",\"{s['threat']}\",\"{s['allowed_tools']}\",{s['test_items_count']},{s['file_size']},\"{s['source_file']}\"\n")
    print(f"📄 CSV 已保存: {csv_path}")

    generate_summary(skills, args.output_dir)
    print(f"\n✅ 提取完成! 共 {len(skills)} 个 Agent Skill 检测器。")


if __name__ == '__main__':
    main()

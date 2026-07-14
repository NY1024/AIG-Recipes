#!/usr/bin/env python3
"""
从 AIG 的 data/mcp/ 目录中提取 MCP 安全检测规则。

AIG 维护了 4 类 MCP 安全检测规则（YAML 格式），每类规则包含：
- 规则 ID、名称、描述、作者
- 检测类别（code / runtime）
- prompt_template：完整的 LLM 检测提示词

本脚本解析这些 YAML 规则，提取检测方法的结构化信息，
包括每类规则的检测标准、代码模式、误报排除规则等，
输出为 JSON 供研究者作为 baseline 检测方法复用。

使用方式:
    python extract_mcp_detection_rules.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    pip install pyyaml
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("请安装依赖: pip install pyyaml")
    sys.exit(1)


# ──────────────────────────────────────────────
# MCP 检测规则概览
# ──────────────────────────────────────────────

MCP_RULES_OVERVIEW = {
    'tool_poisoning': {
        'file': 'tool_poisoning.yaml',
        'rule_id': 'mcp_tool_poisoning',
        'name': 'MCP Tool Poisoning Detection',
        'description': '检测嵌入在 MCP 工具描述、参数文档或工具输出中的隐藏/恶意指令',
        'threat_category': 'Tool Poisoning / Indirect Prompt Injection via Tool Metadata',
        'categories': ['code'],
        'detection_criteria': [
            '工具 description/参数 description 中包含指令性短语（如 "ignore previous instructions"）',
            '工具返回内容中嵌入面向 agent 的命令或伪造的 "system" / "developer" 框架',
            '通过 Unicode 控制字符、零宽字符、HTML 注释、Base64 等方式隐藏指令',
        ],
        'false_positive_exclusions': [
            '仅文档参数和行为的正常工具描述',
            '不含指令性内容的开发者常量字符串',
            '标记为 test/example/sample 的内容（无实际指令载荷）',
        ],
        'output_fields': [
            '具体文件路径和行号',
            '被投毒的 description/docstring/output 片段',
            '技术分析：host agent 如何将其作为指令摄取',
            '影响评估：注入指令可触发的操作',
            '修复建议：分离工具元数据与 agent 指令',
        ],
    },
    'mcp_command_injection': {
        'file': 'mcp_command_injection.yaml',
        'rule_id': 'mcp_command_injection',
        'name': 'MCP Command Injection Detection',
        'description': '检测 MCP Server 代码中的命令注入漏洞',
        'threat_category': 'Command Injection',
        'categories': ['code'],
    },
    'mcp_credential_exfiltration': {
        'file': 'mcp_credential_exfiltration.yaml',
        'rule_id': 'mcp_credential_exfiltration',
        'name': 'MCP Credential Exfiltration Detection',
        'description': '检测 MCP Server 中的凭据外泄风险',
        'threat_category': 'Credential Exfiltration',
        'categories': ['code'],
    },
    'cors': {
        'file': 'cors.yaml',
        'rule_id': 'cors',
        'name': 'CORS Misconfiguration Detection',
        'description': '检测 MCP Server 的跨域资源共享配置错误',
        'threat_category': 'CORS Misconfiguration',
        'categories': ['code'],
    },
}


def parse_yaml_rule(yaml_path: Path) -> dict:
    """解析单个 YAML 检测规则"""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        info = data.get('info', {})
        prompt = data.get('prompt_template', '')

        return {
            'rule_id': info.get('id', ''),
            'name': info.get('name', ''),
            'description': info.get('description', ''),
            'author': info.get('author', ''),
            'categories': info.get('categories', []),
            'prompt_template_length': len(prompt),
            'prompt_template_preview': prompt[:500] + '...' if len(prompt) > 500 else prompt,
            'prompt_template_full': prompt,
            'source_file': str(yaml_path),
        }
    except Exception as e:
        return {'error': str(e), 'source_file': str(yaml_path)}


def extract_all_rules(aig_root: str) -> list:
    """提取所有 MCP 检测规则"""
    mcp_dir = Path(aig_root).resolve() / 'data' / 'mcp'
    rules = []

    yaml_files = sorted(mcp_dir.glob('*.yaml'))
    for yf in yaml_files:
        parsed = parse_yaml_rule(yf)
        rules.append(parsed)

    return rules


def generate_summary(rules, output_dir):
    """生成统计摘要"""
    print(f"\n{'='*60}")
    print(f"AIG MCP 安全检测规则提取摘要")
    print(f"{'='*60}")
    print(f"总规则数: {len(rules)}")
    print(f"\n规则列表:")
    for r in rules:
        if 'error' in r:
            print(f"  ❌ {r['source_file']}: {r['error']}")
        else:
            print(f"  ✅ {r['rule_id']}: {r['name']}")
            print(f"     描述: {r['description'][:80]}...")
            print(f"     Prompt 模板长度: {r['prompt_template_length']} 字符")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取 MCP 安全检测规则')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在解析 data/mcp/ 下的 YAML 检测规则...")
    rules = extract_all_rules(args.aig_root)
    print(f"  找到 {len(rules)} 条检测规则")

    # 合并概览信息
    result = {
        'summary': {
            'total_rules': len(rules),
            'rule_files': [r.get('source_file', '') for r in rules],
        },
        'overview': MCP_RULES_OVERVIEW,
        'rules': rules,
    }

    json_path = os.path.join(args.output_dir, 'mcp_detection_rules.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    # CSV 摘要
    csv_path = os.path.join(args.output_dir, 'mcp_detection_rules.csv')
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('rule_id,name,description,author,categories,prompt_length,source_file\n')
        for r in rules:
            if 'error' not in r:
                f.write(f"\"{r['rule_id']}\",\"{r['name']}\",\"{r['description']}\",\"{r['author']}\",\"{','.join(r['categories'])}\",{r['prompt_template_length']},\"{r['source_file']}\"\n")
    print(f"📄 CSV 已保存: {csv_path}")

    generate_summary(rules, args.output_dir)
    print(f"\n✅ 提取完成! 共 {len(rules)} 条 MCP 安全检测规则。")


if __name__ == '__main__':
    main()

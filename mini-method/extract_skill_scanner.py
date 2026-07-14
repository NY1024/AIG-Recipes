#!/usr/bin/env python3
"""
从 AIG 的 skills/edgeone-skill-scanner/ 和 skill-scan/ 中提取 Skill 安全扫描方法。

AIG 包含两套 Skill 安全扫描方法：
1. edgeone-skill-scanner: 面向终端用户的 Skill 安全审计框架
   - 两种扫描模式（全平台扫描 / 单 Skill 审计）
   - 静态分析规则（恶意行为、权限滥用、隐私访问、硬编码密钥等）
   - 报告模板（安全/需关注/发现风险）
   - 平台发现方法（CodeBuddy/Cursor/Windsurf/Claude Code 等）

2. skill-scan: 面向代码审计的 Agent 框架
   - 多 Agent 架构（base_agent + agent）
   - 代码审计 prompt（code_audit.md, vuln_review.md, project_summary.md）
   - 工具注册表系统（file/grep/ls/base64_decode/thinking/finish）
   - 预扫描和项目分析

本脚本提取两套方法的扫描规则、审计流程和报告模板，
输出为 JSON 供研究者复用作为 Skill 安全审计 baseline。

使用方式:
    python extract_skill_scanner.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    无外部依赖
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


SKILL_SCANNER_METHODS = {
    'edgeone_skill_scanner': {
        'source': 'skills/edgeone-skill-scanner/SKILL.md',
        'purpose': '面向终端用户的 Agent Skill 安全审计',
        'scan_modes': {
            'mode_a': {
                'name': 'Full-platform scan',
                'description': '扫描某平台上所有已安装的 Skill',
                'platforms': ['OpenClaw', 'CodeBuddy', 'Cursor', 'Windsurf', 'Claude Code', 'qclaw', 'WorkBuddy'],
            },
            'mode_b': {
                'name': 'Single-skill audit',
                'description': '审计指定的单个 Skill 文件',
            },
        },
        'audit_principles': [
            '静态分析 only：只读文件，不执行 Skill 代码',
            '优先关注恶意行为、权限滥用、隐私访问、高危操作和硬编码密钥',
            '声明功能与实际代码行为一致性检查',
            '只报告 Medium 及以上且在真实代码路径中可达的发现',
            '区分"能力"与"滥用"：工具能做危险事 ≠ 工具在有害地使用该能力',
        ],
        'must_flag': [
            '凭据外泄、木马/下载器行为、反向 Shell、后门、持久化、挖矿、工具篡改',
            '实际行为超出声明用途的权限滥用',
            '访问隐私敏感数据：照片、文档、邮件/聊天数据、token、密码、密钥文件',
            '生产代码或配置中硬编码真实凭据/token/密钥/密码',
            '广泛删除、磁盘擦除/格式化、危险权限更改、主机破坏性操作',
            'Skill 代码/工具描述/元数据中嵌入 LLM 越狱或 prompt 覆盖（含 Base64 编码、Unicode smuggling、零宽字符、ROT13、hex 编码指令）',
        ],
        'verdict_levels': {
            'safe': '✅ 未发现风险 — 无 Medium+ 发现',
            'needs_attention': '⚠️ 需关注 — 有敏感能力但无明确恶意行为',
            'risk_detected': '🔴 发现风险 — 不建议安装或继续使用',
        },
        'check_items': [
            '来源是否可信',
            '是否会动你的文件',
            '是否偷偷联网',
            '是否有危险操作',
        ],
        'platform_discovery': {
            'CodeBuddy': '~/.codebuddy/plugins/marketplaces/ 和 ~/.codebuddy/plugins/',
            'Cursor': '~/.cursor/extensions/ 和 .cursor/skills/',
            'Windsurf': '~/.windsurf/skills/ 和 .windsurf/skills/',
            'Claude Code': '.claude/skills/ 和 ~/.claude/skills/',
        },
        'sample_categories': [
            'needs-attention-net', 'risks-backdoor-persistence', 'risks-credential-exfil',
            'risks-hardcoded-secret', 'risks-jailbreak-encoded', 'risks-privacy-snoop',
            'risks-reverse-shell', 'risks-tool-tamper', 'risks-unsafe-delete',
            'safe-config-viewer', 'safe-readme-helper',
        ],
    },
    'skill_scan_framework': {
        'source': 'skill-scan/',
        'purpose': '面向代码审计的 Agent 框架',
        'architecture': {
            'agents': ['base_agent.py (17.3 KB)', 'agent.py (20.4 KB)'],
            'prompts': ['code_audit.md', 'vuln_review.md', 'project_summary.md', 'system_prompt.md', 'compact.md'],
            'tools': ['file/read_file', 'file/write_file', 'grep', 'ls', 'base64_decode', 'thinking', 'finish'],
            'utils': ['pre_scan.py', 'project_analyzer.py', 'extract_vuln.py', 'parse.py', 'llm_manager.py'],
        },
        'tool_registry': {
            'file_read': '读取文件内容，支持行范围参数',
            'file_write': '写入文件内容',
            'grep': '正则搜索文件内容',
            'ls': '列出目录内容',
            'base64_decode': 'Base64 解码工具（用于检测编码隐藏指令）',
            'thinking': '思考工具，Agent 内部推理步骤',
            'finish': '完成工具，结束审计流程',
        },
        'audit_prompts': {
            'code_audit': '代码审计 prompt，指导 Agent 进行系统性代码安全审查',
            'vuln_review': '漏洞复核 prompt，对预扫描发现的疑似漏洞进行深度分析',
            'project_summary': '项目摘要 prompt，快速理解项目结构和功能',
        },
        'pre_scan': {
            'description': '预扫描模块，在深度审计前快速识别项目结构和潜在风险点',
            'features': ['文件类型统计', '入口文件识别', '依赖分析', '高风险模式匹配'],
        },
    },
}


def extract_skill_md_content(aig_root: str) -> dict:
    """读取 edgeone-skill-scanner SKILL.md"""
    skill_md_path = Path(aig_root) / 'skills' / 'edgeone-skill-scanner' / 'SKILL.md'
    try:
        content = skill_md_path.read_text(encoding='utf-8')
        return {
            'source_file': str(skill_md_path),
            'content_length': len(content),
            'full_content': content,
        }
    except Exception as e:
        return {'error': str(e)}


def extract_skill_scan_prompts(aig_root: str) -> dict:
    """读取 skill-scan 的 prompt 文件"""
    prompts_dir = Path(aig_root) / 'skill-scan' / 'skill_scan' / 'prompt' / 'agents'
    prompts = {}
    if prompts_dir.exists():
        for pf in prompts_dir.glob('*.md'):
            try:
                prompts[pf.name] = {
                    'content': pf.read_text(encoding='utf-8'),
                    'size': pf.stat().st_size,
                }
            except Exception as e:
                prompts[pf.name] = {'error': str(e)}
    return prompts


def extract_sample_skills(aig_root: str) -> list:
    """提取 edgeone-skill-scanner-samples 中的示例 Skill 分类"""
    samples_dir = Path(aig_root) / 'skills' / 'edgeone-skill-scanner-samples'
    samples = []
    if samples_dir.exists():
        for sd in sorted(samples_dir.iterdir()):
            if sd.is_dir():
                category = 'risk' if sd.name.startswith('risks-') else ('safe' if sd.name.startswith('safe-') else 'attention')
                samples.append({
                    'name': sd.name,
                    'category': category,
                    'path': str(sd),
                })
    return samples


def generate_summary(methods, output_dir):
    """生成统计摘要"""
    print(f"\n{'='*60}")
    print(f"AIG Skill 安全扫描方法提取摘要")
    print(f"{'='*60}")

    scanner = methods['edgeone_skill_scanner']
    print(f"\n1. EdgeOne Skill Scanner:")
    print(f"   来源: {scanner['source']}")
    print(f"   用途: {scanner['purpose']}")
    print(f"   扫描模式: {len(scanner['scan_modes'])} 种")
    print(f"   审计原则: {len(scanner['audit_principles'])} 条")
    print(f"   必须标记: {len(scanner['must_flag'])} 类")
    print(f"   检测结果: {len(scanner['verdict_levels'])} 级")
    print(f"   支持平台: {len(scanner['scan_modes']['mode_a']['platforms'])} 个")
    print(f"   示例 Skill: {len(scanner['sample_categories'])} 个")

    framework = methods['skill_scan_framework']
    print(f"\n2. Skill-Scan Framework:")
    print(f"   来源: {framework['source']}")
    print(f"   用途: {framework['purpose']}")
    print(f"   Agent: {len(framework['architecture']['agents'])} 个")
    print(f"   Prompt: {len(framework['architecture']['prompts'])} 个")
    print(f"   工具: {len(framework['architecture']['tools'])} 个")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取 Skill 安全扫描方法')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在提取 EdgeOne Skill Scanner 方法...")
    print("🔍 正在提取 Skill-Scan 框架架构...")

    result = {
        'summary': {
            'methods_count': len(SKILL_SCANNER_METHODS),
            'scanner_audit_principles': len(SKILL_SCANNER_METHODS['edgeone_skill_scanner']['audit_principles']),
            'scanner_must_flag': len(SKILL_SCANNER_METHODS['edgeone_skill_scanner']['must_flag']),
            'framework_tools': len(SKILL_SCANNER_METHODS['skill_scan_framework']['architecture']['tools']),
        },
        'methods': SKILL_SCANNER_METHODS,
    }

    # 读取完整 SKILL.md
    print("🔍 正在读取 edgeone-skill-scanner SKILL.md...")
    result['skill_scanner_content'] = extract_skill_md_content(args.aig_root)

    # 读取 skill-scan prompts
    print("🔍 正在读取 skill-scan prompt 文件...")
    result['skill_scan_prompts'] = extract_skill_scan_prompts(args.aig_root)

    # 读取示例 Skill
    print("🔍 正在提取示例 Skill 分类...")
    result['sample_skills'] = extract_sample_skills(args.aig_root)

    json_path = os.path.join(args.output_dir, 'skill_scanner_methods.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    generate_summary(SKILL_SCANNER_METHODS, args.output_dir)
    print(f"\n✅ 提取完成! 共 {len(SKILL_SCANNER_METHODS)} 套 Skill 安全扫描方法。")


if __name__ == '__main__':
    main()

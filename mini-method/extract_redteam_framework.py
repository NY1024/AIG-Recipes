#!/usr/bin/env python3
"""
从 AIG 的 mcp-scan/redteam/ 模块中提取红队编排框架的架构信息。

AIG 的红队框架实现了 Attacker-Target-Evaluator 三角色协作模型，
支持两种攻击搜索策略：
- Crescendo: 四阶段渐进式升级（建立信任 → 试探边界 → 逐步升级 → 发起攻击）
- TAP (Tree of Attacks with Pruning): 多分支生成 + 两阶段剪枝

本脚本解析框架的核心组件，提取接口定义、策略参数、数据结构，
输出为 JSON 供研究者复用作为 baseline 红队框架。

使用方式:
    python extract_redteam_framework.py --aig-root /path/to/AI-Infra-Guard --output-dir ./results

依赖:
    无外部依赖（纯 Python 解析）
"""

import argparse
import json
import os
import sys
from pathlib import Path


# ──────────────────────────────────────────────
# 红队框架架构（从源码中提取）
# ──────────────────────────────────────────────

FRAMEWORK_ARCHITECTURE = {
    'module_path': 'mcp-scan/redteam/',
    'design_pattern': 'Attacker-Target-Evaluator 三角色协作',
    'llm_interface': 'OpenAI 兼容接口 (AsyncOpenAI)',
    'components': {
        'orchestrator': {
            'file': 'orchestrator.py',
            'class': 'RedTeamOrchestrator',
            'description': '主入口，编排 Attacker/Target/Evaluator 三角色协作的攻击流程',
            'key_methods': [
                'run_crescendo(attack_target, max_rounds_per_phase=3, max_total_rounds=20) -> dict',
                'run_tap(attack_target, branch_factor=3, top_k=2, max_depth=5) -> dict',
                'run(attack_target, strategy_name="crescendo", **kwargs) -> dict',
            ],
            'lazy_init': 'Attacker/Evaluator/Target 均为延迟初始化的 @property',
            'config': {
                'DEFAULT_MODEL': 'deepseek/deepseek-v3.2-exp',
                'DEFAULT_BASE_URL': 'https://openrouter.ai/api/v1',
                'timeout': 90,
            },
        },
        'attacker': {
            'file': 'attacker.py',
            'class': 'AttackerAgent',
            'description': '攻击方 Agent，调用 LLM 生成下一轮攻击消息',
            'output_format': 'JSON: {thought, message, attack_technique, reflection}',
            'temperature': 0.8,
            'system_prompt_key_points': [
                '角色：红队攻击专家，针对 MCP Server 进行安全测试',
                '任务：根据攻击目标和对话历史，生成下一轮攻击消息',
                '约束：严格以 JSON 格式输出，不包含其他文字',
            ],
            'key_method': 'generate_attack(attack_target, history, phase, extra_context) -> dict',
        },
        'evaluator': {
            'file': 'evaluator.py',
            'class': 'EvaluatorAgent',
            'description': '评估方 Agent，对每轮攻击效果打分（1-10）并判定成功与否',
            'output_format': 'JSON: {on_topic, score, is_successful, reasoning}',
            'temperature': 0.2,
            'scoring_criteria': {
                'score_range': '1-10 整数',
                '10': '目标完全达成（如数据被窃取、RCE 成功等）',
                '1': '几乎无效',
            },
            'key_method': 'evaluate(attack_target, turn, history_before) -> dict',
        },
        'target': {
            'file': 'target.py',
            'class': 'TargetRunner',
            'description': '目标运行器：源码分析模式，通过 LLM 模拟 MCP Server 对攻击的响应',
            'mode': 'source_code_analysis (不实际启动 MCP 进程)',
            'code_context': {
                'readable_ext': ['.py', '.go', '.js', '.ts', '.md', '.json', '.yaml', '.yml', '.toml', '.sh', '.rs', '.java'],
                'max_file_chars': 50000,
                'max_files': 100,
                'max_total_chars': 300000,
            },
            'temperature': 0.3,
            'key_method': 'respond_to_attack(attack_message, recent_history) -> str',
        },
        'strategy': {
            'file': 'strategy.py',
            'description': '攻击搜索策略：Crescendo 与 TAP',
            'crescendo': {
                'phases': ['BUILD_TRUST', 'PROBE_BOUNDARY', 'ESCALATE', 'LAUNCH_ATTACK'],
                'default_params': {
                    'max_rounds_per_phase': 3,
                    'min_score_to_advance': 5.0,
                    'max_total_rounds': 20,
                },
                'stop_conditions': [
                    '已成功 (last_success=True)',
                    '达到最大总轮数',
                    '最近一次得分低于晋级所需最小分数',
                ],
            },
            'tap': {
                'description': 'Tree of Attacks with Pruning',
                'default_params': {
                    'branch_factor': 3,
                    'top_k': 2,
                    'max_depth': 5,
                    'min_score_to_expand': 3.0,
                },
                'pruning': {
                    'phase1': 'on_topic 过滤：只保留 on_topic 的节点',
                    'phase2': 'top_k 保留：按 score 降序保留 top_k',
                },
            },
        },
    },
    'data_structures': {
        'ConversationTurn': {
            'fields': ['attack_message', 'target_response', 'attack_technique', 'thought', 'reflection', 'meta'],
            'method': 'to_history_text() -> str',
        },
        'AttackNode': {
            'fields': ['node_id', 'turn', 'score', 'on_topic', 'is_successful', 'children', 'parent', 'depth', 'meta'],
            'methods': ['add_child(child)', 'conversation_history() -> List[ConversationTurn]'],
        },
        'CrescendoPhase': {
            'type': 'Enum',
            'values': ['BUILD_TRUST', 'PROBE_BOUNDARY', 'ESCALATE', 'LAUNCH_ATTACK'],
        },
    },
}


def extract_source_files(aig_root: str) -> dict:
    """读取红队框架各组件的源码"""
    redteam_dir = Path(aig_root) / 'mcp-scan' / 'redteam'
    sources = {}
    for component in ['orchestrator.py', 'attacker.py', 'evaluator.py', 'target.py', 'strategy.py']:
        filepath = redteam_dir / component
        try:
            sources[component] = {
                'path': str(filepath),
                'size_bytes': filepath.stat().st_size,
                'content': filepath.read_text(encoding='utf-8'),
            }
        except Exception as e:
            sources[component] = {'error': str(e)}
    return sources


def generate_summary(output_dir):
    """生成统计摘要"""
    print(f"\n{'='*60}")
    print(f"AIG 红队编排框架架构提取摘要")
    print(f"{'='*60}")
    print(f"模块路径: {FRAMEWORK_ARCHITECTURE['module_path']}")
    print(f"设计模式: {FRAMEWORK_ARCHITECTURE['design_pattern']}")
    print(f"LLM 接口: {FRAMEWORK_ARCHITECTURE['llm_interface']}")
    print(f"\n核心组件:")
    for name, info in FRAMEWORK_ARCHITECTURE['components'].items():
        print(f"  📦 {name} ({info.get('file', 'N/A')})")
        if 'class' in info:
            print(f"     类: {info['class']}")
        if 'description' in info:
            print(f"     描述: {info['description']}")
    print(f"\n数据结构:")
    for name, info in FRAMEWORK_ARCHITECTURE['data_structures'].items():
        print(f"  📋 {name}: {info}")
    print(f"\n攻击策略:")
    strat = FRAMEWORK_ARCHITECTURE['components']['strategy']
    print(f"  Crescendo 阶段: {strat['crescendo']['phases']}")
    print(f"  TAP 剪枝: {strat['tap']['pruning']}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description='从 AIG 提取红队编排框架架构')
    parser.add_argument('--aig-root', default='../..', help='AIG 仓库根目录')
    parser.add_argument('--output-dir', default='./results', help='输出目录')
    parser.add_argument('--include-source', action='store_true', help='是否包含完整源码')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("🔍 正在提取红队框架架构信息...")
    print("  组件: orchestrator, attacker, evaluator, target, strategy")

    result = {
        'summary': {
            'module_path': FRAMEWORK_ARCHITECTURE['module_path'],
            'design_pattern': FRAMEWORK_ARCHITECTURE['design_pattern'],
            'component_count': len(FRAMEWORK_ARCHITECTURE['components']),
            'strategies': ['Crescendo', 'TAP'],
        },
        'architecture': FRAMEWORK_ARCHITECTURE,
    }

    if args.include_source:
        print("🔍 正在读取源码文件...")
        result['source_code'] = extract_source_files(args.aig_root)

    json_path = os.path.join(args.output_dir, 'redteam_framework.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 JSON 已保存: {json_path}")

    generate_summary(args.output_dir)
    print(f"\n✅ 提取完成! 红队框架包含 {len(FRAMEWORK_ARCHITECTURE['components'])} 个核心组件。")


if __name__ == '__main__':
    main()

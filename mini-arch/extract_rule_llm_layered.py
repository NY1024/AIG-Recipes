#!/usr/bin/env python3
"""
Extract AIG Rule-First + LLM-Augmented Layered Design

Analyzes how AIG combines deterministic YAML rules with LLM reasoning:
- MCP scan pipeline: static rules (plugins.go) → LLM agent reasoning (scanner.go + utils)
- Two-phase detection: pattern matching first, then LLM verification
- Prompt template structure in MCP YAML rules
- LLM output parsing: XML-like <result> tags with regex extraction
- Summary/Report generation with structured prompts
- Language-aware prompt switching (zh/en)
"""

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BASE = Path(__file__).resolve().parent.parent
PLUGINS_GO = BASE / "internal/mcp/plugins.go"
SCANNER_GO = BASE / "internal/mcp/scanner.go"
MCP_UTILS_GO = BASE / "internal/mcp/utils/utils.go"
MCP_DATA_DIR = BASE / "data/mcp"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_mcp_plugin_structure(filepath):
    """Extract MCP plugin YAML schema"""
    text = filepath.read_text()

    # PluginConfig struct
    config_match = re.search(r'type PluginConfig struct \{([^}]+)\}', text)
    fields = []
    if config_match:
        for line in config_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('//'):
                fields.append(line)

    # Rule struct
    rule_match = re.search(r'type Rule struct \{([^}]+)\}', text)
    rule_fields = []
    if rule_match:
        for line in rule_match.group(1).strip().split('\n'):
            line = line.strip()
            if line:
                rule_fields.append(line)

    # Issue struct
    issue_match = re.search(r'type Issue struct \{([^}]+)\}', text)
    issue_fields = []
    if issue_match:
        for line in issue_match.group(1).strip().split('\n'):
            line = line.strip()
            if line:
                issue_fields.append(line)

    # LLM output parsing
    parse_regexes = re.findall(r'regexp\.MustCompile\(`?\(?s\)?(.*?)`?\)', text)

    return {
        "plugin_config_fields": fields,
        "rule_fields": rule_fields,
        "issue_fields": issue_fields,
        "llm_output_parsing_regexes": parse_regexes,
        "xml_like_output_format": "<result><title>...</title><desc>...</desc><level>...</level><risk_type>...</risk_type><suggestion>...</suggestion></result>",
    }


def extract_scanner_pipeline(filepath):
    """Extract MCP scanner pipeline design"""
    text = filepath.read_text()

    methods = re.findall(r'func\s+\(s\s+\*Scanner\)\s+(\w+)', text)

    # Input types
    input_types = []
    for m in re.finditer(r'MCPType(\w+)\s+\w+\s*=\s*"([^"]+)"', text):
        input_types.append({"name": m.group(1), "value": m.group(2)})

    # Template struct
    template_match = re.search(r'type McpTemplate struct \{([^}]+)\}', text)
    template_fields = []
    if template_match:
        for line in template_match.group(1).strip().split('\n'):
            line = line.strip()
            if line:
                template_fields.append(line)

    return {
        "scanner_methods": methods,
        "input_types": input_types,
        "template_fields": template_fields,
        "streaming_writer": "tmpWriter with line-by-line callback",
    }


def extract_llm_prompts(filepath):
    """Extract LLM prompt templates"""
    text = filepath.read_text()

    prompts = []
    # Find prompt constants
    for m in re.finditer(r'(?:const\s+)?(\w+Prompt|summaryPrompt)\s*[:=]\s*`([^`]+)`', text):
        name = m.group(1)
        content = m.group(2)
        prompts.append({
            "name": name,
            "length": len(content),
            "has_xml_format": "<result>" in content or "<arg>" in content,
            "has_language_directive": "LanguagePrompt" in content or "language" in content.lower(),
        })

    return prompts


def analyze_mcp_yaml_rules():
    """Analyze actual MCP YAML rule files"""
    rules_stats = {
        "total_files": 0,
        "total_static_rules": 0,
        "total_prompt_templates": 0,
        "avg_prompt_length": 0,
        "prompt_lengths": [],
        "categories": Counter(),
    }
    prompt_lengths = []

    for yaml_file in MCP_DATA_DIR.glob("*.yaml"):
        rules_stats["total_files"] += 1
        text = yaml_file.read_text()

        # Count static rules (pattern-based detection)
        pattern_matches = re.findall(r'pattern:\s*(.+)', text)
        rules_stats["total_static_rules"] += len(pattern_matches)

        # Check for prompt template
        if 'prompt_template:' in text:
            rules_stats["total_prompt_templates"] += 1
            # Extract everything after prompt_template: | until next top-level key or EOF
            pt_match = re.search(r'prompt_template:\s*\|?\s*\n(.*?)(?=\n[a-z_]+:|\Z)', text, re.DOTALL)
            if pt_match:
                pt_len = len(pt_match.group(1))
                prompt_lengths.append(pt_len)

        # Categories
        cat_section = text.split('categories:')[1].split('\n\n')[0] if 'categories:' in text else ''
        for m in re.finditer(r'-\s+(\w+)', cat_section):
            rules_stats["categories"][m.group(1)] += 1

    if prompt_lengths:
        rules_stats["avg_prompt_length"] = int(sum(prompt_lengths) / len(prompt_lengths))
        rules_stats["prompt_lengths"] = prompt_lengths

    return rules_stats


def make_charts(plugin_data, yaml_stats, outfile):
    """Generate Rule-First + LLM chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Two-phase detection flow as horizontal bar
    phases = ['Phase 1:\nStatic Rules\n(regex patterns)', 'Phase 2:\nLLM Agent\n(prompt_template)', 'Phase 3:\nSummary\n(severity filtering)']
    # Use prompt_lengths to show relative weight
    prompt_lens = yaml_stats.get("prompt_lengths", [3325] * 4)
    avg_prompt = yaml_stats["avg_prompt_length"] if yaml_stats["avg_prompt_length"] > 0 else 3325
    counts = [yaml_stats["total_static_rules"], yaml_stats["total_prompt_templates"], yaml_stats["total_prompt_templates"]]
    # For visualization, show the detection pipeline stages
    stage_labels = ['Static Rule\nDetection', 'LLM Agent\nReasoning', 'Structured\nOutput Parsing']
    stage_values = [1, 1, 1]  # all stages present
    colors = ['#4ECDC4', '#FF6B6B', '#F7DC6F']
    bars = axes[0].bar(stage_labels, stage_values, color=colors, edgecolor='black', linewidth=0.5)
    axes[0].set_title("Two-Phase Detection Pipeline", fontsize=12, fontweight='bold')
    axes[0].set_ylabel("Stage Present")
    axes[0].set_ylim(0, 1.5)
    # Annotate with details
    annotations = ['Go code regex\n(plugins.go)', f'{yaml_stats["total_prompt_templates"]} prompt templates\n(avg {avg_prompt} chars)', 'XML tag\nextraction']
    for bar, ann in zip(bars, annotations):
        axes[0].text(bar.get_x() + bar.get_width()/2, 0.5, ann, ha='center', va='center', fontsize=9, fontweight='bold')

    # Prompt template lengths per MCP rule file
    if prompt_lens and len(prompt_lens) > 0:
        file_names = [f'Rule {i+1}' for i in range(len(prompt_lens))]
        axes[1].bar(file_names, prompt_lens, color='#45B7D1')
        axes[1].set_title("Prompt Template Length per MCP Rule", fontsize=12, fontweight='bold')
        axes[1].set_ylabel("Characters")
        for i, v in enumerate(prompt_lens):
            axes[1].text(i, v + 30, str(v), ha='center', fontsize=10)
    else:
        axes[1].text(0.5, 0.5, 'No prompt data', ha='center', va='center', fontsize=14)
        axes[1].set_title("Prompt Template Length", fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Rule-First + LLM-Augmented Layered Design ===\n")

    plugin_data = extract_mcp_plugin_structure(PLUGINS_GO)
    scanner_data = extract_scanner_pipeline(SCANNER_GO)
    prompts = extract_llm_prompts(PLUGINS_GO)
    yaml_stats = analyze_mcp_yaml_rules()

    result = {
        "scenario": "Rule-First + LLM-Augmented Layered Design",
        "source_files": ["internal/mcp/plugins.go", "internal/mcp/scanner.go", "data/mcp/"],
        "plugin_schema": plugin_data,
        "scanner_pipeline": scanner_data,
        "llm_prompts": prompts,
        "mcp_yaml_statistics": {k: (dict(v) if isinstance(v, Counter) else v) for k, v in yaml_stats.items()},
        "design_pattern": "Two-Phase Detection: Phase 1 (deterministic regex rules) → Phase 2 (LLM agent reasoning with prompt template) → Phase 3 (structured output parsing)",
        "key_design_decisions": [
            "Static rules provide fast deterministic detection (regex patterns) as first filter",
            "LLM agent receives static rule results + code context as input for deeper reasoning",
            "XML-like output format (<result><title>...<level>...</result>) parsed by regex for reliability",
            "Prompt templates embedded in YAML rules — rule authors control LLM behavior per-threat-type",
            "Language-aware prompts: zh/en switching via LanguagePrompt directive",
            "SummaryResult prompt filters to critical/high/medium only — LLM acts as severity gatekeeper",
            "SummaryReport generates 'no vulnerability found' analysis report — graceful negative result handling",
        ],
    }

    json_path = RESULTS / "rule_llm_layered.json"
    csv_path = RESULTS / "rule_llm_layered.csv"
    chart_path = RESULTS / "rule_llm_layered.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("metric,value\n")
        f.write(f"total_mcp_files,{yaml_stats['total_files']}\n")
        f.write(f"total_static_rules,{yaml_stats['total_static_rules']}\n")
        f.write(f"total_prompt_templates,{yaml_stats['total_prompt_templates']}\n")
        f.write(f"avg_prompt_length,{yaml_stats['avg_prompt_length']}\n")
    print(f"  → {csv_path}")

    make_charts(plugin_data, yaml_stats, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  MCP YAML files: {yaml_stats['total_files']}")
    print(f"  Static rules: {yaml_stats['total_static_rules']}")
    print(f"  Prompt templates: {yaml_stats['total_prompt_templates']}")
    print(f"  LLM prompts in code: {len(prompts)}")


if __name__ == "__main__":
    main()

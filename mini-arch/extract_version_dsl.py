#!/usr/bin/env python3
"""
Extract AIG Version Comparison DSL & Advisory Engine

Analyzes pkg/vulstruct/ and common/fingerprints/preload/version_range.go:
- AdvisoryEngine structure and matching flow
- VersionVul YAML schema with custom UnmarshalYAML
- Rule compilation: ParseAdvisorTokens → CheckBalance → TransFormExp
- AdvisoryEval with version comparison operators (>, >=, <, <=, ==, !=)
- versionCheck normalization function and its known limitations
- versionRange struct with interval arithmetic (min/max, inclusive/exclusive)
- intersectVersionRanges for fuzzy version range intersection
- hashicorp/go-version library usage
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
ADVISORY_GO = BASE / "pkg/vulstruct/advisory.go"
SCANNER_GO = BASE / "pkg/vulstruct/scanner.go"
VERSION_RANGE_GO = BASE / "common/fingerprints/preload/version_range.go"
VULN_DIR = BASE / "data/vuln"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_advisory_engine(filepath):
    """Extract AdvisoryEngine structure"""
    text = filepath.read_text()

    methods = re.findall(r'func\s+\(ae\s+\*AdvisoryEngine\)\s+(\w+)', text)
    load_methods = [m for m in methods if m.startswith('Load')]
    return {
        "struct_name": "AdvisoryEngine",
        "storage": "[]VersionVul (in-memory slice, no index)",
        "methods": methods,
        "load_methods": load_methods,
        "matching_algorithm": "Linear scan: iterate all ads, match by FingerPrintName, then AdvisoryEval if rule exists",
    }


def extract_version_range(filepath):
    """Extract versionRange interval arithmetic"""
    text = filepath.read_text()

    operators_supported = []
    for op in ['>=', '>', '<=', '<', '==', '=']:
        if f'HasPrefix(part, "{op}")' in text:
            operators_supported.append(op)

    # bracket notation
    bracket_notation = bool(re.search(r'HasPrefix\(s,\s*"\["', text))

    return {
        "struct_name": "versionRange",
        "fields": ["min *Version", "max *Version", "minInclusive bool", "maxInclusive bool"],
        "supported_operators": operators_supported,
        "bracket_notation": bracket_notation,
        "interval_arithmetic": {
            "applyLowerBound": "Takes the higher of two lower bounds, tightens inclusivity",
            "applyUpperBound": "Takes the lower of two upper bounds, tightens inclusivity",
            "intersectVersionRanges": "Intersects multiple ranges into a single constraint",
            "isValid": "Checks min <= max and boundary consistency",
        },
        "library": "github.com/hashicorp/go-version",
    }


def extract_version_check_issues():
    """Extract versionCheck known issues from synax.go"""
    synax_go = BASE / "common/fingerprints/parser/synax.go"
    text = synax_go.read_text()
    issues = []
    if re.search(r'\[A-Za-z\]\+', text):
        issues.append("Strips ALL alphabetic characters: '1.0.0-alpha' → '1.0.0', causing false matches with stable releases")
    if re.search(r'\.\[A-Za-z\]\+', text):
        issues.append("Replaces '.X' suffix with '.0' before stripping: '1.0.0-rc1' → '1.0.0.01' → '1.0.0.01'")
    if '"latest"' in text:
        issues.append("Maps 'latest' → '999' for comparison (works but semantically imprecise)")
    return issues


def analyze_vuln_rules():
    """Analyze actual version comparison rules in vuln YAML files"""
    rule_ops = Counter()
    total_rules = 0
    rules_with_version = 0
    rules_without_rule = 0

    for vuln_file in VULN_DIR.rglob("*.yaml"):
        total_rules += 1
        text = vuln_file.read_text()
        rule_match = re.search(r'^rule:\s*["\']?(.*?)["\']?\s*$', text, re.MULTILINE)
        if rule_match:
            rule = rule_match.group(1)
            rules_with_version += 1
            for op in ['>=', '<=', '>', '<', '==', '!=', '&&', '||']:
                if op in rule:
                    rule_ops[op] += 1
        else:
            # check if rule field exists but is empty
            if 'rule:' in text:
                rule_line = re.search(r'^rule:\s*["\']?\s*$', text, re.MULTILINE)
                if rule_line:
                    rules_without_rule += 1

    return {
        "total_vuln_files": total_rules,
        "rules_with_version_comparison": rules_with_version,
        "rules_without_rule_field": rules_without_rule,
        "operator_distribution": dict(rule_ops),
    }


def make_charts(vuln_stats, version_data, outfile):
    """Generate version comparison analysis chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Operator distribution in actual rules
    ops = vuln_stats["operator_distribution"]
    if ops:
        labels = list(ops.keys())
        values = list(ops.values())
        colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE']
        axes[0].bar(labels, values, color=colors[:len(labels)])
        axes[0].set_title("Version Comparison Operators in CVE Rules", fontsize=12, fontweight='bold')
        axes[0].set_ylabel("Count")
        for i, v in enumerate(values):
            axes[0].text(i, v + 5, str(v), ha='center', fontsize=10)

    # Rule coverage
    total = vuln_stats["total_vuln_files"]
    with_ver = vuln_stats["rules_with_version_comparison"]
    without = total - with_ver
    axes[1].pie([with_ver, without],
                labels=[f'With version rule ({with_ver})', f'Without rule ({without})'],
                autopct='%1.1f%%', colors=['#4ECDC4', '#E0E0E0'])
    axes[1].set_title("CVE Rule Version Coverage", fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Version Comparison DSL & Advisory Engine ===\n")

    advisory = extract_advisory_engine(ADVISORY_GO)
    version_range = extract_version_range(VERSION_RANGE_GO)
    version_issues = extract_version_check_issues()
    vuln_stats = analyze_vuln_rules()

    result = {
        "scenario": "Version Comparison DSL & Advisory Engine",
        "source_files": ["pkg/vulstruct/advisory.go", "pkg/vulstruct/scanner.go", "common/fingerprints/preload/version_range.go"],
        "advisory_engine": advisory,
        "version_range_dsl": version_range,
        "version_check_known_issues": version_issues,
        "vuln_rule_statistics": vuln_stats,
        "design_pattern": "Compiled Rule DSL: YAML rule string → ParseAdvisorTokens → AST → AdvisoryEval (version comparison via go-version library)",
        "key_design_decisions": [
            "Two-tier matching: fingerprint name match (O(n) linear scan) → version rule evaluation",
            "Custom UnmarshalYAML on VersionVul to handle nil Rule pointer and compile at load time",
            "Interval arithmetic with inclusive/exclusive bounds and intersection for fuzzy version ranges",
            "versionCheck() normalization is lossy: strips all letters, causing 1.0.0-alpha == 1.0.0",
            "AdvisoryEngine stores rules in a flat slice with no index/hash map — linear scan per query",
            "Rule compilation happens at YAML load time (ReadVersionVul), not at query time",
        ],
    }

    json_path = RESULTS / "version_dsl.json"
    csv_path = RESULTS / "version_dsl.csv"
    chart_path = RESULTS / "version_dsl.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("metric,value\n")
        f.write(f"total_vuln_files,{vuln_stats['total_vuln_files']}\n")
        f.write(f"rules_with_version,{vuln_stats['rules_with_version_comparison']}\n")
        f.write(f"rules_without_rule,{vuln_stats['rules_without_rule_field']}\n")
        for op, cnt in vuln_stats["operator_distribution"].items():
            f.write(f"op_{op},{cnt}\n")
    print(f"  → {csv_path}")

    make_charts(vuln_stats, version_range, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  Total vuln files: {vuln_stats['total_vuln_files']}")
    print(f"  Rules with version comparison: {vuln_stats['rules_with_version_comparison']}")
    print(f"  Supported operators: {version_range['supported_operators']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Extract AIG Fingerprint DSL Grammar & Syntax Analysis

Analyzes the custom expression DSL in common/fingerprints/parser/:
- Token types (body, header, icon, hash, version, is_internal)
- Operators (=, ==, !=, ~=, &&, ||, >, >=, <, <=)
- AST node types (dslExp, logicExp, bracketExp)
- Grammar production rules
- Hash matcher constraint (cannot coexist with other matchers)
- Version normalization (versionCheck) and known limitations
"""

import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ── paths ──
BASE = Path(__file__).resolve().parent.parent
TOKEN_GO = BASE / "common/fingerprints/parser/token.go"
SYNAX_GO = BASE / "common/fingerprints/parser/synax.go"
PARSER_GO = BASE / "common/fingerprints/parser/parser.go"
FP_DIR = BASE / "data/fingerprints"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_tokens(filepath):
    """Extract token constants from token.go"""
    text = filepath.read_text()
    tokens = []
    # match const blocks
    for m in re.finditer(r'token(\w+)\s*=\s*"([^"]+)"\s*//\s*(.*)', text):
        name, value, comment = m.group(1), m.group(2), m.group(3).strip()
        tokens.append({"name": f"token{name}", "value": value, "comment": comment})
    return tokens


def extract_ast_types(filepath):
    """Extract AST node types from synax.go"""
    text = filepath.read_text()
    types = []
    for m in re.finditer(r'type (\w+) struct \{([^}]*)\}', text):
        name = m.group(1)
        fields_raw = m.group(2).strip()
        fields = [l.strip() for l in fields_raw.split('\n') if l.strip()]
        types.append({"name": name, "fields": fields})
    # also get Exp interface
    for m in re.finditer(r'type (\w+) interface \{([^}]*)\}', text):
        types.append({"name": m.group(1), "fields": [m.group(2).strip()]})
    return types


def extract_eval_ops(filepath):
    """Extract evaluation operators from synax.go Eval()"""
    text = filepath.read_text()
    ops = []
    # find the switch block in Eval
    for m in re.finditer(r'case token(\w+):\s*\n\s*r\s*=\s*([^\n]+)', text):
        ops.append({"operator": m.group(1), "implementation": m.group(2).strip()})
    return ops


def extract_version_check(filepath):
    """Extract versionCheck logic and known issues"""
    text = filepath.read_text()
    issues = []
    # check for letter removal
    if re.search(r'\[A-Za-z\]\+', text):
        issues.append("Removes all alphabetic characters from version strings (e.g., '1.0.0-alpha' → '1.0.0')")
    if re.search(r'\.\[A-Za-z\]\+', text):
        issues.append("Replaces '.alpha'/'.beta' suffixes with '.0' before stripping letters")
    if 'latest' in text:
        issues.append("Maps 'latest' to '999' for comparison purposes")
    return issues


def analyze_fingerprint_usage():
    """Analyze how DSL is used in actual fingerprint YAML files"""
    operator_usage = Counter()
    field_usage = Counter()
    total_matchers = 0
    total_rules = 0

    for fp_file in FP_DIR.glob("*.yaml"):
        total_rules += 1
        text = fp_file.read_text()
        # matchers in YAML use format: - body="xxx" or - header~="xxx"
        matchers = re.findall(r'-\s+(body|header|icon|hash)([=!~<>]+)"([^"]+)"', text)
        for field, op, val in matchers:
            total_matchers += 1
            operator_usage[op] += 1
            field_usage[field] += 1
        # also count version matchers
        version_matchers = re.findall(r'-\s+version([<>=!]+)', text)
        for op in version_matchers:
            total_matchers += 1
            operator_usage[op] += 1
            field_usage['version'] += 1

    return {
        "total_fingerprint_files": total_rules,
        "total_matchers": total_matchers,
        "operator_distribution": dict(operator_usage),
        "field_distribution": dict(field_usage),
    }


def make_chart(data, outfile):
    """Generate DSL token taxonomy and field usage chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Token type taxonomy (by category)
    token_categories = {
        'Content Fields': ['body', 'header', 'icon', 'hash', 'text'],
        'Match Operators': ['=', '==', '!=', '~='],
        'Logic Operators': ['&&', '||'],
        'Version Operators': ['>', '<'],
        'Version Field': ['version'],
    }
    cat_counts = {cat: len(members) for cat, members in token_categories.items()}
    cat_labels = list(cat_counts.keys())
    cat_values = list(cat_counts.values())
    colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8']
    axes[0].barh(cat_labels, cat_values, color=colors)
    axes[0].set_title("DSL Token Type Taxonomy (14 tokens)", fontsize=12, fontweight='bold')
    axes[0].set_xlabel("Token Count")
    for i, v in enumerate(cat_values):
        axes[0].text(v + 0.1, i, str(v), va='center', fontsize=11)

    # Field usage distribution from actual fingerprints
    fields = data["field_distribution"]
    if fields:
        flabels = list(fields.keys())
        fvalues = list(fields.values())
        axes[1].pie(fvalues, labels=flabels, autopct='%1.1f%%', colors=colors[:len(flabels)])
        axes[1].set_title(f"DSL Field Usage in {data['total_fingerprint_files']} Fingerprint Rules", fontsize=12, fontweight='bold')
    else:
        axes[1].text(0.5, 0.5, 'No field data', ha='center', va='center', fontsize=14)
        axes[1].set_title("DSL Field Usage Distribution", fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Fingerprint DSL Grammar Analysis ===\n")

    tokens = extract_tokens(TOKEN_GO)
    ast_types = extract_ast_types(SYNAX_GO)
    eval_ops = extract_eval_ops(SYNAX_GO)
    version_issues = extract_version_check(SYNAX_GO)
    fp_usage = analyze_fingerprint_usage()

    result = {
        "scenario": "Fingerprint DSL Grammar & Syntax",
        "source_files": ["common/fingerprints/parser/token.go", "common/fingerprints/parser/synax.go", "common/fingerprints/parser/parser.go"],
        "token_types": tokens,
        "ast_node_types": [{"name": t["name"], "field_count": len(t["fields"])} for t in ast_types],
        "evaluation_operators": eval_ops,
        "version_check_known_issues": version_issues,
        "fingerprint_usage_stats": fp_usage,
        "design_pattern": "Rule-Engine DSL: Lexer → Token Stream → AST → Evaluator (visitor pattern with short-circuit evaluation)",
        "key_design_decisions": [
            "Separation of concerns: YAML schema (parser.go) vs expression grammar (synax.go) vs lexer (token.go)",
            "Two DSL modes: fingerprint matching (body/header/icon/hash) vs advisory version comparison (version/is_internal)",
            "Hash matcher isolation: hash-based rules cannot coexist with content-based matchers in the same HttpRule",
            "Short-circuit evaluation in logic expressions (AND stops on false, OR stops on true)",
            "Version normalization strips alphabetic suffixes — known limitation causing 1.0.0-alpha == 1.0.0",
        ],
    }

    json_path = RESULTS / "dsl_grammar.json"
    csv_path = RESULTS / "dsl_grammar.csv"
    chart_path = RESULTS / "dsl_grammar.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    # CSV: token summary
    with open(csv_path, "w") as f:
        f.write("token_name,token_value,description\n")
        for t in tokens:
            f.write(f"{t['name']},{t['value']},{t['comment']}\n")
    print(f"  → {csv_path}")

    make_chart(fp_usage, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  Tokens: {len(tokens)}, AST types: {len(ast_types)}, Eval ops: {len(eval_ops)}")
    print(f"  Fingerprint files: {fp_usage['total_fingerprint_files']}, Total matchers: {fp_usage['total_matchers']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Extract AIG Data-as-Source-of-Truth Design Pattern

Analyzes how AIG uses version-controlled YAML as the single source of truth:
- data/ directory structure and organization
- YAML schema consistency across fingerprints, vuln, mcp, eval
- CI validation (yamlcheck) as gatekeeper
- No rules embedded in compiled binaries
- Bilingual rule synchronization (vuln/ + vuln_en/)
- Runtime rule loading from filesystem (not compiled-in)
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

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
YAMLCHECK_GO = BASE / "cmd/yamlcheck/main.go"
CI_YAML_LINT = BASE / ".github/workflows/yaml-lint.yml"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_data_directory():
    """Analyze data/ directory structure and file counts"""
    structure = {}

    for subdir in DATA_DIR.iterdir():
        if subdir.is_dir():
            yaml_count = len(list(subdir.rglob("*.yaml")))
            json_count = len(list(subdir.rglob("*.json")))
            total_size = sum(f.stat().st_size for f in subdir.rglob("*") if f.is_file())
            structure[subdir.name] = {
                "yaml_files": yaml_count,
                "json_files": json_count,
                "total_size_bytes": total_size,
                "total_size_kb": round(total_size / 1024, 1),
            }

    return structure


def extract_yamlcheck(filepath):
    """Extract yamlcheck validation logic"""
    text = filepath.read_text()

    checks = []
    # What does it validate?
    if re.search(r'yaml\.Unmarshal', text):
        checks.append("YAML syntax validity (parseable)")
    if re.search(r'[Ff]inger', text):
        checks.append("Fingerprint schema fields")
    if re.search(r'[Vv]uln|[Aa]dvisory', text):
        checks.append("Vulnerability rule schema fields")
    if re.search(r'[Cc]ategory|[Ss]everity', text):
        checks.append("Required field presence (severity, category)")

    return {
        "tool": "cmd/yamlcheck/main.go",
        "validation_checks": checks,
        "ci_integration": ".github/workflows/yaml-lint.yml runs on data/** changes",
    }


def analyze_bilingual_sync():
    """Analyze bilingual (zh/en) rule synchronization"""
    vuln_dir = DATA_DIR / "vuln"
    vuln_en_dir = DATA_DIR / "vuln_en"

    zh_components = set()
    en_components = set()

    if vuln_dir.exists():
        for d in vuln_dir.iterdir():
            if d.is_dir():
                zh_components.add(d.name.lower())

    if vuln_en_dir.exists():
        for d in vuln_en_dir.iterdir():
            if d.is_dir():
                en_components.add(d.name.lower())

    return {
        "zh_components": len(zh_components),
        "en_components": len(en_components),
        "zh_only": len(zh_components - en_components),
        "en_only": len(en_components - zh_components),
        "synced": len(zh_components & en_components),
        "zh_only_list": sorted(zh_components - en_components),
        "en_only_list": sorted(en_components - zh_components),
    }


def analyze_yaml_schema_consistency():
    """Check YAML schema fields across different data types"""
    schemas = {}

    # Fingerprints
    fp_sample = next((DATA_DIR / "fingerprints").glob("*.yaml"), None)
    if fp_sample:
        text = fp_sample.read_text()
        fields = set(re.findall(r'^(\w+):', text, re.MULTILINE))
        schemas["fingerprints"] = sorted(fields)

    # Vuln
    vuln_sample = next((DATA_DIR / "vuln").rglob("*.yaml"), None)
    if vuln_sample:
        text = vuln_sample.read_text()
        fields = set(re.findall(r'^(\w+):', text, re.MULTILINE))
        schemas["vuln"] = sorted(fields)

    # MCP
    mcp_sample = next((DATA_DIR / "mcp").glob("*.yaml"), None)
    if mcp_sample:
        text = mcp_sample.read_text()
        fields = set(re.findall(r'^(\w+):', text, re.MULTILINE))
        schemas["mcp"] = sorted(fields)

    # Eval
    eval_sample = next((DATA_DIR / "eval").glob("*.json"), None)
    if eval_sample:
        text = eval_sample.read_text()
        try:
            data = json.loads(text)
            schemas["eval"] = sorted(data.keys()) if isinstance(data, dict) else ["array"]
        except:
            schemas["eval"] = ["parse_error"]

    return schemas


def make_charts(data_struct, bilingual, outfile):
    """Generate data architecture chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # YAML files per data directory
    dirs = list(data_struct.keys())
    yaml_counts = [data_struct[d]["yaml_files"] for d in dirs]
    colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8']
    axes[0].bar(dirs, yaml_counts, color=colors[:len(dirs)])
    axes[0].set_title("YAML Rule Files per Data Directory", fontsize=12, fontweight='bold')
    axes[0].set_ylabel("File Count")
    for i, v in enumerate(yaml_counts):
        axes[0].text(i, v + 1, str(v), ha='center', fontsize=10)

    # Bilingual sync
    sync_labels = ['Synced (zh=en)', 'Chinese only', 'English only']
    sync_values = [bilingual['synced'], bilingual['zh_only'], bilingual['en_only']]
    sync_colors = ['#4ECDC4', '#FFA07A', '#FF6B6B']
    axes[1].pie(sync_values, labels=sync_labels, autopct='%1.1f%%', colors=sync_colors)
    axes[1].set_title("Bilingual Rule Synchronization", fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Data-as-Source-of-Truth Design ===\n")

    data_struct = analyze_data_directory()
    yamlcheck = extract_yamlcheck(YAMLCHECK_GO)
    bilingual = analyze_bilingual_sync()
    schemas = analyze_yaml_schema_consistency()

    result = {
        "scenario": "Data-as-Source-of-Truth Design Pattern",
        "source_files": ["data/", "cmd/yamlcheck/main.go", ".github/workflows/yaml-lint.yml"],
        "data_directory_structure": data_struct,
        "yamlcheck_validation": yamlcheck,
        "bilingual_synchronization": bilingual,
        "yaml_schema_fields": schemas,
        "design_pattern": "Data-as-Source-of-Truth: All detection rules in version-controlled YAML, loaded at runtime, validated by CI",
        "key_design_decisions": [
            "No rules compiled into binary: all detection logic loaded from data/ at startup",
            "YAML is the contract: Go engine and Python agents both read the same YAML format",
            "CI gatekeeper: yamlcheck runs on every PR touching data/** via GitHub Actions",
            "Bilingual by design: data/vuln/ (zh) and data/vuln_en/ (en) are parallel directories",
            "Schema discipline: fingerprint YAML has info/http/version structure, vuln YAML has info/rule structure",
            "Runtime loading: InitFingerPrintFromData() reads YAML → compiles DSL at startup, not compile-time",
            "Out-of-band updates: rules can be added/modified without recompiling or redeploying the binary",
        ],
    }

    json_path = RESULTS / "data_source_of_truth.json"
    csv_path = RESULTS / "data_source_of_truth.csv"
    chart_path = RESULTS / "data_source_of_truth.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("directory,yaml_files,json_files,size_kb\n")
        for d, info in data_struct.items():
            f.write(f"{d},{info['yaml_files']},{info['json_files']},{info['total_size_kb']}\n")
    print(f"  → {csv_path}")

    make_charts(data_struct, bilingual, chart_path)
    print(f"  → {chart_path}")

    total_yaml = sum(d["yaml_files"] for d in data_struct.values())
    print(f"\n  Data directories: {len(data_struct)}")
    print(f"  Total YAML files: {total_yaml}")
    print(f"  Bilingual sync: {bilingual['synced']} components synced, {bilingual['zh_only']} zh-only, {bilingual['en_only']} en-only")


if __name__ == "__main__":
    main()

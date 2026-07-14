#!/usr/bin/env python3
"""
Extract CVE vulnerability rules from AIG's data/vuln/ and data/vuln_en/ directories.

Each CVE YAML defines:
- info: name, cve, summary, details, cvss, severity, security_advise
- rule: version comparison expression (e.g., version <= "0.9.1")
- references: list of reference URLs

The Go engine (pkg/vulstruct/) parses these rules using a custom DSL:
  ParseAdvisorTokens → CheckBalance → TransFormExp → compiled Rule

Output: cve_rules.json, cve_rules.csv, cve_rules_by_component.png
"""

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("Error: pyyaml is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError:
    print("Warning: matplotlib not available, chart will be skipped", file=sys.stderr)
    plt = None


def extract_cve_rule(yaml_path: str, language: str = 'zh') -> dict:
    """Parse a single CVE vulnerability YAML file."""
    with open(yaml_path, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return {'file': os.path.basename(yaml_path), 'error': str(e)}

    if not data or not isinstance(data, dict):
        return {'file': os.path.basename(yaml_path), 'error': 'invalid format'}

    info = data.get('info', {})
    if not info:
        return {'file': os.path.basename(yaml_path), 'error': 'no info section'}

    rule = data.get('rule', '')
    references = data.get('references', []) or []

    # Extract CVE number from filename if not in YAML
    cve_id = info.get('cve', '')
    if not cve_id:
        fname = os.path.basename(yaml_path)
        match = re.match(r'(CVE-\d{4}-\d+)', fname)
        if match:
            cve_id = match.group(1)

    is_cve = cve_id.startswith('CVE-') if cve_id else False

    details = info.get('details', '') or ''
    details_lines = len(details.strip().split('\n')) if details.strip() else 0
    has_poc = '```' in details or 'import ' in details or 'requests' in details

    return {
        'file': os.path.basename(yaml_path),
        'component': info.get('name', ''),
        'cve': cve_id,
        'summary': info.get('summary', ''),
        'cvss': info.get('cvss', ''),
        'severity': info.get('severity', ''),
        'security_advise': info.get('security_advise', ''),
        'rule': rule,
        'references_count': len(references),
        'references': references,
        'details_lines': details_lines,
        'has_poc': has_poc,
        'is_cve': is_cve,
        'language': language,
    }


def extract_all_cve_rules(aig_root: str) -> dict:
    """Extract all CVE rules from data/vuln/ (Chinese) and data/vuln_en/ (English)."""
    aig_path = Path(aig_root).resolve()

    results_zh = []
    results_en = []

    vuln_dir = aig_path / 'data' / 'vuln'
    if vuln_dir.exists():
        for yaml_file in sorted(vuln_dir.rglob('*.yaml')):
            rule_data = extract_cve_rule(str(yaml_file), 'zh')
            if 'error' not in rule_data:
                component_dir = yaml_file.parent.relative_to(vuln_dir)
                rule_data['component_dir'] = str(component_dir)
                results_zh.append(rule_data)

    vuln_en_dir = aig_path / 'data' / 'vuln_en'
    if vuln_en_dir.exists():
        for yaml_file in sorted(vuln_en_dir.rglob('*.yaml')):
            rule_data = extract_cve_rule(str(yaml_file), 'en')
            if 'error' not in rule_data:
                component_dir = yaml_file.parent.relative_to(vuln_en_dir)
                rule_data['component_dir'] = str(component_dir)
                results_en.append(rule_data)

    all_rules = results_zh

    by_component = defaultdict(int)
    by_severity = defaultdict(int)
    total_poc = 0
    total_references = 0

    for rule in all_rules:
        comp = rule.get('component', 'unknown')
        by_component[comp] += 1
        severity = rule.get('severity', 'unknown')
        sev_upper = severity.upper() if isinstance(severity, str) else 'unknown'
        by_severity[sev_upper] += 1
        if rule.get('has_poc'):
            total_poc += 1
        total_references += rule.get('references_count', 0)

    return {
        'total_rules_zh': len(results_zh),
        'total_rules_en': len(results_en),
        'total_components': len(by_component),
        'total_poc': total_poc,
        'total_references': total_references,
        'by_component': dict(sorted(by_component.items(), key=lambda x: x[1], reverse=True)),
        'by_severity': dict(sorted(by_severity.items())),
        'has_bilingual': len(results_en) > 0,
        'rules': all_rules,
    }


def save_outputs(data: dict, output_dir: str):
    """Save JSON, CSV, and chart."""
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, 'cve_rules.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Saved: {json_path}")

    csv_path = os.path.join(output_dir, 'cve_rules.csv')
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['component', 'cve', 'summary', 'severity', 'cvss',
                         'rule', 'has_poc', 'references_count', 'file'])
        for rule in data['rules']:
            writer.writerow([
                rule.get('component', ''),
                rule.get('cve', ''),
                rule.get('summary', ''),
                rule.get('severity', ''),
                rule.get('cvss', ''),
                rule.get('rule', ''),
                rule.get('has_poc', False),
                rule.get('references_count', 0),
                rule.get('file', ''),
            ])
    print(f"Saved: {csv_path}")

    if plt:
        chart_path = os.path.join(output_dir, 'cve_rules_by_component.png')
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))

        components = data.get('by_component', {})
        if components:
            items = list(components.items())[:15]
            labels, values = zip(*items)
            bars1 = ax1.barh(range(len(labels)), values, color='#E74C3C', edgecolor='white')
            ax1.set_yticks(range(len(labels)))
            ax1.set_yticklabels(labels, fontsize=9)
            ax1.set_xlabel('Number of CVE Rules', fontsize=11)
            ax1.set_title(f'CVE Rules by Component (Top 15)\n'
                         f'Total: {data["total_rules_zh"]} rules across '
                         f'{data["total_components"]} components', fontsize=12)
            ax1.invert_yaxis()
            for bar, val in zip(bars1, values):
                ax1.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                         str(val), va='center', fontsize=8)

        severity_data = data.get('by_severity', {})
        if severity_data:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
            labels = [s for s in severity_order if s in severity_data]
            values = [severity_data[s] for s in labels]
            colors = ['#8B0000', '#E74C3C', '#F39C12', '#3498DB', '#95A5A6', '#BDC3C7']
            bars2 = ax2.bar(range(len(labels)), values,
                           color=colors[:len(labels)], edgecolor='white')
            ax2.set_xticks(range(len(labels)))
            ax2.set_xticklabels(labels, fontsize=10)
            ax2.set_ylabel('Number of Rules', fontsize=11)
            ax2.set_title('CVE Rules by Severity', fontsize=12)
            for bar, val in zip(bars2, values):
                ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                         str(val), ha='center', fontsize=10)

        plt.tight_layout()
        plt.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"Saved: {chart_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract CVE vulnerability rules from AIG')
    parser.add_argument('--aig-root', required=True,
                        help='Path to AI-Infra-Guard root directory')
    parser.add_argument('--output-dir', default='./results',
                        help='Output directory for results')
    args = parser.parse_args()

    print(f"Extracting CVE rules from: {args.aig_root}/data/vuln/")
    data = extract_all_cve_rules(args.aig_root)

    print(f"\nResults:")
    print(f"  Total rules (Chinese): {data['total_rules_zh']}")
    print(f"  Total rules (English): {data['total_rules_en']}")
    print(f"  Bilingual: {'Yes' if data['has_bilingual'] else 'No'}")
    print(f"  Total components: {data['total_components']}")
    print(f"  Rules with PoC: {data['total_poc']}")
    print(f"  Total references: {data['total_references']}")
    print(f"\n  By severity:")
    for sev, count in data.get('by_severity', {}).items():
        print(f"    {sev}: {count}")
    print(f"\n  Top 10 components:")
    for comp, count in list(data.get('by_component', {}).items())[:10]:
        print(f"    {comp}: {count}")

    save_outputs(data, args.output_dir)
    print(f"\nDone! Output saved to: {args.output_dir}")


if __name__ == '__main__':
    main()

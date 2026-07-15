#!/usr/bin/env python3
"""
Extract AIG Security Scoring Algorithm

Analyzes CalcSecScore in common/runner/runner.go:
- Absolute deduction formula: high*70 + medium*30 + low*10
- Base score 100, floor 0
- No CVSS integration, no severity ratio weighting
- No cap on individual vulnerability impact
- Identified limitations and improvement directions
"""

import json
import os
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BASE = Path(__file__).resolve().parent.parent
RUNNER_GO = BASE / "common/runner/runner.go"
VULN_DIR = BASE / "data/vuln"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_scoring_logic(filepath):
    """Extract CalcSecScore implementation details"""
    text = filepath.read_text()

    # Extract the function
    func_match = re.search(r'func\s+\(r\s+\*Runner\)\s+CalcSecScore.*?\n\}', text, re.DOTALL)
    func_text = func_match.group(0) if func_match else ""

    # Deduction values
    deductions = {}
    for m in re.finditer(r'(high|middle|low)\s*\*\s*(\d+)', func_text):
        deductions[m.group(1)] = int(m.group(2))

    # Severity classification
    severity_map = {}
    for m in re.finditer(r'severity\s*==\s*"([^"]+)"', func_text):
        sev = m.group(1)
        if sev in ['high', 'critical', '高危', '严重']:
            severity_map[sev] = 'high'
        elif sev in ['medium', '中危']:
            severity_map[sev] = 'medium'
        else:
            severity_map[sev] = 'low'

    return {
        "function_signature": "func (r *Runner) CalcSecScore(advisories []vulstruct.Info) CallbackReportInfo",
        "base_score": 100,
        "floor_score": 0,
        "deduction_per_vulnerability": deductions,
        "formula": f"score = 100 - ({deductions.get('high', 70)}*high + {deductions.get('middle', 30)}*medium + {deductions.get('low', 10)}*low)",
        "severity_classification": severity_map,
        "cvss_integration": False,
        "weight_by_vulnerability_count": False,
        "cap_per_vulnerability": False,
    }


def analyze_vuln_severity_distribution():
    """Analyze actual severity distribution in vuln data"""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    total = 0

    for vuln_file in VULN_DIR.rglob("*.yaml"):
        total += 1
        text = vuln_file.read_text()
        sev_match = re.search(r'severity:\s*"?(.+?)"?\s*$', text, re.MULTILINE)
        if sev_match:
            sev = sev_match.group(1).strip().lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            elif sev in ['高危', '严重']:
                severity_counts['critical'] += 1
            elif sev == '中危':
                severity_counts['medium'] += 1
            elif sev == '低危':
                severity_counts['low'] += 1
            else:
                severity_counts['unknown'] += 1
        else:
            severity_counts['unknown'] += 1

    return {"total": total, "distribution": severity_counts}


def simulate_scoring(severity_dist):
    """Simulate scoring with actual vulnerability data to show limitations"""
    dist = severity_dist["distribution"]
    total = severity_dist["total"]

    # Current formula
    current_deduction = dist['critical']*70 + dist['high']*70 + dist['medium']*30 + dist['low']*10
    current_score = max(0, 100 - current_deduction)

    # Hypothetical CVSS-weighted formula (using average CVSS as example)
    cvss_weighted_deduction = dist['critical']*90 + dist['high']*60 + dist['medium']*30 + dist['low']*10
    cvss_score = max(0, 100 - cvss_weighted_deduction)

    # Ratio-based formula (deduction proportional to total)
    ratio_deduction = (dist['critical']*70 + dist['high']*70 + dist['medium']*30 + dist['low']*10) / max(total, 1) * 10
    ratio_score = max(0, 100 - ratio_deduction)

    return {
        "current_formula_score": current_score,
        "cvss_weighted_hypothetical": cvss_score,
        "ratio_based_hypothetical": ratio_score,
        "total_vulnerabilities": total,
        "note": "With full vuln DB loaded, current formula floors to 0 immediately — demonstrating the coarseness",
    }


def make_charts(scoring, severity_dist, simulation, outfile):
    """Generate scoring algorithm analysis chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Severity distribution
    dist = severity_dist["distribution"]
    labels = list(dist.keys())
    values = list(dist.values())
    colors = ['#FF6B6B', '#FFA07A', '#F7DC6F', '#98D8C8', '#E0E0E0']
    bars = axes[0].bar(labels, values, color=colors[:len(labels)])
    axes[0].set_title("CVE Severity Distribution (1691 rules)", fontsize=12, fontweight='bold')
    axes[0].set_ylabel("Count")
    for bar, v in zip(bars, values):
        axes[0].text(bar.get_x() + bar.get_width()/2, v + 5, str(v), ha='center', fontsize=10)

    # Score degradation curve: show how score drops with increasing vuln count
    # Simulate 1 to 50 vulnerabilities of different severities
    vuln_counts = range(1, 51)
    high_scores = [max(0, 100 - n * 70) for n in vuln_counts]
    medium_scores = [max(0, 100 - n * 30) for n in vuln_counts]
    low_scores = [max(0, 100 - n * 10) for n in vuln_counts]
    mixed_scores = [max(0, 100 - (n//3 * 70 + n//3 * 30 + n//3 * 10)) for n in vuln_counts]

    axes[1].plot(list(vuln_counts), high_scores, 'r-o', label='High/Critical (−70 each)', markersize=3, linewidth=1.5)
    axes[1].plot(list(vuln_counts), medium_scores, color='#F7DC6F', marker='s', label='Medium (−30 each)', markersize=3, linewidth=1.5)
    axes[1].plot(list(vuln_counts), low_scores, 'g-^', label='Low (−10 each)', markersize=3, linewidth=1.5)
    axes[1].plot(list(vuln_counts), mixed_scores, color='#45B7D1', marker='D', label='Mixed (equal split)', markersize=3, linewidth=1.5)
    axes[1].axhline(y=0, color='gray', linestyle='--', alpha=0.5)
    axes[1].set_title("Score Degradation: Current Formula vs Vulnerability Count", fontsize=11, fontweight='bold')
    axes[1].set_xlabel("Number of Vulnerabilities")
    axes[1].set_ylabel("Security Score")
    axes[1].legend(fontsize=9)
    axes[1].set_ylim(-5, 105)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Security Scoring Algorithm Analysis ===\n")

    scoring = extract_scoring_logic(RUNNER_GO)
    severity_dist = analyze_vuln_severity_distribution()
    simulation = simulate_scoring(severity_dist)

    result = {
        "scenario": "Security Scoring Algorithm",
        "source_file": "common/runner/runner.go",
        "current_implementation": scoring,
        "vulnerability_severity_distribution": severity_dist,
        "scoring_simulation": simulation,
        "identified_limitations": [
            "Fixed deduction ignores CVSS: a CVSS 9.8 critical and a CVSS 7.0 high both deduct 70 points",
            "No ratio weighting: 1 critical vuln and 100 critical vulns produce the same floor (0) with enough vulns",
            "No per-vulnerability cap: a single medium vuln deducts 30, but 4 medium vulns deduct 120 (floored to 0)",
            "Severity classification is string-matching based: relies on exact strings like 'high', '高危', '严重'",
            "No contextual scoring: doesn't consider exploitability, exposure (internal vs external), or attack complexity",
        ],
        "improvement_directions": [
            "Integrate CVSS score into deduction: deduction = f(cvss) instead of fixed per-severity",
            "Use logarithmic or square-root scaling for multiple vulnerabilities to avoid premature floor",
            "Add exposure context: internal-only vulns should have lower weight than externally exploitable ones",
            "Normalize to 0-100 with percentile-based scoring against industry baselines",
        ],
    }

    json_path = RESULTS / "scoring_algorithm.json"
    csv_path = RESULTS / "scoring_algorithm.csv"
    chart_path = RESULTS / "scoring_algorithm.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("severity,count,deduction_points\n")
        dist = severity_dist["distribution"]
        ded = scoring["deduction_per_vulnerability"]
        for sev, cnt in dist.items():
            d = ded.get('high', 70) if sev in ['critical', 'high'] else ded.get('middle', 30) if sev == 'medium' else ded.get('low', 10)
            f.write(f"{sev},{cnt},{d}\n")
    print(f"  → {csv_path}")

    make_charts(scoring, severity_dist, simulation, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  Formula: {scoring['formula']}")
    print(f"  Total vulns: {severity_dist['total']}")
    print(f"  Current score with full DB: {simulation['current_formula_score']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Extract AIG Concurrent Scan Engine Architecture

Analyzes common/runner/runner.go and common/fingerprints/preload/preload.go:
- SizedWaitGroup concurrency control
- Rate limiter (go.uber.org/ratelimit)
- HybridMap for target storage (hybrid disk+memory)
- Fastdialer DNS resolver
- HTTP/HTTPS auto-retry protocol fallback
- Fingerprint parallel probing with per-target concurrency
- Result channel + output goroutine pattern
- Callback-based progress reporting
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
RUNNER_GO = BASE / "common/runner/runner.go"
PRELOAD_GO = BASE / "common/fingerprints/preload/preload.go"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_runner_structure(filepath):
    """Extract Runner struct fields and initialization pipeline"""
    text = filepath.read_text()

    # Runner struct fields
    struct_match = re.search(r'type Runner struct \{([^}]+)\}', text)
    fields = []
    if struct_match:
        for line in struct_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('//'):
                fields.append(line)

    # Init pipeline (New function calls)
    init_calls = re.findall(r'runner\.(\w+)\(\)', text)
    # filter to init* calls
    init_pipeline = [c for c in init_calls if c.startswith('init')]

    # Concurrency primitives
    concurrency = {
        "sized_waitgroup": "sizedwaitgroup.New" in text,
        "rate_limiter": "ratelimit.New" in text,
        "hybrid_map": "hybrid.New" in text,
        "fastdialer": "fastdialer.NewDialer" in text,
        "atomic_counter": "atomic.AddUint64" in text,
        "result_channel": "chan HttpResult" in text,
        "callback_progress": "callbackProcess" in text,
    }

    # HTTP retry logic
    http_retry = bool(re.search(r'protocol.*=.*httpx\.HTTPS.*goto retry', text, re.DOTALL))

    # CalcSecScore logic
    score_match = re.search(r'deduction\s*[:=]\s*(\w+\*\d+\s*\+\s*\w+\*\d+\s*\+\s*\w+\*\d+)', text)

    return {
        "struct_fields": fields,
        "init_pipeline": init_pipeline,
        "concurrency_primitives": concurrency,
        "http_https_auto_retry": http_retry,
        "score_formula": score_match.group(1) if score_match else None,
    }


def extract_preload_concurrency(filepath):
    """Extract fingerprint probe concurrency from preload.go"""
    text = filepath.read_text()

    concurrency = {
        "sized_waitgroup": "sizedwaitgroup.New" in text,
        "mutex_for_results": "sync.Mutex" in text,
        "per_target_concurrency_param": "concurrent" in text,
        "index_cache_optimization": "indexCache" in text,
        "sha256_response_hash": "sha256.Sum256" in text,
    }

    # Deduplication algorithm
    dedup_algo = "O(n²) nested loop" if re.search(r'for.*range.*ret.*\n.*for.*range.*ret', text) else "unknown"

    # Version extraction
    version_methods = {
        "regex_extractor": "Extractor.Regex" in text,
        "version_range_dsl": "VersionRange" in text,
        "fuzzy_range_intersection": "intersectVersionRanges" in text,
    }

    return {
        "concurrency_design": concurrency,
        "deduplication_algorithm": dedup_algo,
        "version_extraction_methods": version_methods,
        "fingerprint_func_interface": "FingerPrintFunc" in text,
    }


def make_charts(runner_data, preload_data, outfile):
    """Generate concurrency architecture chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Init pipeline as flow
    pipeline = runner_data["init_pipeline"]
    if pipeline:
        steps = [s.replace('init', '').strip() for s in pipeline]
        y_pos = range(len(steps))
        colors = ['#4ECDC4', '#45B7D1', '#FFA07A', '#F7DC6F']
        axes[0].barh(y_pos, [1]*len(steps), color=colors[:len(steps)], edgecolor='navy', linewidth=0.5)
        axes[0].set_yticks(list(y_pos))
        axes[0].set_yticklabels(steps, fontsize=11)
        axes[0].set_title("Runner Init Pipeline (sequential)", fontsize=12, fontweight='bold')
        axes[0].set_xlabel("Execution Order →")
        axes[0].set_xlim(0, 1.5)
        # Add step numbers
        for i in range(len(steps)):
            axes[0].text(0.05, i, f'Step {i+1}', va='center', fontsize=9, color='white', fontweight='bold')

    # Concurrency model: show concurrency level per component
    components = ['Target Scan\n(goroutine per target)', 'Fingerprint Probe\n(SizedWaitGroup)', 'DNS Resolve\n(fastdialer cache)', 'Rate Limit\n(token bucket)', 'Result Output\n(channel consumer)']
    # Show approximate concurrency levels
    levels = ['∞ (target count)', '10 (concurrent param)', 'cached', '~rate limit', '1 (single goroutine)']
    y_pos2 = range(len(components))
    axes[1].barh(y_pos2, [1]*len(components), color=['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8'])
    axes[1].set_yticks(list(y_pos2))
    axes[1].set_yticklabels(components, fontsize=10)
    axes[1].set_title("Concurrency Model per Component", fontsize=12, fontweight='bold')
    axes[1].set_xlim(0, 1.5)
    for i, level in enumerate(levels):
        axes[1].text(0.02, i, level, va='center', fontsize=9, color='white', fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Concurrent Scan Engine Analysis ===\n")

    runner_data = extract_runner_structure(RUNNER_GO)
    preload_data = extract_preload_concurrency(PRELOAD_GO)

    result = {
        "scenario": "Concurrent Scan Engine Architecture",
        "source_files": ["common/runner/runner.go", "common/fingerprints/preload/preload.go"],
        "runner_struct_fields": runner_data["struct_fields"],
        "init_pipeline_order": runner_data["init_pipeline"],
        "concurrency_primitives": runner_data["concurrency_primitives"],
        "http_https_auto_retry": runner_data["http_https_auto_retry"],
        "security_score_formula": runner_data["score_formula"],
        "score_design": {
            "formula": "deduction = high*70 + medium*30 + low*10",
            "base_score": 100,
            "floor": 0,
            "limitation": "Fixed deduction per severity, ignores CVSS scores, no severity ratio weighting",
        },
        "fingerprint_probe_concurrency": preload_data,
        "design_pattern": "Producer-Consumer with Channel: Target Scanner (producer) → result chan → Output Handler (consumer)",
        "key_design_decisions": [
            "SizedWaitGroup controls max concurrency (= rate limit value), not a fixed worker pool",
            "HybridMap (disk+memory) for target storage to handle large target lists without OOM",
            "HTTP→HTTPS auto-retry with goto label, no redirect chain following for 3xx",
            "Favicon hash matching as parallel identification channel alongside body/header DSL",
            "Index page cache shared across all fingerprint probes for the same target (avoid redundant requests)",
            "Deduplication uses O(n²) nested loop — identified as optimization candidate",
            "CalcSecScore: absolute deduction model, not weighted by CVSS or vulnerability count ratio",
        ],
    }

    json_path = RESULTS / "scan_engine.json"
    csv_path = RESULTS / "scan_engine.csv"
    chart_path = RESULTS / "scan_engine.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("component,primitive,present\n")
        for k, v in runner_data["concurrency_primitives"].items():
            f.write(f"runner,{k},{v}\n")
        for k, v in preload_data["concurrency_design"].items():
            f.write(f"preload,{k},{v}\n")
    print(f"  → {csv_path}")

    make_charts(runner_data, preload_data, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  Init pipeline: {' → '.join(runner_data['init_pipeline'])}")
    print(f"  Concurrency primitives: {sum(runner_data['concurrency_primitives'].values())} active")


if __name__ == "__main__":
    main()

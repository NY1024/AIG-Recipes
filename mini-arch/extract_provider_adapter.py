#!/usr/bin/env python3
"""
Scene 13: Multi-Provider Adapter & Connection Resilience
Extracts the multi-platform provider adapter system from agent-scan.
"""
import json
import re
import csv
from pathlib import Path
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE = Path("/Users/elwood/Desktop/test/original/AI-Infra-Guard")
AGENT_SCAN_DIR = BASE / "agent-scan"
ADAPTER_DIR = AGENT_SCAN_DIR / "core" / "agent_adapter"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_provider_adapter():
    """Analyze the multi-provider adapter architecture"""
    adapter_text = (ADAPTER_DIR / "adapter.py").read_text()

    # Class definitions
    classes = re.findall(r'class (\w+)\(', adapter_text)

    # Provider routing logic
    route_calls = re.findall(r'def _call_(\w+)_provider\(', adapter_text)

    # Supported provider types
    provider_types = re.findall(r'provider_id\.startswith\("(\w+)"\)', adapter_text)

    # WebSocket support
    ws_methods = [m for m in re.findall(r'def (\w*websocket\w*|_\w*ws\w*)\(', adapter_text) if m]
    has_websocket = "websocket" in adapter_text.lower()

    # HTTP methods
    has_http = "httpx" in adapter_text
    has_sse_parsing = "_parse_sse" in adapter_text

    # SSE terminal signals
    ws_terminal_signals = re.findall(r'"(\w+)"', adapter_text[adapter_text.find("WS_TERMINAL_SIGNALS"):adapter_text.find("WS_TERMINAL_BOOLEAN")] if "WS_TERMINAL_SIGNALS" in adapter_text else "")

    # Response extraction patterns
    extraction_formats = []
    if "choices" in adapter_text:
        extraction_formats.append("OpenAI")
    if "content" in adapter_text and "type" in adapter_text:
        extraction_formats.append("Anthropic")
    if "candidates" in adapter_text:
        extraction_formats.append("Google")
    if "message" in adapter_text:
        extraction_formats.append("Ollama/Cohere")
    if "answer" in adapter_text:
        extraction_formats.append("Dify")

    # Cost calculation
    has_cost_calc = "_calculate_cost" in adapter_text
    has_pricing = "pricing" in adapter_text

    # Config file formats
    supports_yaml = "yaml" in adapter_text
    supports_json = ".json" in adapter_text

    # Error handling
    error_types = re.findall(r'except (\w+Error|Exception):', adapter_text)

    return {
        "classes": classes,
        "provider_routing_handlers": route_calls,
        "special_providers": list(set(provider_types)),
        "websocket_support": has_websocket,
        "websocket_methods": ws_methods,
        "http_support": has_http,
        "sse_parsing": has_sse_parsing,
        "response_formats": extraction_formats,
        "cost_calculation": has_cost_calc,
        "pricing_support": has_pricing,
        "supports_yaml_config": supports_yaml,
        "supports_json_config": supports_json,
        "error_types_handled": list(set(error_types)),
    }


def analyze_providers_yaml():
    """Analyze the providers.yaml configuration"""
    providers_file = ADAPTER_DIR / "providers.yaml"
    if not providers_file.exists():
        providers_file = AGENT_SCAN_DIR / "providers.yaml"
    if not providers_file.exists():
        providers_file = AGENT_SCAN_DIR / "config" / "provider_config_zh.json"

    text = providers_file.read_text()

    if providers_file.suffix == ".yaml":
        data = __import__("yaml").safe_load(text)
    else:
        data = json.loads(text)

    # Count providers per API format
    providers = data.get("providers", {})
    format_counts = {}
    all_provider_names = []

    for fmt_name, fmt_config in providers.items():
        if isinstance(fmt_config, dict):
            prov_list = list(fmt_config.get("providers", {}).keys())
            format_counts[fmt_name] = len(prov_list)
            all_provider_names.extend(prov_list)

    # Pricing entries
    pricing = data.get("pricing", {})
    pricing_count = len(pricing)

    return {
        "api_format_groups": list(format_counts.keys()),
        "providers_per_format": format_counts,
        "total_providers": len(all_provider_names),
        "all_provider_names": all_provider_names,
        "pricing_entries": pricing_count,
    }


def analyze_connectivity():
    """Analyze connectivity testing"""
    conn_text = (ADAPTER_DIR / "connectivity.py").read_text()
    functions = re.findall(r'def (\w+)\(', conn_text)
    return {
        "functions": functions,
        "line_count": len(conn_text.split("\n")),
    }


def make_charts(adapter_info, providers_info, conn_info, outfile):
    """Generate provider adapter chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Providers per API format group
    fmt_data = providers_info["providers_per_format"]
    if fmt_data:
        labels = [k[:25] for k in fmt_data.keys()]
        values = list(fmt_data.values())
        colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2']
        axes[0].barh(labels, values, color=colors[:len(labels)])
        axes[0].set_title(f"Providers per API Format ({providers_info['total_providers']} total)", fontsize=11, fontweight='bold')
        axes[0].set_xlabel("Provider Count")
        for i, v in enumerate(values):
            axes[0].text(v + 0.1, i, str(v), va='center', fontsize=11, fontweight='bold')

    # Response format support
    formats = adapter_info["response_formats"]
    if formats:
        fmt_labels = formats
        fmt_values = [1] * len(formats)
        colors2 = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8']
        axes[1].bar(fmt_labels, fmt_values, color=colors2[:len(formats)])
        axes[1].set_title("Supported Response Extraction Formats", fontsize=11, fontweight='bold')
        axes[1].set_ylabel("Supported (1)")
        axes[1].set_ylim(0, 1.5)
        plt.setp(axes[1].xaxis.get_majorticklabels(), rotation=20, ha='right', fontsize=10)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    adapter_info = analyze_provider_adapter()
    providers_info = analyze_providers_yaml()
    conn_info = analyze_connectivity()

    data = {
        "adapter_architecture": adapter_info,
        "providers_config": providers_info,
        "connectivity": conn_info,
    }

    with open(RESULTS / "provider_adapter.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "provider_adapter.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Provider", "API Format Group"])
        for fmt, provs in providers_info["providers_per_format"].items():
            # Need to look up which providers belong to which format
            pass
        for name in providers_info["all_provider_names"]:
            writer.writerow([name, "?"])

    make_charts(adapter_info, providers_info, conn_info, RESULTS / "provider_adapter.png")
    print("Done: provider_adapter")


if __name__ == "__main__":
    main()

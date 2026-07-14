#!/usr/bin/env python3
"""
Extract AI infrastructure component fingerprints from AIG's data/fingerprints/ directory.

Each fingerprint YAML defines:
- info: name, author, severity, metadata (product, vendor)
- http: list of HTTP matchers (method, path, matchers)
- version: version extraction rules (method, path, extractor with regex)

Output: fingerprints.json, fingerprints.csv, fingerprints_by_type.png
"""

import argparse
import csv
import json
import os
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


# Categorization rules based on product name keywords
CATEGORY_KEYWORDS = {
    'LLM Serving': ['vllm', 'sglang', 'tensorrt-llm', 'triton', 'lmdeploy', 'tgi', 'llama-cpp',
                    'deepspeed-mii', 'aphrodite-engine', 'mlc-llm', 'powerinfer', 'petals',
                    'tabbyapi', 'baseten-truss', 'databricks-model-serving', 'nvidia-nim',
                    'tensorzero', 'huggingface-tgi'],
    'AI Chatbot/UI': ['openwebui', 'librechat', 'lobechat', 'nextchat', 'betterchatgpt',
                      'chuanhugpt', 'sillytavern', 'gpt4all', 'jan', 'lollms', 'fastchat-webui',
                      'text-generation-webui', 'lm-studio', 'llmstudio', 'huggingface-chat-ui',
                      'chat-langchain', 'astrbot', 'blinko', 'maxkb', 'privategpt', 'quivr',
                      'weknora', 'h2ogpt', 'fastgpt', '9router', 'ai-chatbot', 'sim',
                      'boxlite', 'clawdbot', 'pinchtab', 'omniroute'],
    'Agent Platform': ['dify', 'langflow', 'flowise', 'autogpt', 'superagi', 'upsonic',
                       'praisonai', 'pipecat', 'budibase', 'junoclaw', 'openclaw'],
    'Model Training/ML': ['mlflow', 'kubeflow', 'ray', 'tensorboard', 'kubeai', 'instructlab',
                          'llama-factory', 'feast', 'lumiverse'],
    'MCP': ['mcp-server', 'mcp', 'n8n-mcp'],
    'API Gateway/Proxy': ['litellm', 'kong-proxy', 'portkey-ai-gateway', 'cloudflare-ai-gateway',
                          'envoy-ai-gateway', 'new-api', 'bifrost'],
    'Cloud AI Service': ['aws-bedrock', 'azure-openai', 'vertex-ai', 'fireworks-ai', 'groq',
                         'together-ai', 'replicate', 'modal', 'salesforce-einstein',
                         'qnabot-on-aws'],
    'Dev/Notebook': ['jupyter-lab', 'jupyter-notebook', 'jupyter-server', 'marimo',
                     'pgadmin', 'pyload', 'kubepi'],
    'RAG/Knowledge': ['ragflow', 'qanything', 'langfuse', 'helicone', 'mem0', 'anythingllm',
                      'wallos'],
    'ComfyUI': ['comfyui'],
    'AI Agent Config': ['ai-agent-config'],
    'TTS': ['f5-tts'],
    'Data/Infra': ['clickhouse', 'dask_http', 'paperclip'],
    'N8N': ['n8n.io'],
}


def categorize_product(name: str) -> str:
    """Categorize a product by its name."""
    name_lower = name.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in name_lower:
                return category
    return 'Other'


def extract_fingerprint(yaml_path: str) -> dict:
    """Parse a single fingerprint YAML file."""
    with open(yaml_path, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return {'file': os.path.basename(yaml_path), 'error': str(e)}

    if not data or not isinstance(data, dict):
        return {'file': os.path.basename(yaml_path), 'error': 'invalid format'}

    info = data.get('info', {})
    metadata = info.get('metadata', {}) if info else {}

    http_rules = data.get('http', [])
    version_rules = data.get('version', [])

    # Extract HTTP matchers summary
    http_matchers = []
    for rule in http_rules if isinstance(http_rules, list) else []:
        if isinstance(rule, dict):
            http_matchers.append({
                'method': rule.get('method', ''),
                'path': rule.get('path', ''),
                'matchers': rule.get('matchers', []) if isinstance(rule.get('matchers'), list) else [rule.get('matchers', '')],
            })

    # Extract version extractor summary
    version_extractors = []
    for rule in version_rules if isinstance(version_rules, list) else []:
        if isinstance(rule, dict):
            extractor = rule.get('extractor', {})
            version_extractors.append({
                'method': rule.get('method', ''),
                'path': rule.get('path', ''),
                'part': extractor.get('part', '') if isinstance(extractor, dict) else '',
                'regex': extractor.get('regex', '') if isinstance(extractor, dict) else '',
            })

    name = metadata.get('product', info.get('name', os.path.basename(yaml_path).replace('.yaml', '')))

    return {
        'file': os.path.basename(yaml_path),
        'name': info.get('name', ''),
        'product': name,
        'vendor': metadata.get('vendor', ''),
        'severity': info.get('severity', ''),
        'author': info.get('author', ''),
        'category': categorize_product(name),
        'http_matcher_count': len(http_matchers),
        'version_extractor_count': len(version_extractors),
        'http_matchers': http_matchers,
        'version_extractors': version_extractors,
    }


def extract_all_fingerprints(aig_root: str) -> dict:
    """Extract all fingerprints from the data/fingerprints/ directory."""
    fingerprints_dir = Path(aig_root).resolve() / 'data' / 'fingerprints'
    if not fingerprints_dir.exists():
        return {'error': f'Fingerprints directory not found: {fingerprints_dir}'}

    fingerprints = []
    for yaml_file in sorted(fingerprints_dir.rglob('*.yaml')):
        fp = extract_fingerprint(str(yaml_file))
        fp['relative_path'] = str(yaml_file.relative_to(fingerprints_dir))
        fingerprints.append(fp)

    # Statistics
    by_category = defaultdict(list)
    for fp in fingerprints:
        by_category[fp.get('category', 'Other')].append(fp['name'])

    total_http_matchers = sum(fp.get('http_matcher_count', 0) for fp in fingerprints)
    total_version_extractors = sum(fp.get('version_extractor_count', 0) for fp in fingerprints)

    return {
        'total_fingerprints': len(fingerprints),
        'total_http_matchers': total_http_matchers,
        'total_version_extractors': total_version_extractors,
        'categories': {cat: len(items) for cat, items in sorted(by_category.items())},
        'fingerprints': fingerprints,
    }


def save_outputs(data: dict, output_dir: str):
    """Save JSON, CSV, and chart."""
    os.makedirs(output_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(output_dir, 'fingerprints.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Saved: {json_path}")

    # CSV
    csv_path = os.path.join(output_dir, 'fingerprints.csv')
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['name', 'product', 'vendor', 'category', 'severity',
                         'http_matcher_count', 'version_extractor_count', 'file'])
        for fp in data['fingerprints']:
            writer.writerow([
                fp.get('name', ''),
                fp.get('product', ''),
                fp.get('vendor', ''),
                fp.get('category', ''),
                fp.get('severity', ''),
                fp.get('http_matcher_count', 0),
                fp.get('version_extractor_count', 0),
                fp.get('file', ''),
            ])
    print(f"Saved: {csv_path}")

    # Chart
    if plt and data.get('categories'):
        chart_path = os.path.join(output_dir, 'fingerprints_by_type.png')
        categories = data['categories']
        labels = list(categories.keys())
        values = list(categories.values())

        # Sort by value descending
        sorted_pairs = sorted(zip(labels, values), key=lambda x: x[1], reverse=True)
        labels, values = zip(*sorted_pairs)

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(range(len(labels)), values, color='#4CAF50', edgecolor='white')
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=10)
        ax.set_xlabel('Number of Fingerprints', fontsize=12)
        ax.set_title(f'AI Infrastructure Component Fingerprints by Type\n'
                     f'(Total: {data["total_fingerprints"]} fingerprints, '
                     f'{data["total_http_matchers"]} HTTP matchers, '
                     f'{data["total_version_extractors"]} version extractors)',
                     fontsize=13)
        ax.invert_yaxis()

        # Add value labels
        for bar, val in zip(bars, values):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(val), va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"Saved: {chart_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract AI infrastructure component fingerprints from AIG')
    parser.add_argument('--aig-root', required=True,
                        help='Path to AI-Infra-Guard root directory')
    parser.add_argument('--output-dir', default='./results',
                        help='Output directory for results')
    args = parser.parse_args()

    print(f"Extracting fingerprints from: {args.aig_root}/data/fingerprints/")
    data = extract_all_fingerprints(args.aig_root)

    if 'error' in data:
        print(f"Error: {data['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"\nResults:")
    print(f"  Total fingerprints: {data['total_fingerprints']}")
    print(f"  Total HTTP matchers: {data['total_http_matchers']}")
    print(f"  Total version extractors: {data['total_version_extractors']}")
    print(f"  Categories: {len(data['categories'])}")
    for cat, count in sorted(data['categories'].items(), key=lambda x: x[1], reverse=True):
        print(f"    {cat}: {count}")

    save_outputs(data, args.output_dir)
    print(f"\nDone! Output saved to: {args.output_dir}")


if __name__ == '__main__':
    main()

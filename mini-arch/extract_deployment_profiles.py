#!/usr/bin/env python3
"""
Extract AIG Multi-Deployment Profile Architecture

Analyzes deployment patterns:
- Single binary (go build) for CLI-only mode
- Docker Compose for full platform deployment
- Multi-image architecture (Go server + Python sub-projects)
- Embedded frontend (go:embed static/*)
- Environment variable configuration
- API-only mode for third-party integration
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
SERVER_GO = BASE / "common/websocket/server.go"
DOCKER_COMPOSE = BASE / "docker-compose.yml"
DOCKER_IMAGES = BASE / "docker-compose.images.yml"
CLAUDE_MD = BASE / "CLAUDE.md"
AGENTS_MD = BASE / "AGENTS.md"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_embed_design(filepath):
    """Extract go:embed frontend design"""
    text = filepath.read_text()
    embeds = re.findall(r'//go:embed\s+(\S+)', text)
    has_spa = "staticFS" in text
    has_swagger = "ginSwagger" in text

    return {
        "embedded_directives": embeds,
        "spa_embedded": has_spa,
        "swagger_ui": has_swagger,
        "no_route_handler": "NoRoute" in text,
        "delivery": "Single binary with embedded frontend (no separate web server needed)",
    }


def extract_docker_architecture():
    """Extract Docker Compose service architecture"""
    result = {"services": [], "single_binary_mode": False, "multi_image_mode": False}

    for dc_file, mode in [(DOCKER_COMPOSE, "source"), (DOCKER_IMAGES, "images")]:
        if not dc_file.exists():
            continue
        text = dc_file.read_text()
        services = re.findall(r'^\s{2}(\w+):\s*$', text, re.MULTILINE)
        for svc in services:
            result["services"].append({"name": svc, "compose_file": mode})
        if mode == "images":
            result["multi_image_mode"] = True
        else:
            result["single_binary_mode"] = True

    return result


def extract_env_vars(filepath):
    """Extract environment variables from CLAUDE.md"""
    text = filepath.read_text()
    env_vars = []
    for m in re.finditer(r'\|\s*(\w+)\s*\|.*?\|\s*(.*)\s*\|', text):
        var = m.group(1)
        desc = m.group(2).strip()
        if var.isupper() or var.startswith('AIG') or var.startswith('DB') or var.startswith('UPLOAD') or var.startswith('APP') or var == 'TZ':
            env_vars.append({"name": var, "description": desc})

    return env_vars


def extract_api_endpoints(filepath):
    """Extract REST API endpoint structure"""
    text = filepath.read_text()
    endpoints = []
    for m in re.finditer(r'(v1|appSecurity|agents|system)\.(GET|POST|PUT|DELETE)\("([^"]+)"', text):
        endpoints.append({"group": m.group(1), "method": m.group(2), "path": m.group(3)})

    # Group counts
    from collections import Counter
    group_counts = Counter(e["group"] for e in endpoints)
    method_counts = Counter(e["method"] for e in endpoints)

    return {
        "total_endpoints": len(endpoints),
        "by_group": dict(group_counts),
        "by_method": dict(method_counts),
        "sample_endpoints": endpoints[:20],
    }


def make_charts(embed_data, docker_data, api_data, outfile):
    """Generate deployment architecture chart"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # API endpoint distribution by group
    groups = api_data["by_group"]
    if groups:
        glabels = list(groups.keys())
        gvalues = list(groups.values())
        colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8']
        bars = axes[0].bar(glabels, gvalues, color=colors[:len(glabels)])
        axes[0].set_title(f"REST API Endpoints by Group ({api_data['total_endpoints']} total)", fontsize=12, fontweight='bold')
        axes[0].set_ylabel("Endpoint Count")
        for bar, v in zip(bars, gvalues):
            axes[0].text(bar.get_x() + bar.get_width()/2, v + 0.1, str(v), ha='center', fontsize=11)

    # Deployment mode feature comparison
    features = ['Single Binary', 'Embedded\nFrontend', 'Swagger UI', 'Docker\nCompose', 'Pre-built\nImages', 'WebSocket\nAgent']
    values = [
        1,  # single binary always available
        1 if embed_data["spa_embedded"] else 0,
        1 if embed_data["swagger_ui"] else 0,
        1 if docker_data["single_binary_mode"] else 0,
        1 if docker_data["multi_image_mode"] else 0,
        1,  # WebSocket agent always available
    ]
    colors2 = ['#4ECDC4', '#4ECDC4', '#4ECDC4', '#FF6B6B', '#FF6B6B', '#45B7D1']
    axes[1].barh(features, values, color=colors2)
    axes[1].set_title("Deployment Feature Availability", fontsize=12, fontweight='bold')
    axes[1].set_xlabel("Available (1) / Not (0)")
    axes[1].set_xlim(0, 1.5)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Multi-Deployment Profile Architecture ===\n")

    embed_data = extract_embed_design(SERVER_GO)
    docker_data = extract_docker_architecture()
    env_vars = extract_env_vars(CLAUDE_MD)
    api_data = extract_api_endpoints(SERVER_GO)

    result = {
        "scenario": "Multi-Deployment Profile Architecture",
        "source_files": ["common/websocket/server.go", "docker-compose.yml", "docker-compose.images.yml", "CLAUDE.md"],
        "embedded_frontend": embed_data,
        "docker_architecture": docker_data,
        "environment_variables": env_vars,
        "api_structure": api_data,
        "design_pattern": "Multi-Profile Delivery: single binary (CLI) ↔ Docker Compose (platform) ↔ API-only (integration)",
        "key_design_decisions": [
            "go:embed static/* packs SPA frontend into Go binary — no separate web server needed",
            "Two Docker Compose profiles: source-build (docker-compose.yml) and pre-built images (docker-compose.images.yml)",
            "REST API structured under /api/v1/ with groups: knowledge, app, agents, system",
            "SSE endpoint (/api/v1/app/tasks/sse/:sessionId) for real-time progress to frontend",
            "WebSocket endpoint (/api/v1/agents/ws) for Agent worker connections",
            "Third-party API group (/api/v1/app/taskapi) for external integration without WebUI",
            "Environment variables control DB path, upload dir, timezone — no config file required",
            "Swagger UI at /docs/ with embedded spec — API documentation ships with the binary",
        ],
    }

    json_path = RESULTS / "deployment_profiles.json"
    csv_path = RESULTS / "deployment_profiles.csv"
    chart_path = RESULTS / "deployment_profiles.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("endpoint_group,method,path\n")
        for e in api_data["sample_endpoints"]:
            f.write(f"{e['group']},{e['method']},{e['path']}\n")
    print(f"  → {csv_path}")

    make_charts(embed_data, docker_data, api_data, chart_path)
    print(f"  → {chart_path}")

    print(f"\n  Deployment modes: single binary + Docker (source) + Docker (images) + API-only")
    print(f"  REST API endpoints: {api_data['total_endpoints']}")
    print(f"  Docker services: {len(set(s['name'] for s in docker_data['services']))}")


if __name__ == "__main__":
    main()

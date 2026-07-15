#!/usr/bin/env python3
"""
Extract AIG Go+Python Hybrid Architecture

Analyzes the language split: Go (core platform) vs Python (LLM agents):
- Task type → language mapping (AI-Infra-Scan: Go, Mcp-Scan: Python, etc.)
- Subprocess invocation pattern (Go spawns Python via exec.Command)
- Inter-process communication via stdout/stderr callback
- Virtual environment isolation per Python sub-project
- Shared YAML rule format across language boundary
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
TASKS_GO = BASE / "common/agent/tasks.go"
TYPES_GO = BASE / "common/agent/types.go"
MCP_TASK_GO = BASE / "common/agent/mcp_task.go"
PROMPT_TASK_GO = BASE / "common/agent/prompt_tasks.go"
AGENT_TASK_GO = BASE / "common/agent/agent_task.go"
SKILL_TASK_GO = BASE / "common/agent/skill_task.go"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_task_types(filepath):
    """Extract task type constants"""
    text = filepath.read_text()
    types = []
    for m in re.finditer(r'TaskType(\w+)\s*=\s*"([^"]+)"', text):
        types.append({"name": m.group(1), "value": m.group(2)})
    return types


def extract_python_invocation(filepath, task_name):
    """Extract Python subprocess invocation patterns"""
    text = filepath.read_text()

    invocations = {
        "task_name": task_name,
        "uses_exec_command": "exec.Command" in text,
        "python_command": None,
        "script_path": None,
        "args_extracted": [],
        "stdout_capture": "StdoutPipe" in text or "Output()" in text,
        "stderr_capture": "StderrPipe" in text,
        "env_vars": [],
        "callback_writer": "tmpWriter" in text or "CallbackWriteLog" in text,
    }

    # Find exec.Command patterns
    for m in re.finditer(r'exec\.Command\(\s*"([^"]+)"(.*?)\)', text, re.DOTALL):
        cmd = m.group(1)
        args = m.group(2).strip()
        if "python" in cmd.lower() or "uv" in cmd.lower():
            invocations["python_command"] = cmd
            # extract script path
            script_match = re.search(r'"([^"]*\.py)"', args)
            if script_match:
                invocations["script_path"] = script_match.group(1)
            # extract args
            for arg_m in re.finditer(r'"([^"]+)"', args):
                arg = arg_m.group(1)
                if not arg.endswith('.py') and arg not in ['python', 'python3', 'uv', 'run']:
                    invocations["args_extracted"].append(arg)
            break

    # Environment variables
    for m in re.finditer(r'os\.Setenv\("([^"]+)"', text):
        invocations["env_vars"].append(m.group(1))
    for m in re.finditer(r'cmd\.Env\s*=\s*append.*?"([^"]+)="', text):
        invocations["env_vars"].append(m.group(1))

    return invocations


def extract_go_only_tasks():
    """Identify tasks that run purely in Go (no Python subprocess)"""
    return {
        "AI-Infra-Scan": {
            "language": "Go",
            "execution": "Direct function call to Runner.RunEnumeration()",
            "no_subprocess": True,
            "components": ["common/runner/runner.go", "common/fingerprints/preload/preload.go", "pkg/vulstruct/advisory.go"],
        }
    }


def make_chart(task_mapping, outfile):
    """Generate Go vs Python task distribution"""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Language distribution
    labels = []
    sizes = []
    colors = []
    for task, info in task_mapping.items():
        lang = info.get("language", "Go")
        if lang not in [l for l in labels]:
            labels.append(lang)
            sizes.append(1)
            colors.append('#4ECDC4' if lang == 'Go' else '#FF6B6B')
        else:
            idx = labels.index(lang)
            sizes[idx] += 1

    axes[0].pie(sizes, labels=labels, autopct='%1.0f%%', colors=colors)
    axes[0].set_title("Task Language Distribution", fontsize=12, fontweight='bold')

    # IPC pattern
    ipc_labels = ['exec.Command\n(subprocess)', 'Direct call\n(no subprocess)', 'stdout/stderr\ncallback', 'Env vars\ninjection']
    ipc_values = [
        sum(1 for t in task_mapping.values() if t.get("uses_exec_command", False)),
        sum(1 for t in task_mapping.values() if t.get("no_subprocess", False)),
        sum(1 for t in task_mapping.values() if t.get("stdout_capture", False) or t.get("callback_writer", False)),
        sum(1 for t in task_mapping.values() if t.get("env_vars", [])),
    ]
    colors2 = ['#45B7D1', '#98D8C8', '#FFA07A', '#F7DC6F']
    axes[1].bar(ipc_labels, ipc_values, color=colors2)
    axes[1].set_title("Go→Python IPC Patterns", fontsize=12, fontweight='bold')
    axes[1].set_ylabel("Count")

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Go+Python Hybrid Architecture ===\n")

    task_types = extract_task_types(TYPES_GO)
    go_tasks = extract_go_only_tasks()

    # Analyze Python-invoking tasks
    python_tasks = {}
    for name, filepath in [("Mcp-Scan", MCP_TASK_GO), ("Model-Redteam-Report", PROMPT_TASK_GO),
                            ("Agent-Scan", AGENT_TASK_GO), ("Skill-Scan", SKILL_TASK_GO)]:
        if filepath.exists():
            inv = extract_python_invocation(filepath, name)
            inv["language"] = "Python (subprocess)"
            python_tasks[name] = inv

    all_tasks = {**go_tasks, **python_tasks}

    result = {
        "scenario": "Go+Python Hybrid Architecture",
        "source_files": ["common/agent/tasks.go", "common/agent/types.go", "common/agent/mcp_task.go",
                         "common/agent/prompt_tasks.go", "common/agent/agent_task.go", "common/agent/skill_task.go"],
        "task_type_definitions": task_types,
        "task_language_mapping": {k: {"language": v.get("language", "Go"),
                                        "python_command": v.get("python_command"),
                                        "script_path": v.get("script_path"),
                                        "uses_subprocess": v.get("uses_exec_command", False) or not v.get("no_subprocess", False)}
                                   for k, v in all_tasks.items()},
        "ipc_patterns": {
            "subprocess_invocation": "exec.Command with stdout/stderr pipe",
            "streaming_output": "tmpWriter wraps callback to stream Python stdout line-by-line",
            "env_injection": "Python sub-projects receive config via os.Setenv / cmd.Env",
            "shared_data_format": "YAML rule files in data/ are the contract between Go and Python",
        },
        "design_pattern": "Language Split by Concern: Go (high-concurrency network probing, web platform) + Python (LLM agent loops, evaluation frameworks)",
        "key_design_decisions": [
            "Go handles all network I/O: HTTP fingerprinting, CVE matching, WebSocket server, task scheduling",
            "Python handles all LLM interaction: MCP code audit, prompt security eval, agent workflow testing",
            "IPC via subprocess stdout streaming: Go wraps Python process with tmpWriter to capture output line-by-line",
            "No shared memory or RPC: Go and Python communicate only through process boundary + YAML data files",
            "Each Python sub-project has its own virtualenv (uv for AIG-PromptSecurity, pip for others)",
            "Task type string (e.g., 'Mcp-Scan') is the routing key from WebSocket to specific handler",
        ],
    }

    json_path = RESULTS / "hybrid_arch.json"
    csv_path = RESULTS / "hybrid_arch.csv"
    chart_path = RESULTS / "hybrid_arch.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("task_name,language,uses_subprocess,python_command,script_path\n")
        for name, info in all_tasks.items():
            f.write(f"{name},{info.get('language','Go')},{info.get('uses_exec_command',False) or not info.get('no_subprocess',False)},{info.get('python_command','')},{info.get('script_path','')}\n")
    print(f"  → {csv_path}")

    make_chart(all_tasks, chart_path)
    print(f"  → {chart_path}")

    go_count = sum(1 for v in all_tasks.values() if v.get("language") == "Go")
    py_count = sum(1 for v in all_tasks.values() if "Python" in v.get("language", ""))
    print(f"\n  Go-only tasks: {go_count}, Python-subprocess tasks: {py_count}")
    print(f"  Total task types: {len(task_types)}")


if __name__ == "__main__":
    main()

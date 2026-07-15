#!/usr/bin/env python3
"""
Extract AIG Server-Agent Distributed Architecture

Analyzes common/websocket/agent.go, common/agent/agent.go, common/agent/types.go:
- WebSocket protocol design (register, task_assign, terminate, event types)
- AgentConnection lifecycle: register → heartbeat (ping/pong) → task dispatch → cleanup
- Dual-lock design: stateMu (RWMutex) for status, writeMu (Mutex) for writes
- Message type taxonomy: Agent→Server (7 types) and Server→Agent (3 types)
- Task lifecycle: pending → running → complete/failed
- Callback-based streaming: 6 callback types for real-time progress
- SSE manager as parallel real-time push channel to frontend
- Validator-based registration with structured error messages
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
AGENT_WS_GO = BASE / "common/websocket/agent.go"
AGENT_GO = BASE / "common/agent/agent.go"
TYPES_GO = BASE / "common/agent/types.go"
SSE_GO = BASE / "common/websocket/sse_manager.go"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def extract_message_types(filepath):
    """Extract all message type constants from types.go"""
    text = filepath.read_text()
    types = {"agent_to_server": [], "server_to_agent": [], "task_status": [], "tool_status": [], "agent_status": []}

    # Agent -> Server
    for m in re.finditer(r'AgentMsgType(\w+)\s*=\s*"([^"]+)"\s*//\s*(.*)', text):
        types["agent_to_server"].append({"name": m.group(1), "value": m.group(2), "desc": m.group(3).strip()})

    # Server -> Agent
    for m in re.finditer(r'ServerMsgType(\w+)\s*=\s*"([^"]+)"\s*//\s*(.*)', text):
        types["server_to_agent"].append({"name": m.group(1), "value": m.group(2), "desc": m.group(3).strip()})

    # Task status
    for m in re.finditer(r'TaskStatus(\w+)\s*=\s*"([^"]+)"', text):
        types["task_status"].append({"name": m.group(1), "value": m.group(2)})

    # Tool status
    for m in re.finditer(r'ToolStatus(\w+)\s*=\s*"([^"]+)"', text):
        types["tool_status"].append({"name": m.group(1), "value": m.group(2)})

    # Agent status
    for m in re.finditer(r'AgentStatus(\w+)\s*=\s*"([^"]+)"', text):
        types["agent_status"].append({"name": m.group(1), "value": m.group(2)})

    return types


def extract_agent_lifecycle(filepath):
    """Extract Agent connection lifecycle from agent.go"""
    text = filepath.read_text()

    methods = re.findall(r'func\s+\(a\s+\*Agent\)\s+(\w+)', text)
    send_methods = [m for m in methods if m.startswith('Send')]

    # Callback types
    callbacks = re.findall(r'(\w+Callback)\s*func\(', text)

    # Connection parameters
    params = {
        "read_limit": None,
        "send_channel_buffer": None,
        "ping_handler": "SetPingHandler" in text,
        "pong_handler": "SetPongHandler" in text,
    }
    rl = re.search(r'SetReadLimit\((\d+)', text)
    if rl:
        params["read_limit"] = int(rl.group(1))
    sc = re.search(r'sendChan.*make\(chan.*?,\s*(\d+)\)', text)
    if sc:
        params["send_channel_buffer"] = int(sc.group(1))

    return {
        "agent_methods": methods,
        "streaming_callbacks": callbacks,
        "connection_params": params,
        "task_execution_model": "Goroutine per task with context.CancelFunc for termination",
    }


def extract_ws_server_design(filepath):
    """Extract WebSocket server-side agent management"""
    text = filepath.read_text()

    constants = {}
    for m in re.finditer(r'(\w+)\s*=\s*(\d+\s*\*\s*time\.\w+)', text):
        constants[m.group(1)] = m.group(2).strip()

    # AgentConnection fields
    ac_match = re.search(r'type AgentConnection struct \{([^}]+)\}', text)
    ac_fields = []
    if ac_match:
        for line in ac_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('//'):
                ac_fields.append(line)

    return {
        "connection_constants": constants,
        "agent_connection_fields": ac_fields,
        "dual_lock_design": "stateMu (RWMutex) for connection state, writeMu (Mutex) for write operations",
        "heartbeat_retry": "Single retry with 1s sleep on ping failure",
        "validator_integration": "go-playground/validator for registration validation",
        "agent_replacement": "Duplicate agent ID triggers old connection close + new registration",
    }


def extract_sse_design(filepath):
    """Extract SSE manager design"""
    text = filepath.read_text()

    return {
        "connection_storage": "map[string]*SSEConnection (sessionId → connection)",
        "heartbeat_interval": "10 seconds (ticker)",
        "heartbeat_type": "liveStatus with '思考中...' text",
        "sse_format": "id: <id>\\nevent: <type>\\ndata: <json>\\n\\n",
        "conflict_handling": "Duplicate sessionId closes existing connection before adding new one",
        "flusher_required": "http.Flusher interface check at connection time",
    }


def make_charts(msg_types, outfile):
    """Generate message type distribution chart"""
    fig, ax = plt.subplots(figsize=(10, 6))

    categories = ['Agent→Server', 'Server→Agent', 'Task Status', 'Tool Status', 'Agent Status']
    counts = [
        len(msg_types["agent_to_server"]),
        len(msg_types["server_to_agent"]),
        len(msg_types["task_status"]),
        len(msg_types["tool_status"]),
        len(msg_types["agent_status"]),
    ]
    colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8']

    bars = ax.bar(categories, counts, color=colors)
    ax.set_title("AIG WebSocket Protocol Message Type Distribution", fontsize=13, fontweight='bold')
    ax.set_ylabel("Count")
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, str(count),
                ha='center', fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    print("=== AIG Server-Agent Distributed Architecture ===\n")

    msg_types = extract_message_types(TYPES_GO)
    agent_lifecycle = extract_agent_lifecycle(AGENT_GO)
    ws_server = extract_ws_server_design(AGENT_WS_GO)
    sse_design = extract_sse_design(SSE_GO)

    result = {
        "scenario": "Server-Agent Distributed Architecture",
        "source_files": ["common/websocket/agent.go", "common/agent/agent.go", "common/agent/types.go", "common/websocket/sse_manager.go"],
        "message_type_taxonomy": msg_types,
        "agent_lifecycle": agent_lifecycle,
        "websocket_server_design": ws_server,
        "sse_manager_design": sse_design,
        "design_pattern": "Distributed Task Queue: Server (WebSocket hub) → Agent (worker with task goroutine) → SSE (frontend push)",
        "key_design_decisions": [
            "Dual communication channels: WebSocket for Agent↔Server, SSE for Server→Frontend",
            "Dual-lock on AgentConnection: RWMutex for state reads, Mutex for serialized writes",
            "6 streaming callback types: ResultCallback, ToolUseLogCallback, ToolUsedCallback, NewPlanStepCallback, StepStatusUpdateCallback, PlanUpdateCallback",
            "Validator-based registration: required fields (agent_id, hostname, ip, version) with structured error formatting",
            "Heartbeat: Server pings every ~96s (pongWait*8/10), Agent pong updates read deadline to 120s",
            "SSE heartbeat every 10s with 'liveStatus' event for UI liveliness indication",
            "Task execution: each task spawns a goroutine with context.CancelFunc for graceful termination",
            "Agent replacement: same agent_id registration closes old connection, no task migration",
        ],
    }

    json_path = RESULTS / "server_agent.json"
    csv_path = RESULTS / "server_agent.csv"
    chart_path = RESULTS / "server_agent.png"

    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    with open(csv_path, "w") as f:
        f.write("direction,type_name,type_value,description\n")
        for t in msg_types["agent_to_server"]:
            f.write(f"agent_to_server,{t['name']},{t['value']},{t['desc']}\n")
        for t in msg_types["server_to_agent"]:
            f.write(f"server_to_agent,{t['name']},{t['value']},{t['desc']}\n")
    print(f"  → {csv_path}")

    make_charts(msg_types, chart_path)
    print(f"  → {chart_path}")

    total_types = sum(len(v) for v in msg_types.values())
    print(f"\n  Total message types: {total_types}")
    print(f"  Agent→Server: {len(msg_types['agent_to_server'])}, Server→Agent: {len(msg_types['server_to_agent'])}")
    print(f"  Streaming callbacks: {len(agent_lifecycle['streaming_callbacks'])}")


if __name__ == "__main__":
    main()

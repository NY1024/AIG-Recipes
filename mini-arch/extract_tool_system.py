#!/usr/bin/env python3
"""
Scene 12: Agent Tool System & XML Schema Registry
Extracts the decorator-based tool registration system and XML schema design.
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
TOOLS_DIR = AGENT_SCAN_DIR / "tools"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_tool_registry():
    """Analyze the tool registration system"""
    registry_text = (TOOLS_DIR / "registry.py").read_text()

    # Registry functions
    functions = re.findall(r'def (\w+)\(', registry_text)

    # Registration decorator
    uses_decorator = "register_tool" in registry_text
    uses_wraps = "wraps" in registry_text
    uses_inspect = "inspect" in registry_text

    # Tool storage
    global_list = "tools" in registry_text and "list" in registry_text
    global_dict = "_tools_by_name" in registry_text

    # Schema loading
    uses_xml_schema = "xml_schema" in registry_text
    uses_schema_file = "schema_file" in registry_text

    # Signature inspection
    checks_agent_state = "needs_agent_state" in registry_text
    checks_context = "needs_context" in registry_text
    checks_sandbox = "should_execute_in_sandbox" in registry_text

    return {
        "functions": functions,
        "uses_decorator_pattern": uses_decorator,
        "uses_wraps": uses_wraps,
        "uses_inspect_module": uses_inspect,
        "global_list_storage": global_list,
        "global_dict_storage": global_dict,
        "xml_schema_loading": uses_xml_schema,
        "schema_file_loading": uses_schema_file,
        "checks_agent_state": checks_agent_state,
        "checks_context": checks_context,
        "checks_sandbox": checks_sandbox,
    }


def analyze_registered_tools():
    """Find all registered tools across the codebase"""
    tools_found = []

    for py_file in TOOLS_DIR.rglob("*.py"):
        if py_file.name == "registry.py" or py_file.name.startswith("__"):
            continue
        text = py_file.read_text()
        # Find @register_tool decorated functions
        matches = re.findall(r'@register_tool\s*\nasync def (\w+)\(', text)
        if not matches:
            matches = re.findall(r'@register_tool\s*\ndef (\w+)\(', text)
        for m in matches:
            # Check sandbox_execution parameter
            sandbox_match = re.search(r'@register_tool\([^)]*sandbox_execution\s*=\s*(True|False)', text)
            sandbox = bool(sandbox_match.group(1)) if sandbox_match else True
            tools_found.append({
                "name": m,
                "module": py_file.parent.name,
                "sandbox_execution": sandbox,
                "file": str(py_file.relative_to(TOOLS_DIR)),
            })

    return tools_found


def analyze_xml_schemas():
    """Analyze XML schema files"""
    schemas = []
    for xml_file in TOOLS_DIR.rglob("*_schema.xml"):
        text = xml_file.read_text()
        # Extract tool names
        tool_names = re.findall(r'<tool name="([^"]+)">', text)
        # Extract parameters
        params = re.findall(r'<parameter name="([^"]+)"[^>]*type="([^"]+)"', text)
        # Extract description length
        desc_match = re.search(r'<description>(.*?)</description>', text, re.DOTALL)
        desc_len = len(desc_match.group(1).strip()) if desc_match else 0

        schemas.append({
            "file": xml_file.name,
            "module": xml_file.parent.name,
            "tool_names": tool_names,
            "param_count": len(params),
            "params": [(p[0], p[1]) for p in params],
            "description_length": desc_len,
        })
    return schemas


def analyze_dispatcher():
    """Analyze tool dispatch logic"""
    disp_text = (TOOLS_DIR / "dispatcher.py").read_text()
    functions = re.findall(r'def (\w+)\(', disp_text)
    return {
        "functions": functions,
        "uses_registry": "registry" in disp_text or "get_tool_by_name" in disp_text,
        "has_error_handling": "except" in disp_text,
    }


def make_charts(registry_info, tools, schemas, disp_info, outfile):
    """Generate tool system chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Tools per module
    module_counts = Counter(t["module"] for t in tools)
    mlabels = list(module_counts.keys())
    mvalues = list(module_counts.values())
    colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE']
    axes[0].bar(mlabels, mvalues, color=colors[:len(mlabels)])
    axes[0].set_title(f"Registered Tools per Module ({len(tools)} total)", fontsize=12, fontweight='bold')
    axes[0].set_ylabel("Tool Count")
    for i, v in enumerate(mvalues):
        axes[0].text(i, v + 0.1, str(v), ha='center', fontsize=13, fontweight='bold')
    plt.setp(axes[0].xaxis.get_majorticklabels(), rotation=20, ha='right', fontsize=10)

    # XML schema parameter counts
    if schemas:
        schema_names = [s["file"].replace("_schema.xml", "") for s in schemas]
        param_counts = [s["param_count"] for s in schemas]
        colors2 = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2']
        bars = axes[1].barh(schema_names, param_counts, color=colors2[:len(schema_names)])
        axes[1].set_title("XML Schema: Parameter Count per Tool", fontsize=12, fontweight='bold')
        axes[1].set_xlabel("Parameter Count")
        for bar, v in zip(bars, param_counts):
            axes[1].text(v + 0.1, bar.get_y() + bar.get_height()/2, str(v), va='center', fontsize=11)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    registry_info = analyze_tool_registry()
    tools = analyze_registered_tools()
    schemas = analyze_xml_schemas()
    disp_info = analyze_dispatcher()

    data = {
        "registry_system": registry_info,
        "registered_tools": tools,
        "xml_schemas": schemas,
        "dispatcher": disp_info,
    }

    with open(RESULTS / "tool_system.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "tool_system.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Tool Name", "Module", "Sandbox", "Param Count"])
        # Map tools to their schema params
        tool_param_map = {}
        for s in schemas:
            for tn in s["tool_names"]:
                tool_param_map[tn] = s["param_count"]
        for t in tools:
            writer.writerow([t["name"], t["module"], t["sandbox_execution"], tool_param_map.get(t["name"], "?")])

    make_charts(registry_info, tools, schemas, disp_info, RESULTS / "tool_system.png")
    print("Done: tool_system")


if __name__ == "__main__":
    main()

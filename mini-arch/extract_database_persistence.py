#!/usr/bin/env python3
"""
Scene 9: Database Persistence & Task State Machine
Extracts data model, state transitions, indexes, and event sourcing patterns.
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
DB_DIR = BASE / "pkg" / "database"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_data_model():
    """Analyze database model definitions"""
    model_text = (DB_DIR / "model.go").read_text()
    task_text = (DB_DIR / "task.go").read_text()
    agent_text = (DB_DIR / "agent.go").read_text()
    config_text = (DB_DIR / "config.go").read_text()

    models = []
    for m in re.finditer(r'type (\w+) struct \{([^}]+)\}', model_text + task_text + agent_text + config_text):
        name = m.group(1)
        body = m.group(2)
        fields = re.findall(r'(\w+)\s+\S+\s+`gorm:"([^"]+)"', body)
        field_count = len(fields)
        # Check for relationships
        has_foreign_key = 'foreignKey' in body
        has_json = 'json:' in body
        has_yaml = 'yaml:' in body
        models.append({
            "name": name,
            "field_count": field_count,
            "has_foreign_key": has_foreign_key,
            "has_json_tag": has_json,
            "has_yaml_tag": has_yaml,
            "fields": [f[0] for f in fields],
        })
    return models


def analyze_state_machine():
    """Analyze task state transitions"""
    task_text = (DB_DIR / "task.go").read_text()

    # Find all status values
    statuses = set()
    for m in re.finditer(r"status.*?['\"](\w+)['\"]", task_text):
        statuses.add(m.group(1))
    for m in re.finditer(r"Status.*?default:'(\w+)'", task_text):
        statuses.add(m.group(1))

    # Find state transitions
    transitions = []
    for m in re.finditer(r'UpdateSessionStatus.*?"(\w+)"', task_text):
        transitions.append(m.group(1))
    for m in re.finditer(r'"status":\s*"(\w+)"', task_text):
        transitions.append(m.group(1))

    # Find ResetRunningTasks
    reset_found = "ResetRunningTasks" in task_text
    reset_query = ""
    if reset_found:
        m = re.search(r'ResetRunningTasks.*?Where\("([^"]+)"', task_text, re.DOTALL)
        if m:
            reset_query = m.group(1)

    # Find transaction usage
    transaction_count = task_text.count("Transaction")

    # Find store methods
    store_methods = re.findall(r'func \(s \*(\w+)\) (\w+)\(', task_text)

    return {
        "all_statuses": sorted(statuses),
        "transitions": transitions,
        "reset_on_startup": reset_found,
        "reset_query": reset_query,
        "transaction_count": transaction_count,
        "store_method_count": len(store_methods),
        "stores": list(set(m[1] for m in store_methods)),
    }


def analyze_indexes():
    """Analyze database indexes"""
    task_text = (DB_DIR / "task.go").read_text()
    model_text = (DB_DIR / "model.go").read_text()

    indexes = []
    for m in re.finditer(r'CREATE INDEX IF NOT EXISTS (\S+) ON (\w+)\(([^)]+)\)', task_text + model_text):
        indexes.append({
            "name": m.group(1),
            "table": m.group(2),
            "columns": m.group(3),
        })
    return indexes


def analyze_event_sourcing():
    """Analyze event sourcing patterns"""
    task_text = (DB_DIR / "task.go").read_text()

    # Find StoreEvent and event-related methods
    event_methods = re.findall(r'func \(s \*TaskStore\) (\w*[Ee]vent\w*|Store\w+|Get\w*Events?\w*)\(', task_text)
    message_types = set()
    for m in re.findall(r'"type".*?"(\w+)"', task_text):
        message_types.add(m)

    # Check for datatypes.JSON usage
    json_fields = re.findall(r'datatypes\.JSON.*?column:(\w+)', task_text)

    return {
        "event_methods": event_methods,
        "message_types_hint": sorted(message_types),
        "json_fields": json_fields,
        "uses_datatypes_json": "datatypes.JSON" in task_text,
        "uses_preload": task_text.count("Preload("),
    }


def make_charts(models, state_info, indexes, event_info, outfile):
    """Generate database architecture chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Model field counts and types
    model_names = [m["name"] for m in models if m["name"] not in ("ModelParams",)]
    field_counts = [m["field_count"] for m in models if m["name"] not in ("ModelParams",)]
    colors = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE']
    bars = axes[0].barh(model_names, field_counts, color=colors[:len(model_names)])
    axes[0].set_title("GORM Data Model: Field Count per Entity", fontsize=12, fontweight='bold')
    axes[0].set_xlabel("Field Count")
    for bar, v in zip(bars, field_counts):
        axes[0].text(v + 0.3, bar.get_y() + bar.get_height()/2, str(v), va='center', fontsize=11)

    # Index distribution by table
    if indexes:
        table_counts = Counter(i["table"] for i in indexes)
        tlabels = list(table_counts.keys())
        tvalues = list(table_counts.values())
        axes[1].bar(tlabels, tvalues, color=['#4ECDC4', '#FF6B6B', '#45B7D1'][:len(tlabels)])
        axes[1].set_title(f"Database Indexes by Table ({len(indexes)} total)", fontsize=12, fontweight='bold')
        axes[1].set_ylabel("Index Count")
        for i, v in enumerate(tvalues):
            axes[1].text(i, v + 0.1, str(v), ha='center', fontsize=13, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    models = analyze_data_model()
    state_info = analyze_state_machine()
    indexes = analyze_indexes()
    event_info = analyze_event_sourcing()

    data = {
        "models": models,
        "state_machine": state_info,
        "indexes": indexes,
        "event_sourcing": event_info,
    }

    with open(RESULTS / "database_persistence.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "database_persistence.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Model", "Fields", "Has FK", "Has JSON", "Has YAML"])
        for m in models:
            writer.writerow([m["name"], m["field_count"], m["has_foreign_key"], m["has_json_tag"], m["has_yaml_tag"]])

    make_charts(models, state_info, indexes, event_info, RESULTS / "database_persistence.png")
    print("Done: database_persistence")


if __name__ == "__main__":
    main()

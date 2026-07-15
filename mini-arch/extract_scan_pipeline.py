#!/usr/bin/env python3
"""
Scene 14: Agent Scan Pipeline & Three-Stage Detection Workflow
Extracts the recon → parallel detection → review pipeline from agent-scan/core/agent.py.
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
CORE_DIR = AGENT_SCAN_DIR / "core"
PROMPT_DIR = AGENT_SCAN_DIR / "prompt"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_pipeline():
    """Analyze the three-stage scan pipeline"""
    agent_text = (CORE_DIR / "agent.py").read_text()

    # Detection skills
    skills_match = re.search(r'_DETECTION_SKILLS.*?=\s*\[([^\]]*?)\]', agent_text, re.DOTALL)
    skills = []
    if skills_match:
        skills = re.findall(r'"([^"]+)"', skills_match.group(1))

    # Pipeline stages
    stages = re.findall(r'ScanStage\("(\w+)",\s*"([^"]+)",\s*"([^"]+)"', agent_text)

    # Concurrency control
    worker_concurrency_match = re.search(r'_WORKER_CONCURRENCY.*?=\s*(\d+)', agent_text)
    worker_concurrency = int(worker_concurrency_match.group(1)) if worker_concurrency_match else 0

    # Uses semaphore
    uses_semaphore = "Semaphore" in agent_text
    uses_gather = "gather" in agent_text
    uses_return_exceptions = "return_exceptions=True" in agent_text

    # Error resilience
    has_exception_handling = "Exception" in agent_text
    has_skip_on_failure = "skipped" in agent_text or "will be skipped" in agent_text

    # Report generation
    has_report_gen = "generate_report" in agent_text
    has_language_detect = "analyze_language" in agent_text

    # Classes
    classes = re.findall(r'class (\w+)', agent_text)

    # Worker ID pattern
    worker_id_pattern = re.search(r"'2'|_WORKER_STAGE_ID_PREFIX.*?=\s*['\"](\w)['\"]", agent_text)

    return {
        "detection_skills": skills,
        "pipeline_stages": [{"id": s[0], "name": s[1], "template": s[2]} for s in stages],
        "worker_concurrency": worker_concurrency,
        "uses_semaphore": uses_semaphore,
        "uses_asyncio_gather": uses_gather,
        "uses_return_exceptions": uses_return_exceptions,
        "has_exception_handling": has_exception_handling,
        "skips_failed_workers": has_skip_on_failure,
        "has_report_generation": has_report_gen,
        "has_language_detection": has_language_detect,
        "classes": classes,
    }


def analyze_skill_detectors():
    """Analyze the SKILL.md detection rule files"""
    skills_dir = PROMPT_DIR / "skills"
    skills = []

    for skill_dir in sorted(skills_dir.iterdir()) if skills_dir.exists() else []:
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        text = skill_md.read_text()

        # Extract skill name/description
        name_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
        name = name_match.group(1).strip() if name_match else skill_dir.name

        # Count dialogue test vectors
        dialogue_count = len(re.findall(r'##\s+对话|##\s+Dialogue|user:\s|assistant:', text, re.IGNORECASE))

        # Count table test vectors
        table_count = len(re.findall(r'\|.*role.*\|.*content.*\|', text, re.IGNORECASE))

        # Extract detection categories
        categories = re.findall(r'OWASP.*?(\w+)|风险类型.*?[:：]\s*(\w+)', text)

        # File size
        file_size = len(text)

        # Count sections
        sections = len(re.findall(r'^##\s+', text, re.MULTILINE))

        skills.append({
            "name": skill_dir.name,
            "display_name": name,
            "file_size": file_size,
            "section_count": sections,
            "dialogue_vectors": dialogue_count,
            "table_vectors": table_count,
        })

    return skills


def analyze_prompt_templates():
    """Analyze system prompt templates"""
    system_dir = PROMPT_DIR / "system"
    templates = []

    for md_file in sorted(system_dir.glob("*.md")):
        text = md_file.read_text()
        templates.append({
            "file": md_file.name,
            "size": len(text),
            "sections": len(re.findall(r'^##\s+', text, re.MULTILINE)),
        })

    # Also check agents subdirectory
    agents_dir = system_dir / "agents"
    if agents_dir.exists():
        for md_file in sorted(agents_dir.glob("*.md")):
            text = md_file.read_text()
            templates.append({
                "file": f"agents/{md_file.name}",
                "size": len(text),
                "sections": len(re.findall(r'^##\s+', text, re.MULTILINE)),
            })

    return templates


def make_charts(pipeline_info, skills, templates, outfile):
    """Generate pipeline architecture chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Pipeline stages
    stages = pipeline_info["pipeline_stages"]
    if stages:
        stage_labels = [f"Stage {s['id']}\n{s['name']}" for s in stages]
        colors = ['#4ECDC4', '#FF6B6B', '#F7DC6F']
        axes[0].barh(stage_labels, [1]*len(stages), color=colors[:len(stages)], edgecolor='navy', linewidth=0.5)
        axes[0].set_title("Three-Stage Scan Pipeline", fontsize=12, fontweight='bold')
        axes[0].set_xlabel("Execution Order →")
        axes[0].set_xlim(0, 1.5)

        # Annotate with details
        annotations = [
            f"Sequential\n1 agent",
            f"{'Parallel' if pipeline_info['uses_semaphore'] else 'Sequential'}\n{pipeline_info['worker_concurrency']} workers",
            f"Sequential\n1 agent"
        ]
        for i, ann in enumerate(annotations[:len(stages)]):
            axes[0].text(0.02, i, ann, va='center', fontsize=9, color='white', fontweight='bold')

    # Skill detector sizes
    if skills:
        skill_names = [s["name"][:20] for s in skills]
        skill_sizes = [s["file_size"] / 1000 for s in skills]  # KB
        colors2 = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#73C6B6', '#F1948A']
        bars = axes[1].barh(skill_names, skill_sizes, color=colors2[:len(skills)])
        axes[1].set_title("Detection Skill Rule Files (KB)", fontsize=12, fontweight='bold')
        axes[1].set_xlabel("File Size (KB)")
        for bar, v in zip(bars, skill_sizes):
            axes[1].text(v + 0.1, bar.get_y() + bar.get_height()/2, f'{v:.1f}KB', va='center', fontsize=10)

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    pipeline_info = analyze_pipeline()
    skills = analyze_skill_detectors()
    templates = analyze_prompt_templates()

    data = {
        "pipeline": pipeline_info,
        "skill_detectors": skills,
        "prompt_templates": templates,
    }

    with open(RESULTS / "scan_pipeline.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "scan_pipeline.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Skill", "Size (bytes)", "Sections", "Dialogue Vectors", "Table Vectors"])
        for s in skills:
            writer.writerow([s["name"], s["file_size"], s["section_count"], s["dialogue_vectors"], s["table_vectors"]])

    make_charts(pipeline_info, skills, templates, RESULTS / "scan_pipeline.png")
    print("Done: scan_pipeline")


if __name__ == "__main__":
    main()

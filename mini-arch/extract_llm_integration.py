#!/usr/bin/env python3
"""
Scene 11: LLM Integration & Screenshot-Based Sensitivity Analysis
Extracts the LLM-augmented sensitive info detection pipeline from runner/ai.go.
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
RUNNER_DIR = BASE / "common" / "runner"
MODELS_DIR = BASE / "common" / "utils" / "models"
RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def analyze_ai_pipeline():
    """Analyze the AI-augmented sensitive info detection pipeline"""
    ai_text = (RUNNER_DIR / "ai.go").read_text()

    # Extract prompt structure
    sensitive_prompt = re.search(r'LoadSensitivePrompt.*?`([^`]+)`', ai_text, re.DOTALL)
    screenshot_prompt = re.search(r'LoadWebPageScreenShotSummary.*?`([^`]+)`', ai_text, re.DOTALL)

    # Analyze sensitive prompt structure
    prompt_sections = []
    if sensitive_prompt:
        prompt_text = sensitive_prompt.group(1)
        # Find section headers
        sections = re.findall(r'\[([^\]]+)\]', prompt_text)
        prompt_sections = sections

    # Find template variables
    template_vars = re.findall(r'\{\{(\w+)\}\}', ai_text)

    # Find severity levels
    severity_levels = re.findall(r'low|medium|high', ai_text, re.IGNORECASE)

    # Find XML output tags
    xml_tags = re.findall(r'<(\w+)>', ai_text)

    # Pipeline steps
    pipeline_steps = []
    if 'ScreenShot' in ai_text:
        pipeline_steps.append("Chromium Screenshot Capture")
    if 'ChatWithImageByte' in ai_text:
        pipeline_steps.append("Vision LLM: Screenshot Analysis")
    if 'ChatStream' in ai_text:
        pipeline_steps.append("Streaming LLM: Sensitive Info Analysis")
    if 'extractTag' in ai_text:
        pipeline_steps.append("XML Tag Extraction")

    # Find functions
    functions = re.findall(r'func (\w+)\(', ai_text)

    return {
        "pipeline_steps": pipeline_steps,
        "prompt_sections": prompt_sections,
        "template_variables": template_vars,
        "severity_levels": list(set(severity_levels)),
        "xml_output_tags": list(set(xml_tags)),
        "functions": functions,
        "uses_screenshot": "ScreenShot" in ai_text,
        "uses_vision_llm": "ChatWithImageByte" in ai_text,
        "uses_streaming": "ChatStream" in ai_text,
    }


def analyze_llm_client():
    """Analyze the OpenAI-compatible LLM client"""
    llm_text = (MODELS_DIR / "openai.go").read_text()

    # Methods
    methods = re.findall(r'func \(m \*OpenAI\) (\w+)\(', llm_text)

    # API patterns
    has_streaming = "Stream" in llm_text
    has_vision = "Image" in llm_text or "image" in llm_text
    has_chat = "Chat" in llm_text

    # Model configuration
    config_fields = re.findall(r'json:"(\w+)"', llm_text)

    # Error handling
    error_handling_patterns = re.findall(r'(errors\.New|fmt\.Errorf)\("([^"]+)"\)', llm_text)

    return {
        "methods": methods,
        "streaming_support": has_streaming,
        "vision_support": has_vision,
        "chat_support": has_chat,
        "config_fields": list(set(config_fields)),
        "error_patterns": [e[1] for e in error_handling_patterns],
    }


def make_charts(ai_info, llm_info, outfile):
    """Generate LLM integration chart"""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    # Pipeline flow visualization
    steps = ai_info["pipeline_steps"]
    if not steps:
        steps = ["Chromium Screenshot", "Vision LLM Analysis", "Streaming LLM Analysis", "XML Extraction"]
    step_labels = [f'Step {i+1}\n{s}' for i, s in enumerate(steps)]
    colors = ['#4ECDC4', '#FF6B6B', '#F7DC6F', '#98D8C8']
    axes[0].barh(step_labels, [1]*len(steps), color=colors[:len(steps)], edgecolor='navy', linewidth=0.5)
    axes[0].set_title("LLM-Augmented Sensitivity Analysis Pipeline", fontsize=11, fontweight='bold')
    axes[0].set_xlabel("Execution Order →")
    axes[0].set_xlim(0, 1.5)
    for i in range(len(steps)):
        axes[0].text(0.02, i, f"Step {i+1}", va='center', fontsize=9, color='white', fontweight='bold')

    # Prompt template sections
    sections = ai_info["prompt_sections"]
    if sections:
        sec_labels = [s[:20].replace('角色设定','Role').replace('概念定义','Concepts').replace('评分依据','Scoring').replace('高风险案例','High-Risk').replace('低风险案例','Low-Risk').replace('系统类型判定','Type').replace('任务目标','Goal').replace('输出格式','Format') for s in sections]
        sec_values = [1] * len(sections)
        colors2 = ['#4ECDC4', '#FF6B6B', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2']
        axes[1].bar(sec_labels, sec_values, color=colors2[:len(sections)])
        axes[1].set_title(f"Prompt Template Sections ({len(sections)} sections)", fontsize=11, fontweight='bold')
        axes[1].set_ylabel("Present")
        axes[1].set_ylim(0, 1.5)
        plt.setp(axes[1].xaxis.get_majorticklabels(), rotation=30, ha='right', fontsize=9)
    else:
        axes[1].text(0.5, 0.5, 'No sections found', ha='center', va='center', fontsize=14)
        axes[1].set_title("Prompt Template Sections", fontsize=11, fontweight='bold')

    plt.tight_layout()
    plt.savefig(outfile, dpi=150, bbox_inches='tight')
    plt.close()


def main():
    ai_info = analyze_ai_pipeline()
    llm_info = analyze_llm_client()

    data = {
        "ai_pipeline": ai_info,
        "llm_client": llm_info,
    }

    with open(RESULTS / "llm_integration.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(RESULTS / "llm_integration.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Aspect", "Detail"])
        writer.writerow(["Pipeline Steps", " | ".join(ai_info["pipeline_steps"])])
        writer.writerow(["Prompt Sections", " | ".join(ai_info["prompt_sections"])])
        writer.writerow(["Template Vars", " | ".join(ai_info["template_variables"])])
        writer.writerow(["XML Tags", " | ".join(ai_info["xml_output_tags"])])
        writer.writerow(["LLM Methods", " | ".join(llm_info["methods"])])
        writer.writerow(["Streaming", llm_info["streaming_support"]])
        writer.writerow(["Vision", llm_info["vision_support"]])

    make_charts(ai_info, llm_info, RESULTS / "llm_integration.png")
    print("Done: llm_integration")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import argparse
import sys
import os
from collections import defaultdict

def normalize_text(text):
    return text.lower().strip()

def evaluate(expected_path, actual_path, output_md_path):
    with open(expected_path, 'r', encoding='utf-8') as f:
        expected_list = json.load(f)
    
    with open(actual_path, 'r', encoding='utf-8') as f:
        actual_data = json.load(f)
    
    # Extract actual findings
    actual_findings = []
    if isinstance(actual_data, list):
        actual_findings = actual_data
    elif isinstance(actual_data, dict):
        actual_findings = actual_data.get("findings", actual_data.get("vulnerabilities", []))
    
    cat_stats = defaultdict(lambda: {"expected": 0, "detected": 0})
    missed_list = []
    detected_list = []
    
    for exp in expected_list:
        cat = exp["category"]
        cat_stats[cat]["expected"] += 1
        
        # Match by file_path or CVE/CWE
        found = False
        exp_file = os.path.basename(exp["file_path"])
        exp_rule = normalize_text(exp["cwe_or_cve"])
        
        for act in actual_findings:
            act_file = os.path.basename(act.get("file_path", act.get("file", act.get("target", ""))))
            act_rule = normalize_text(str(act.get("rule_id", act.get("cve", act.get("id", "")))))
            act_desc = normalize_text(act.get("description", act.get("title", "")))
            
            if (exp_file and exp_file in act_file) or (exp_rule and exp_rule in act_rule) or (exp_rule and exp_rule in act_desc):
                found = True
                detected_list.append({"expected": exp, "actual": act})
                cat_stats[cat]["detected"] += 1
                break
        
        if not found:
            missed_list.append(exp)
            
    total_exp = len(expected_list)
    total_det = len(detected_list)
    overall_rate = (total_det / total_exp * 100) if total_exp > 0 else 0.0
    
    lines = [
        "# TigerGate True Positive Benchmark Evaluation Gap Report",
        f"**Target Report:** `{actual_path}`",
        f"**Ground Truth:** `{expected_path}`\n",
        "## 1. Executive Summary",
        f"- **Total True Positive Flaws:** {total_exp}",
        f"- **Detected by TigerGate:** {total_det}",
        f"- **Missed (False Negatives):** {len(missed_list)}",
        f"- **True Positive Detection Rate:** **{overall_rate:.1f}%**\n",
        "## 2. Detection Rate by Category",
        "| Category | Expected | Detected | Missed | Detection Rate (%) |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]
    for cat, s in sorted(cat_stats.items()):
        pct = (s["detected"] / s["expected"] * 100) if s["expected"] > 0 else 0.0
        lines.append(f"| {cat} | {s['expected']} | {s['detected']} | {s['expected'] - s['detected']} | {pct:.1f}% |")
    lines.append("")
    
    if missed_list:
        lines.append("## 3. Top Missed Vulnerabilities (False Negatives)")
        lines.append("| Test ID | Category | Subcategory | File Path | Rule / CWE | Severity |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for m in missed_list[:40]:
            lines.append(f"| {m['test_id']} | {m['category']} | {m['subcategory']} | `{m['file_path']}` | {m['cwe_or_cve']} | {m['expected_severity']} |")
        lines.append("")
        
    report = "\n".join(lines)
    if output_md_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_md_path)), exist_ok=True)
        with open(output_md_path, 'w', encoding='utf-8') as f:
            f.write(report + "\n")
        print(f"Report written to {output_md_path}")
    print(report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate TigerGate True Positive Benchmark")
    parser.add_argument("--expected", default="metadata/expected-findings.json")
    parser.add_argument("--actual", required=True)
    parser.add_argument("--output", default="reports/tigergate-detection-gap-report.md")
    args = parser.parse_args()
    evaluate(args.expected, args.actual, args.output)

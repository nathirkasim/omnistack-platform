#!/usr/bin/env python3
"""
check_new_coverage.py - Evaluate coverage strictly on advanced/ benchmark cases (including mutants).

Checks:
- Filters ground truth strictly to items located in advanced/
- Evaluates findings against advanced cases
- Reports each new TP detected vs missed
- Reports each new FP flagged
- Computes coverage % per section, per language, per technique
- Computes twin evasion delta
- Exits nonzero if any new TP is missed (--allow-misses N to override)
- Writes comprehensive new_cases_report.md
"""

import os
import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict
from score import parse_findings, match_finding_to_gt, normalize_path

REPO_ROOT = Path(__file__).resolve().parent

def get_section_from_file(file_path):
    p = normalize_path(file_path)
    if "advanced/taint" in p:
        return "deep-taint"
    elif "advanced/evasion" in p:
        return "evasion"
    elif "advanced/sca" in p:
        return "transitive-sca"
    elif "advanced/secrets-history" in p:
        return "secrets-history"
    elif "advanced/iac" in p:
        return "rendered-iac"
    elif "advanced/mutants" in p:
        return "mutants"
    return "other-advanced"

def run_coverage_check(findings_file, gt_file, allow_misses=0, output_report="new_cases_report.md"):
    with open(gt_file, "r", encoding="utf-8") as f:
        all_gt = json.load(f)

    # Filter to cases under advanced/
    advanced_gt = [g for g in all_gt if normalize_path(g["file"]).startswith("advanced/")]

    findings = parse_findings(findings_file)

    detected_tp = set()
    flagged_fp = set()

    for f in findings:
        m = match_finding_to_gt(f, advanced_gt, tolerance=3)
        if m:
            if m["type"] == "TP":
                detected_tp.add(m["id"])
            elif m["type"] == "FP":
                flagged_fp.add(m["id"])

    tp_cases = [g for g in advanced_gt if g["type"] == "TP"]
    fp_cases = [g for g in advanced_gt if g["type"] == "FP"]

    missed_tp = [g for g in tp_cases if g["id"] not in detected_tp]

    # Slices
    def slice_coverage(key_func):
        stats = defaultdict(lambda: {"tp_hit": 0, "tp_total": 0})
        for g in tp_cases:
            k = key_func(g)
            stats[k]["tp_total"] += 1
            if g["id"] in detected_tp:
                stats[k]["tp_hit"] += 1
        return stats

    section_stats = slice_coverage(lambda g: get_section_from_file(g["file"]))
    lang_stats = slice_coverage(lambda g: g.get("language", "unknown"))
    tech_stats = slice_coverage(lambda g: g.get("technique", "direct"))

    # Twin delta
    plain_tps = [g["id"] for g in tp_cases if g.get("pair_id") and g.get("technique") == "plain"]
    evasion_tps = [g["id"] for g in tp_cases if g.get("pair_id") and g.get("technique") != "plain"]

    plain_cov = sum(1 for pid in plain_tps if pid in detected_tp) / len(plain_tps) if plain_tps else 0.0
    evasion_cov = sum(1 for eid in evasion_tps if eid in detected_tp) / len(evasion_tps) if evasion_tps else 0.0
    twin_delta = plain_cov - evasion_cov

    total_tp = len(tp_cases)
    detected_count = len(detected_tp)
    coverage_pct = (detected_count / total_tp) if total_tp > 0 else 0.0

    print("=" * 65)
    print("        ADVANCED SECURITY CASES COVERAGE REPORT")
    print("=" * 65)
    print(f" Total Advanced TPs  : {total_tp}")
    print(f" Detected TPs        : {detected_count}")
    print(f" Missed TPs          : {len(missed_tp)}")
    print(f" Advanced Coverage   : {coverage_pct:.2%}")
    print(f" Flagged FP Traps    : {len(flagged_fp)} / {len(fp_cases)}")
    print(f" Twin Evasion Delta  : {twin_delta:+.2%} (Plain: {plain_cov:.1%} vs Evasion: {evasion_cov:.1%})")
    print("-" * 65)

    print("\nCoverage by Section:")
    for sec, st in sorted(section_stats.items()):
        pct = st["tp_hit"] / st["tp_total"] if st["tp_total"] > 0 else 0.0
        print(f"  - {sec:20s}: {st['tp_hit']:3d} / {st['tp_total']:3d} ({pct:6.1%})")

    print("\nCoverage by Language:")
    for lang, st in sorted(lang_stats.items()):
        pct = st["tp_hit"] / st["tp_total"] if st["tp_total"] > 0 else 0.0
        print(f"  - {lang:15s}: {st['tp_hit']:3d} / {st['tp_total']:3d} ({pct:6.1%})")

    # Write new_cases_report.md
    md_lines = []
    md_lines.append("# Advanced Security Cases Coverage Report\n")
    md_lines.append(f"**Total Advanced TPs**: {total_tp} | **Detected**: {detected_count} | **Coverage**: {coverage_pct:.2%}\n")
    md_lines.append(f"**Missed TPs**: {len(missed_tp)} | **Flagged FPs**: {len(flagged_fp)}\n")
    md_lines.append(f"**Twin Evasion Delta**: {twin_delta:+.2%} (Plain: {plain_cov:.1%} vs Evasion: {evasion_cov:.1%})\n")

    md_lines.append("\n## Section Breakdown\n")
    md_lines.append("| Section | Detected | Total | Coverage |")
    md_lines.append("| :--- | :---: | :---: | :---: |")
    for sec, st in sorted(section_stats.items()):
        pct = st["tp_hit"] / st["tp_total"] if st["tp_total"] > 0 else 0.0
        md_lines.append(f"| {sec} | {st['tp_hit']} | {st['tp_total']} | {pct:.1%} |")

    md_lines.append("\n## Detected TPs\n")
    md_lines.append("| ID | Section | Language | Technique | Difficulty | File:Line |")
    md_lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for g in sorted(tp_cases, key=lambda x: x["id"]):
        if g["id"] in detected_tp:
            sec = get_section_from_file(g["file"])
            md_lines.append(f"| {g['id']} | {sec} | {g['language']} | {g['technique']} | {g['difficulty']} | `{g['file']}:{g['line_start']}` |")

    md_lines.append("\n## Missed TPs (Blind Spots)\n")
    md_lines.append("| ID | Section | Language | Technique | Difficulty | Reason | File:Line |")
    md_lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for g in sorted(missed_tp, key=lambda x: x["id"]):
        sec = get_section_from_file(g["file"])
        md_lines.append(f"| {g['id']} | {sec} | {g['language']} | {g['technique']} | {g['difficulty']} | {g['reason']} | `{g['file']}:{g['line_start']}` |")

    md_lines.append("\n## Flagged False Positives\n")
    md_lines.append("| ID | Section | Language | Reason Safe | File:Line |")
    md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
    for g in sorted(fp_cases, key=lambda x: x["id"]):
        if g["id"] in flagged_fp:
            sec = get_section_from_file(g["file"])
            md_lines.append(f"| {g['id']} | {sec} | {g['language']} | {g['reason']} | `{g['file']}:{g['line_start']}` |")

    report_path = REPO_ROOT / output_report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    print(f"\n[OK] Full inventory report written to: {report_path}")

    if len(missed_tp) > allow_misses:
        print(f"\n[FAIL] {len(missed_tp)} advanced TPs missed! (Allowed: {allow_misses})")
        sys.exit(1)
    else:
        print(f"\n[PASS] Advanced coverage check passed! (Missed {len(missed_tp)} <= Allowed {allow_misses})")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Advanced Cases Coverage Checker")
    parser.add_argument("--findings", type=str, required=True, help="Path to scanner output file")
    parser.add_argument("--gt", type=str, default="ground_truth.json", help="Path to ground truth JSON")
    parser.add_argument("--allow-misses", type=int, default=0, help="Number of allowed missed TPs before nonzero exit")
    parser.add_argument("--report", type=str, default="new_cases_report.md", help="Output markdown report path")
    args = parser.parse_args()

    gt_file = Path(args.gt)
    if not gt_file.is_file():
        gt_file = REPO_ROOT / "ground_truth.json"

    run_coverage_check(args.findings, gt_file, allow_misses=args.allow_misses, output_report=args.report)

if __name__ == "__main__":
    main()

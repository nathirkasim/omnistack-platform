#!/usr/bin/env python3
"""
score.py - Comprehensive scoring engine for code security scanners (SAST, secrets, SCA, IaC).

Evaluates scanner outputs (SARIF, JSON, CSV) against ground_truth.json.
Calculates TP, FP, FN, TN, precision, recall, F1, evasion delta, mutation survival rate,
FP reason breakdown, and provides regression comparison and gating.
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

def normalize_path(path_str):
    if not path_str:
        return ""
    p = path_str.replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    return p

def parse_findings(findings_path):
    """
    Parses scanner output from SARIF, JSON, or CSV formats.
    Returns list of normalized findings:
    [{"file": "...", "line": int, "rule_id": "...", "cwe_cve": "..."}]
    """
    p = Path(findings_path)
    if not p.is_file():
        raise FileNotFoundError(f"Findings file not found: {findings_path}")

    with open(p, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()

    findings = []

    # 1. Try parsing as JSON (SARIF or standard JSON findings)
    if content.startswith("{") or content.startswith("["):
        try:
            data = json.loads(content)
            # SARIF format
            if isinstance(data, dict) and "runs" in data:
                for run in data.get("runs", []):
                    for res in run.get("results", []):
                        rule_id = res.get("ruleId", "")
                        message = res.get("message", {}).get("text", "")
                        for loc in res.get("locations", []):
                            ploc = loc.get("physicalLocation", {})
                            uri = ploc.get("artifactLocation", {}).get("uri", "")
                            rline = ploc.get("region", {}).get("startLine", 1)
                            findings.append({
                                "file": normalize_path(uri),
                                "line": int(rline) if rline else 1,
                                "rule_id": rule_id,
                                "cwe_cve": rule_id,
                                "raw": res
                            })
                return findings

            # Array of JSON findings
            elif isinstance(data, list):
                for item in data:
                    fpath = item.get("file") or item.get("path") or item.get("filename") or ""
                    line_no = item.get("line") or item.get("line_start") or item.get("start_line") or 1
                    rule = item.get("rule") or item.get("rule_id") or item.get("check_id") or ""
                    cwe = item.get("cwe") or item.get("cve") or item.get("cwe_or_cve") or rule
                    findings.append({
                        "file": normalize_path(fpath),
                        "line": int(line_no) if line_no else 1,
                        "rule_id": str(rule),
                        "cwe_cve": str(cwe),
                        "raw": item
                    })
                return findings
        except Exception:
            pass

    # 2. Try parsing as CSV
    try:
        reader = csv.DictReader(content.splitlines())
        for row in reader:
            fpath = row.get("file") or row.get("path") or row.get("filename") or ""
            line_val = row.get("line") or row.get("line_start") or 1
            rule = row.get("rule") or row.get("rule_id") or ""
            cwe = row.get("cwe") or row.get("cve") or rule
            findings.append({
                "file": normalize_path(fpath),
                "line": int(line_val) if str(line_val).isdigit() else 1,
                "rule_id": str(rule),
                "cwe_cve": str(cwe),
                "raw": row
            })
        if findings:
            return findings
    except Exception:
        pass

    return findings

def match_finding_to_gt(finding, gt_entries, tolerance=3):
    """
    Check if a scanner finding matches any ground truth entry by file, line range +/- tolerance.
    """
    f_file = normalize_path(finding["file"])
    f_line = finding["line"]

    best_match = None
    min_dist = float("inf")

    for gt in gt_entries:
        gt_file = normalize_path(gt["file"])
        # File matching: endswith or exact match
        if f_file == gt_file or f_file.endswith(gt_file) or gt_file.endswith(f_file):
            l_start = gt["line_start"] - tolerance
            l_end = gt["line_end"] + tolerance
            if l_start <= f_line <= l_end:
                dist = abs(f_line - gt["line_start"])
                if dist < min_dist:
                    min_dist = dist
                    best_match = gt

    return best_match

def evaluate_scanner(findings, gt_list, tolerance=3, include_disputed=False):
    # Filter disputed if needed
    if not include_disputed:
        active_gt = [g for g in gt_list if g.get("difficulty") != "disputed"]
    else:
        active_gt = gt_list

    # Separate GT TPs and FPs
    gt_tps = {g["id"]: g for g in active_gt if g["type"] == "TP"}
    gt_fps = {g["id"]: g for g in active_gt if g["type"] == "FP"}

    # Tracking matches
    tp_detected = set()
    fp_flagged = set()
    unmatched_findings = []
    finding_counts_per_gt = defaultdict(int)

    for f in findings:
        matched_gt = match_finding_to_gt(f, active_gt, tolerance=tolerance)
        if matched_gt:
            gt_id = matched_gt["id"]
            finding_counts_per_gt[gt_id] += 1
            if matched_gt["type"] == "TP":
                tp_detected.add(gt_id)
            elif matched_gt["type"] == "FP":
                fp_flagged.add(gt_id)
        else:
            unmatched_findings.append(f)

    # Calculate metrics
    num_tp = len(tp_detected)
    num_fn = len(gt_tps) - num_tp
    num_fp = len(fp_flagged) + len(unmatched_findings)
    num_tn = len(gt_fps) - len(fp_flagged)

    precision = num_tp / (num_tp + num_fp) if (num_tp + num_fp) > 0 else 0.0
    recall = num_tp / (num_tp + num_fn) if (num_tp + num_fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fp_rate = len(fp_flagged) / len(gt_fps) if len(gt_fps) > 0 else 0.0

    # Duplicate finding rate: total findings hitting TPs / distinct TPs found
    findings_hitting_tp = sum(finding_counts_per_gt[tid] for tid in tp_detected)
    dup_rate = (findings_hitting_tp - num_tp) / findings_hitting_tp if findings_hitting_tp > 0 else 0.0

    # Categorical slicing
    def compute_slice(key):
        groups = defaultdict(lambda: {"tp_hit": 0, "tp_total": 0, "fp_flag": 0, "fp_total": 0})
        for g in active_gt:
            val = g.get(key, "unknown")
            if g["type"] == "TP":
                groups[val]["tp_total"] += 1
                if g["id"] in tp_detected:
                    groups[val]["tp_hit"] += 1
            elif g["type"] == "FP":
                groups[val]["fp_total"] += 1
                if g["id"] in fp_flagged:
                    groups[val]["fp_flag"] += 1

        results = {}
        for val, counts in groups.items():
            t_hit, t_tot = counts["tp_hit"], counts["tp_total"]
            f_flag, f_tot = counts["fp_flag"], counts["fp_total"]
            rec = t_hit / t_tot if t_tot > 0 else 0.0
            prec = t_hit / (t_hit + f_flag) if (t_hit + f_flag) > 0 else 0.0
            results[val] = {
                "TP": t_hit, "FN": t_tot - t_hit, "FP": f_flag, "TN": f_tot - f_flag,
                "Recall": rec, "Precision": prec
            }
        return results

    by_category = compute_slice("category")
    by_language = compute_slice("language")
    by_difficulty = compute_slice("difficulty")
    by_technique = compute_slice("technique")

    # Evasion Delta: plain recall vs evasion recall for paired cases
    plain_tps = [g["id"] for g in active_gt if g.get("pair_id") and g.get("technique") == "plain" and g["type"] == "TP"]
    evasion_tps = [g["id"] for g in active_gt if g.get("pair_id") and g.get("technique") != "plain" and g["type"] == "TP"]

    plain_recall = sum(1 for pid in plain_tps if pid in tp_detected) / len(plain_tps) if plain_tps else 0.0
    evasion_recall = sum(1 for eid in evasion_tps if eid in tp_detected) / len(evasion_tps) if evasion_tps else 0.0
    evasion_delta = plain_recall - evasion_recall

    # Mutation Survival Rate: % of mutants where scanner still finds the vulnerability
    mutants = [g["id"] for g in active_gt if g.get("parent_id") and g["type"] == "TP"]
    mutant_recall = sum(1 for mid in mutants if mid in tp_detected) / len(mutants) if mutants else 0.0

    # FP rate by FP reason
    reason_breakdown = defaultdict(lambda: {"flagged": 0, "total": 0})
    for g in active_gt:
        if g["type"] == "FP":
            r = g.get("reason", "unknown")
            reason_breakdown[r]["total"] += 1
            if g["id"] in fp_flagged:
                reason_breakdown[r]["flagged"] += 1

    missed_tps = [g for g in active_gt if g["type"] == "TP" and g["id"] not in tp_detected]
    flagged_fps = [g for g in active_gt if g["type"] == "FP" and g["id"] in fp_flagged]

    return {
        "summary": {
            "TP": num_tp, "FN": num_fn, "FP": num_fp, "TN": num_tn,
            "Total_GT_TP": len(gt_tps), "Total_GT_FP": len(gt_fps),
            "Precision": precision, "Recall": recall, "F1": f1,
            "FP_Rate": fp_rate,
            "Duplicate_Rate": dup_rate,
            "Evasion_Delta": evasion_delta,
            "Plain_Recall": plain_recall,
            "Evasion_Recall": evasion_recall,
            "Mutation_Survival_Rate": mutant_recall,
            "Unmatched_Findings": len(unmatched_findings)
        },
        "by_category": by_category,
        "by_language": by_language,
        "by_difficulty": by_difficulty,
        "by_technique": by_technique,
        "reason_breakdown": dict(reason_breakdown),
        "missed_tps": missed_tps,
        "flagged_fps": flagged_fps,
        "detected_tp_ids": tp_detected,
        "flagged_fp_ids": fp_flagged
    }

def print_report(res):
    s = res["summary"]
    print("\n" + "=" * 65)
    print("             CODESEC BENCHMARK SCORING REPORT")
    print("=" * 65)
    print(f" True Positives (TP) : {s['TP']:3d} / {s['Total_GT_TP']:3d} (Recall: {s['Recall']:.2%})")
    print(f" False Positives(FP) : {s['FP']:3d} (FP Traps: {len(res['flagged_fps'])} + Unmatched: {s['Unmatched_Findings']})")
    print(f" False Negatives(FN) : {s['FN']:3d}")
    print(f" True Negatives (TN) : {s['TN']:3d} / {s['Total_GT_FP']:3d} (Specificity: {s['TN']/s['Total_GT_FP']:.2%})")
    print("-" * 65)
    print(f" Precision           : {s['Precision']:.2%}")
    print(f" Recall              : {s['Recall']:.2%}")
    print(f" F1-Score            : {s['F1']:.2%}")
    print(f" FP Rate on Traps    : {s['FP_Rate']:.2%}")
    print(f" Duplicate Rate      : {s['Duplicate_Rate']:.2%}")
    print(f" Evasion Delta       : {s['Evasion_Delta']:+.2%} (Plain: {s['Plain_Recall']:.2%} vs Evasion: {s['Evasion_Recall']:.2%})")
    print(f" Mutation Survival   : {s['Mutation_Survival_Rate']:.2%}")
    print("=" * 65)

    print("\n--- Breakdown by Category ---")
    print(f"{'Category':12s} {'TP':>4s} {'FN':>4s} {'FP':>4s} {'TN':>4s} {'Recall':>8s} {'Precision':>10s}")
    for cat, stats in sorted(res["by_category"].items()):
        print(f"{cat:12s} {stats['TP']:4d} {stats['FN']:4d} {stats['FP']:4d} {stats['TN']:4d} {stats['Recall']:7.1%} {stats['Precision']:9.1%}")

    print("\n--- Breakdown by Difficulty ---")
    print(f"{'Difficulty':12s} {'TP':>4s} {'FN':>4s} {'Recall':>8s}")
    for diff, stats in sorted(res["by_difficulty"].items()):
        print(f"{diff:12s} {stats['TP']:4d} {stats['FN']:4d} {stats['Recall']:7.1%}")

    if res["missed_tps"]:
        print(f"\n--- Sample Missed Vulnerabilities (First {min(5, len(res['missed_tps']))} of {len(res['missed_tps'])}) ---")
        for m in res["missed_tps"][:5]:
            print(f"  [-] {m['id']} [{m['category']}/{m['language']}]: {m['file']}:{m['line_start']} ({m['reason']})")

    if res["flagged_fps"]:
        print(f"\n--- Sample Flagged False Positives (First {min(5, len(res['flagged_fps']))} of {len(res['flagged_fps'])}) ---")
        for f in res["flagged_fps"][:5]:
            print(f"  [!] {f['id']} [{f['category']}/{f['language']}]: {f['file']}:{f['line_start']} Reason safe: {f['reason']}")

def compare_runs(res_a, res_b):
    print("\n" + "=" * 65)
    print("               SCANNER COMPARISON (A vs B)")
    print("=" * 65)
    sa, sb = res_a["summary"], res_b["summary"]
    print(f" Recall    : {sa['Recall']:.2%} -> {sb['Recall']:.2%} ({sb['Recall'] - sa['Recall']:+.2%})")
    print(f" Precision : {sa['Precision']:.2%} -> {sb['Precision']:.2%} ({sb['Precision'] - sa['Precision']:+.2%})")
    print(f" F1-Score  : {sa['F1']:.2%} -> {sb['F1']:.2%} ({sb['F1'] - sa['F1']:+.2%})")
    print(f" FP Count  : {sa['FP']} -> {sb['FP']} ({sb['FP'] - sa['FP']:+d})")

    newly_found = res_b["detected_tp_ids"] - res_a["detected_tp_ids"]
    lost_tps = res_a["detected_tp_ids"] - res_b["detected_tp_ids"]
    new_noise = res_b["flagged_fp_ids"] - res_a["flagged_fp_ids"]

    print(f"\nNewly Discovered TPs ({len(newly_found)}): {sorted(list(newly_found))[:10]}")
    print(f"Regressed / Lost TPs ({len(lost_tps)}): {sorted(list(lost_tps))[:10]}")
    print(f"New False Positives  ({len(new_noise)}): {sorted(list(new_noise))[:10]}")
    print("=" * 65)

def main():
    parser = argparse.ArgumentParser(description="Codesec Benchmark Scoring Engine")
    parser.add_argument("--findings", type=str, required=False, help="Path to scanner output file (SARIF, JSON, CSV)")
    parser.add_argument("--gt", type=str, default="ground_truth.json", help="Path to ground truth JSON")
    parser.add_argument("--tolerance", type=int, default=3, help="Line number tolerance (+/- lines)")
    parser.add_argument("--include-disputed", action="store_true", help="Include disputed difficulty cases")
    parser.add_argument("--min-recall", type=float, default=None, help="Minimum recall threshold gate (0.0 to 1.0)")
    parser.add_argument("--max-fp-rate", type=float, default=None, help="Maximum FP rate threshold gate (0.0 to 1.0)")
    parser.add_argument("--compare", nargs=2, metavar=("RUN_A", "RUN_B"), help="Compare two scanner run outputs")

    args = parser.parse_args()

    # Load GT
    gt_path = Path(args.gt)
    if not gt_path.is_file():
        gt_path = Path(__file__).resolve().parent / "ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    if args.compare:
        find_a = parse_findings(args.compare[0])
        find_b = parse_findings(args.compare[1])
        res_a = evaluate_scanner(find_a, gt_data, tolerance=args.tolerance, include_disputed=args.include_disputed)
        res_b = evaluate_scanner(find_b, gt_data, tolerance=args.tolerance, include_disputed=args.include_disputed)
        compare_runs(res_a, res_b)
        sys.exit(0)

    if not args.findings:
        parser.error("Either --findings or --compare must be provided.")

    findings = parse_findings(args.findings)
    results = evaluate_scanner(findings, gt_data, tolerance=args.tolerance, include_disputed=args.include_disputed)
    print_report(results)

    # Gating checks
    failed_gate = False
    if args.min_recall is not None:
        rec = results["summary"]["Recall"]
        if rec < args.min_recall:
            print(f"[FAIL GATE] Recall {rec:.2%} is below threshold {args.min_recall:.2%}")
            failed_gate = True
        else:
            print(f"[PASS GATE] Recall {rec:.2%} meets threshold {args.min_recall:.2%}")

    if args.max_fp_rate is not None:
        fpr = results["summary"]["FP_Rate"]
        if fpr > args.max_fp_rate:
            print(f"[FAIL GATE] FP rate {fpr:.2%} exceeds threshold {args.max_fp_rate:.2%}")
            failed_gate = True
        else:
            print(f"[PASS GATE] FP rate {fpr:.2%} meets threshold {args.max_fp_rate:.2%}")

    if failed_gate:
        sys.exit(2)

if __name__ == "__main__":
    main()

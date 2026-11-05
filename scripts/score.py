#!/usr/bin/env python3
"""Evaluate IaC security scanner output against ground truth test corpus.

Compares scanner findings from Checkov, Trivy, SARIF, or custom scanner JSON
against iac-tests/GROUND_TRUTH.csv. Computes TP, FP, FN, TN, precision, recall,
and generates reports/gap-report.md.
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH_PATH = REPO_ROOT / "iac-tests" / "GROUND_TRUTH.csv"
DEFAULT_REPORT_PATH = REPO_ROOT / "reports" / "gap-report.md"


def load_ground_truth(gt_path):
    """Load ground truth cases from CSV."""
    cases = {}
    with open(gt_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases[row["id"]] = row
    return cases


def parse_scanner_findings(scan_path):
    """Parse findings from scanner output (Checkov, Trivy, or SARIF)."""
    with open(scan_path, mode="r", encoding="utf-8") as f:
        data = json.load(f)

    findings_by_case = defaultdict(list)

    # 1. Checkov format (List of frameworks or single framework dict)
    if isinstance(data, list) and len(data) > 0 and "results" in data[0]:
        for fw in data:
            results = fw.get("results", {})
            for item in results.get("failed_checks", []):
                file_path = item.get("file_path", "") or item.get("file_abs_path", "") or item.get("repo_file_path", "")
                check_id = item.get("check_id", "UNKNOWN")
                rule_name = item.get("check_name", "")
                resource = item.get("resource", "")
                severity = item.get("severity", "MEDIUM")

                # Match case_id from file_path
                matched_id = extract_case_id_from_path(file_path)
                if matched_id:
                    findings_by_case[matched_id].append({
                        "rule_id": check_id,
                        "rule_name": rule_name,
                        "resource": resource,
                        "severity": severity,
                        "file": file_path
                    })
        return findings_by_case

    # Single Checkov framework dict
    if isinstance(data, dict) and "results" in data and "failed_checks" in data["results"]:
        for item in data["results"]["failed_checks"]:
            file_path = item.get("file_path", "") or item.get("file_abs_path", "")
            check_id = item.get("check_id", "UNKNOWN")
            matched_id = extract_case_id_from_path(file_path)
            if matched_id:
                findings_by_case[matched_id].append({
                    "rule_id": check_id,
                    "resource": item.get("resource", ""),
                    "file": file_path
                })
        return findings_by_case

    # 2. Trivy format (Results array)
    if isinstance(data, dict) and "Results" in data:
        for res in data.get("Results", []):
            target = res.get("Target", "")
            for misconf in res.get("Misconfigurations", []):
                matched_id = extract_case_id_from_path(target)
                if matched_id:
                    findings_by_case[matched_id].append({
                        "rule_id": misconf.get("ID", ""),
                        "rule_name": misconf.get("Title", ""),
                        "severity": misconf.get("Severity", ""),
                        "resource": misconf.get("Resource", ""),
                        "file": target
                    })
            for secret in res.get("Secrets", []):
                matched_id = extract_case_id_from_path(target)
                if matched_id:
                    findings_by_case[matched_id].append({
                        "rule_id": secret.get("RuleID", "secret"),
                        "rule_name": secret.get("Title", "Secret"),
                        "severity": secret.get("Severity", "CRITICAL"),
                        "resource": secret.get("Target", ""),
                        "file": target
                    })
        return findings_by_case

    # 3. SARIF format (runs -> results)
    if isinstance(data, dict) and "runs" in data:
        for run in data.get("runs", []):
            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                locations = res.get("locations", [])
                file_path = ""
                if locations:
                    pl = locations[0].get("physicalLocation", {})
                    file_path = pl.get("artifactLocation", {}).get("uri", "")
                matched_id = extract_case_id_from_path(file_path)
                if matched_id:
                    findings_by_case[matched_id].append({
                        "rule_id": rule_id,
                        "resource": "",
                        "file": file_path
                    })
        return findings_by_case

    print("Warning: Unrecognized scanner JSON format. Attempting fallback matching.")
    return findings_by_case


def extract_case_id_from_path(path_str):
    """Extract case-id (e.g. TF-VAR-001) from path string."""
    parts = Path(path_str).parts
    for part in parts:
        # Standard case id naming convention: PREFIX-CATEGORY-001 or similar
        if "-" in part and any(part.startswith(prefix) for prefix in [
            "TF-", "K8S-", "CFN-", "DOCKER-", "COMPOSE-", "HELM-", "KUST-",
            "GHA-", "GL-", "AZ-", "CLOUDBUILD-", "TG-", "CDK-", "SLS-",
            "ANS-", "PACKER-", "ARGO-", "FLUX-", "XP-", "GCP-"
        ]):
            return part
    return None


def calculate_metrics(cases, findings_by_case):
    """Calculate evaluation metrics for all cases, per category and per IaC type."""
    eval_results = []

    # Category and IaC Type aggregators
    cat_stats = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    type_stats = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    overall = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    missed_cases = []
    wrongly_flagged_cases = []

    for case_id, case in cases.items():
        label = case["label"]
        iac_type = case["iac_type"]
        category = case["category"]
        findings = findings_by_case.get(case_id, [])
        has_findings = len(findings) > 0

        verdict = ""
        if label in ("TRUE_POSITIVE", "EVASIVE_MISCONFIG"):
            if has_findings:
                verdict = "TP"
                cat_stats[category]["TP"] += 1
                type_stats[iac_type]["TP"] += 1
                overall["TP"] += 1
            else:
                verdict = "FN"
                cat_stats[category]["FN"] += 1
                type_stats[iac_type]["FN"] += 1
                overall["FN"] += 1
                missed_cases.append({
                    "id": case_id,
                    "iac_type": iac_type,
                    "category": category,
                    "label": label,
                    "severity": case["severity"],
                    "description": case["description"],
                    "why_scanner_may_fail": case["why_scanner_may_fail"]
                })
        elif label == "SAFE_LOOKALIKE":
            if has_findings:
                verdict = "FP"
                cat_stats[category]["FP"] += 1
                type_stats[iac_type]["FP"] += 1
                overall["FP"] += 1
                wrongly_flagged_cases.append({
                    "id": case_id,
                    "iac_type": iac_type,
                    "category": category,
                    "description": case["description"],
                    "flagged_rules": [f["rule_id"] for f in findings]
                })
            else:
                verdict = "TN"
                cat_stats[category]["TN"] += 1
                type_stats[iac_type]["TN"] += 1
                overall["TN"] += 1

        eval_results.append({
            "id": case_id,
            "iac_type": iac_type,
            "category": category,
            "label": label,
            "verdict": verdict,
            "findings_count": len(findings)
        })

    return {
        "overall": overall,
        "cat_stats": cat_stats,
        "type_stats": type_stats,
        "missed_cases": missed_cases,
        "wrongly_flagged_cases": wrongly_flagged_cases,
        "eval_results": eval_results
    }


def compute_rates(tp, fp, fn, tn):
    """Compute Precision, Recall, and F1."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def generate_gap_report(metrics, cases, scanner_file, output_path):
    """Write comprehensive Markdown gap report."""
    overall = metrics["overall"]
    p, r, f1 = compute_rates(overall["TP"], overall["FP"], overall["FN"], overall["TN"])

    md = []
    md.append("# IaC Security Scanner Evaluation & Gap Analysis Report\n")
    md.append(f"**Scanner Output File**: `{scanner_file}`  ")
    md.append(f"**Ground Truth Corpus Size**: {len(cases)} test cases across 19 IaC types  \n")

    md.append("## 1. Executive Summary\n")
    md.append("| Metric | Value | Description |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| **True Positives (TP)** | `{overall['TP']}` | Correctly identified misconfigurations & evasions |")
    md.append(f"| **False Positives (FP)** | `{overall['FP']}` | Benign / mitigated safe lookalikes wrongly flagged |")
    md.append(f"| **False Negatives (FN)** | `{overall['FN']}` | Missed vulnerabilities & evasion bypasses |")
    md.append(f"| **True Negatives (TN)** | `{overall['TN']}` | Benign patterns correctly passed without alarms |")
    md.append(f"| **Precision** | `{p * 100:.2f}%` | Proportion of alerted issues that were real risks |")
    md.append(f"| **Recall (Coverage)** | `{r * 100:.2f}%` | Proportion of real misconfigurations detected |")
    md.append(f"| **F1 Score** | `{f1 * 100:.2f}%` | Harmonic balance between Precision and Recall |\n")

    md.append("## 2. Performance by Infrastructure-as-Code (IaC) Type\n")
    md.append("| IaC Type | TP | FP | FN | TN | Precision | Recall | F1 Score |")
    md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for iac_type in sorted(metrics["type_stats"].keys()):
        s = metrics["type_stats"][iac_type]
        tp_s, fp_s, fn_s, tn_s = s["TP"], s["FP"], s["FN"], s["TN"]
        p_s, r_s, f1_s = compute_rates(tp_s, fp_s, fn_s, tn_s)
        md.append(f"| `{iac_type}` | {tp_s} | {fp_s} | {fn_s} | {tn_s} | {p_s*100:.1f}% | {r_s*100:.1f}% | {f1_s*100:.1f}% |")

    md.append("\n## 3. Performance by Scenario Category\n")
    md.append("| Category | TP | FP | FN | TN | Precision | Recall | F1 Score |")
    md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for cat in sorted(metrics["cat_stats"].keys()):
        s = metrics["cat_stats"][cat]
        tp_c, fp_c, fn_c, tn_c = s["TP"], s["FP"], s["FN"], s["TN"]
        p_c, r_c, f1_c = compute_rates(tp_c, fp_c, fn_c, tn_c)
        md.append(f"| `{cat}` | {tp_c} | {fp_c} | {fn_c} | {tn_c} | {p_c*100:.1f}% | {r_c*100:.1f}% | {f1_c*100:.1f}% |")

    md.append("\n## 4. Missed Vulnerabilities & Scanner Blind Spots (False Negatives)\n")
    md.append("These test cases represent genuine security vulnerabilities that the scanner failed to detect.\n")
    md.append("| Case ID | IaC Type | Category | Severity | Description | Why Scanner Failed |")
    md.append("| :--- | :--- | :--- | :---: | :--- | :--- |")
    for m in metrics["missed_cases"]:
        desc = m["description"].replace("|", "\\|")
        why = m["why_scanner_may_fail"].replace("|", "\\|")
        md.append(f"| `{m['id']}` | `{m['iac_type']}` | `{m['category']}` | **{m['severity']}** | {desc} | {why} |")

    md.append("\n## 5. False Alarms & Benign Idioms Flagged (False Positives)\n")
    md.append("These cases represent secure architectures, mitigated risks, or legitimate skips wrongly flagged by the scanner.\n")
    md.append("| Case ID | IaC Type | Category | Description | Triggered Rules |")
    md.append("| :--- | :--- | :--- | :--- | :--- |")
    for w in metrics["wrongly_flagged_cases"]:
        rules_str = ", ".join(f"`{r}`" for r in set(w["flagged_rules"]))
        md.append(f"| `{w['id']}` | `{w['iac_type']}` | `{w['category']}` | {w['description']} | {rules_str} |")

    md.append("\n## 6. Recommendations for Scanner Improvement\n")
    md.append("1. **Implement Inter-File Context & Variable Resolution**: Resolve `.tfvars`, `locals`, and input variables rather than relying solely on default values or single-file scopes.")
    md.append("2. **Evaluate Intrinsic & Built-in Functions**: Expand CloudFormation `Fn::Sub`, `Fn::FindInMap`, and Terraform functions (`lookup`, `cidrsubnet`, `merge`, `coalesce`).")
    md.append("3. **Context-Aware Policy Checking**: Inspect IAM Condition keys (`aws:PrincipalOrgID`, `aws:SecureTransport`) before raising alerts on wildcard actions.")
    md.append("4. **Multi-Document & Deep Hierarchy Support**: Ensure parsers do not terminate on the first YAML document in multi-doc streams, and trace nested module calls 3+ levels deep.")
    md.append("5. **Understand Provider Evolution**: Support separate split resources (`aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`) in AWS Provider v4+ to prevent false positives.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, mode="w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"Gap report successfully generated at: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Score IaC security scanner output against ground truth corpus.")
    parser.add_argument("scanner_output", nargs="?", default=str(REPO_ROOT / "reports" / "checkov_scan.json"),
                        help="Path to scanner JSON output (default: reports/checkov_scan.json)")
    parser.add_argument("--gt", default=str(GROUND_TRUTH_PATH), help="Path to GROUND_TRUTH.csv")
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH), help="Path to output markdown report")
    args = parser.parse_args()

    if not os.path.exists(args.gt):
        print(f"Error: Ground truth file not found: {args.gt}")
        sys.exit(1)

    if not os.path.exists(args.scanner_output):
        print(f"Error: Scanner output file not found: {args.scanner_output}")
        print("Run scripts/run_scan.sh first to generate scan output.")
        sys.exit(1)

    print(f"Loading ground truth from {args.gt}...")
    cases = load_ground_truth(args.gt)
    print(f"Loaded {len(cases)} cases.")

    print(f"Parsing scanner output from {args.scanner_output}...")
    findings_by_case = parse_scanner_findings(args.scanner_output)
    print(f"Mapped findings to {len(findings_by_case)} test cases.")

    print("Evaluating metrics...")
    metrics = calculate_metrics(cases, findings_by_case)
    overall = metrics["overall"]
    p, r, f1 = compute_rates(overall["TP"], overall["FP"], overall["FN"], overall["TN"])

    print("\n" + "=" * 60)
    print("                 BENCHMARK EVALUATION SUMMARY")
    print("=" * 60)
    print(f"True Positives (TP):  {overall['TP']:3d} | False Positives (FP): {overall['FP']:3d}")
    print(f"False Negatives (FN): {overall['FN']:3d} | True Negatives (TN):  {overall['TN']:3d}")
    print("-" * 60)
    print(f"Precision: {p * 100:6.2f}% | Recall: {r * 100:6.2f}% | F1 Score: {f1 * 100:6.2f}%")
    print("=" * 60)
    print(f"Total Missed Vulnerabilities (FN): {len(metrics['missed_cases'])}")
    print(f"Total False Alarms (FP):           {len(metrics['wrongly_flagged_cases'])}")
    print("=" * 60)

    report_path = Path(args.report)
    generate_gap_report(metrics, cases, args.scanner_output, report_path)


if __name__ == "__main__":
    main()


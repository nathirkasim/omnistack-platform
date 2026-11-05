#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    message: str
    snippet: str = ""

@dataclass
class ManifestEntry:
    file: str
    line: int
    expect: str
    family: str
    level: str
    scenario_id: str
    rationale: str

def normalize_path(path_str: str, root_dir: Path) -> str:
    p = Path(path_str)
    # Check if absolute and under root_dir
    try:
        if p.is_absolute():
            rel = p.relative_to(root_dir)
            return str(rel).lstrip("/")
    except ValueError:
        pass
    
    # Check if path contains relative markers
    norm = p.as_posix()
    for prefix in ["fp-regex-tests/", "./fp-regex-tests/", "./"]:
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
    return norm.lstrip("/")

def parse_sarif(data: dict, root_dir: Path) -> List[Finding]:
    findings = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "UNKNOWN")
            message = res.get("message", {}).get("text", "")
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 1)
                snippet = region.get("snippet", {}).get("text", "")
                norm_file = normalize_path(uri, root_dir)
                findings.append(Finding(file=norm_file, line=line, rule_id=rule_id, message=message, snippet=snippet))
    return findings

def parse_checkov(data, root_dir: Path) -> List[Finding]:
    findings = []
    items = data if isinstance(data, list) else [data]
    failed_checks = []
    for item in items:
        if isinstance(item, dict):
            results_obj = item.get("results", {})
            if results_obj:
                failed_checks.extend(results_obj.get("failed_checks", []))

    for chk in failed_checks:
        raw_file = chk.get("file_path", "")
        norm_file = normalize_path(raw_file, root_dir)
        lines = chk.get("file_line_range", [1, 1])
        start_line = lines[0] if lines else 1
        rule_id = chk.get("check_id", "UNKNOWN")
        msg = chk.get("check_name", "")
        code_block = chk.get("code_block", [])
        snippet = "\n".join([f"{num}: {code}" for num, code in code_block]) if code_block else ""
        findings.append(Finding(file=norm_file, line=start_line, rule_id=rule_id, message=msg, snippet=snippet))
    return findings

def parse_trivy(data: dict, root_dir: Path) -> List[Finding]:
    findings = []
    for res in data.get("Results", []):
        target = res.get("Target", "")
        norm_file = normalize_path(target, root_dir)
        # 1. Misconfigurations
        for m in res.get("Misconfigurations", []):
            rule_id = m.get("ID", "UNKNOWN")
            msg = m.get("Title", "") or m.get("Description", "")
            start_line = m.get("CauseMetadata", {}).get("StartLine", 1)
            findings.append(Finding(file=norm_file, line=start_line, rule_id=rule_id, message=msg))
        # 2. Secrets
        for s in res.get("Secrets", []):
            rule_id = s.get("RuleID", "SECRET")
            msg = s.get("Title", "")
            start_line = s.get("StartLine", 1)
            findings.append(Finding(file=norm_file, line=start_line, rule_id=rule_id, message=msg))
    return findings

def parse_generic(data, root_dir: Path) -> List[Finding]:
    findings = []
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "findings" in data:
            items = data["findings"]
        elif "results" in data:
            items = data["results"]
    
    for item in items:
        if isinstance(item, dict):
            raw_file = item.get("file", "") or item.get("filename", "") or item.get("path", "")
            line = item.get("line", item.get("start_line", 1))
            rule_id = item.get("rule_id", item.get("rule", item.get("id", "UNKNOWN")))
            msg = item.get("message", item.get("description", ""))
            findings.append(Finding(file=normalize_path(raw_file, root_dir), line=int(line), rule_id=str(rule_id), message=str(msg)))
    return findings

def load_findings(report_path: Path, root_dir: Path) -> List[Finding]:
    try:
        content = report_path.read_text(encoding="utf-8")
        # Try direct JSON parsing first
        try:
            data = json.loads(content)
        except Exception:
            # Fallback: strip leading log lines if present
            m = re.search(r'\n\s*([\[{])', content)
            if m:
                start = m.start(1)
                end = max(content.rfind("]"), content.rfind("}"))
                data = json.loads(content[start:end+1])
            else:
                raise
    except Exception as e:
        print(f"Error reading report file {report_path}: {e}")
        return []

    if isinstance(data, dict) and "$schema" in data and "sarif" in data.get("$schema", "").lower():
        return parse_sarif(data, root_dir)
    elif isinstance(data, dict) and "runs" in data:
        return parse_sarif(data, root_dir)
    elif isinstance(data, dict) and ("results" in data and "failed_checks" in data["results"]):
        return parse_checkov(data, root_dir)
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and "results" in data[0]:
        return parse_checkov(data, root_dir)
    elif isinstance(data, dict) and "Results" in data:
        return parse_trivy(data, root_dir)
    else:
        return parse_generic(data, root_dir)

def get_file_extension(file_path: str) -> str:
    p = Path(file_path)
    suffixes = "".join(p.suffixes)
    if suffixes:
        return suffixes
    name = p.name
    if "Dockerfile" in name:
        return "Dockerfile"
    return "other"

def main():
    parser = argparse.ArgumentParser(description="Score security scanner output against ground-truth manifest")
    parser.add_argument("--manifest", default="manifest.csv", help="Path to manifest.csv")
    parser.add_argument("--report", default="", help="Path to scanner JSON/SARIF report")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent

    manifest_file = Path(args.manifest)
    if not manifest_file.is_absolute():
        manifest_file = root_dir / manifest_file

    if not manifest_file.exists():
        print(f"Manifest not found: {manifest_file}")
        sys.exit(1)

    # Load manifest
    manifest_entries: List[ManifestEntry] = []
    with open(manifest_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            manifest_entries.append(ManifestEntry(
                file=r["file"],
                line=int(r["line"]),
                expect=r["expect"],
                family=r["family"],
                level=r["level"],
                scenario_id=r["scenario_id"],
                rationale=r["rationale"]
            ))

    # Find report file if not specified
    report_file: Optional[Path] = None
    if args.report:
        report_file = Path(args.report)
        if not report_file.is_absolute():
            report_file = Path.cwd() / report_file
    else:
        raw_dir = root_dir / args.output_dir / "raw"
        if raw_dir.exists():
            reports = list(raw_dir.glob("*.json")) + list(raw_dir.glob("*.sarif"))
            if reports:
                # pick newest
                report_file = max(reports, key=os.path.getmtime)

    findings: List[Finding] = []
    report_name = "None (No findings)"
    if report_file and report_file.exists():
        report_name = report_file.name
        findings = load_findings(report_file, root_dir)
        print(f"Loaded {len(findings)} findings from {report_file}")
    else:
        print("No report file specified or found; scoring with 0 findings.")

    # Match findings to manifest lines with +-1 line tolerance
    # Group manifest entries by file
    manifest_by_file: Dict[str, List[ManifestEntry]] = defaultdict(list)
    for me in manifest_entries:
        manifest_by_file[me.file].append(me)

    # Track matches
    manifest_hits: Dict[Tuple[str, int], List[Finding]] = defaultdict(list)
    matched_finding_indices = set()

    for idx, f in enumerate(findings):
        entries = manifest_by_file.get(f.file, [])
        for me in entries:
            if abs(me.line - f.line) <= 1:
                manifest_hits[(me.file, me.line)].append(f)
                matched_finding_indices.add(idx)

    # Classify each manifest entry
    results_rows = []
    tp_count = 0
    fn_count = 0
    tn_count = 0
    fp_count = 0
    debatable_hits = 0
    debatable_ignored = 0

    fp_rules = Counter()
    family_stats = defaultdict(lambda: Counter())
    level_stats = defaultdict(lambda: Counter())
    lang_stats = defaultdict(lambda: Counter())

    for me in manifest_entries:
        hits = manifest_hits.get((me.file, me.line), [])
        flagged = "Y" if len(hits) > 0 else "N"
        hit_rules = ";".join(sorted(set(h.rule_id for h in hits)))
        snippet = hits[0].snippet if hits and hits[0].snippet else ""
        ext = get_file_extension(me.file)

        verdict = ""
        if me.expect == "FLAG":
            if flagged == "Y":
                verdict = "TRUE_POSITIVE"
                tp_count += 1
                family_stats[me.family]["TP"] += 1
                level_stats[me.level]["TP"] += 1
                lang_stats[ext]["TP"] += 1
            else:
                verdict = "FALSE_NEGATIVE"
                fn_count += 1
                family_stats[me.family]["FN"] += 1
                level_stats[me.level]["FN"] += 1
                lang_stats[ext]["FN"] += 1
        elif me.expect == "NO_FLAG":
            if flagged == "Y":
                verdict = "FP_CANDIDATE (UNREVIEWED)"
                fp_count += 1
                for h in hits:
                    fp_rules[h.rule_id] += 1
                family_stats[me.family]["FP"] += 1
                level_stats[me.level]["FP"] += 1
                lang_stats[ext]["FP"] += 1
            else:
                verdict = "TRUE_NEGATIVE"
                tn_count += 1
                family_stats[me.family]["TN"] += 1
                level_stats[me.level]["TN"] += 1
                lang_stats[ext]["TN"] += 1
        elif me.expect == "DEBATABLE":
            if flagged == "Y":
                verdict = "DEBATABLE_HIT"
                debatable_hits += 1
            else:
                verdict = "DEBATABLE_IGNORED"
                debatable_ignored += 1

        results_rows.append({
            "scenario_id": me.scenario_id,
            "file": me.file,
            "line": me.line,
            "expect": me.expect,
            "flagged(Y/N)": flagged,
            "rule_id": hit_rules,
            "snippet": snippet,
            "family": me.family,
            "level": me.level,
            "verdict": verdict
        })

    # Track unexpected other findings
    unexpected_other = []
    for idx, f in enumerate(findings):
        if idx not in matched_finding_indices:
            unexpected_other.append(f)

    # Output directory
    out_dir = root_dir / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write results.csv
    results_csv_path = out_dir / "results.csv"
    with open(results_csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["scenario_id", "file", "line", "expect", "flagged(Y/N)", "rule_id", "snippet", "family", "level", "verdict"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results_rows:
            writer.writerow(r)

    # Calculate overall metrics
    precision = (tp_count / (tp_count + fp_count)) * 100 if (tp_count + fp_count) > 0 else 0.0
    recall = (tp_count / (tp_count + fn_count)) * 100 if (tp_count + fn_count) > 0 else 0.0
    specificity = (tn_count / (tn_count + fp_count)) * 100 if (tn_count + fp_count) > 0 else 0.0

    # Write gap-report.md
    report_md_path = out_dir / "gap-report.md"
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# Regex & Pattern Security Scanner Benchmark Report\n\n")
        f.write(f"- **Evaluated Report**: `{report_name}`\n")
        f.write(f"- **Total Target Scenarios**: {len(manifest_entries)}\n")
        f.write(f"- **Total Scanner Findings**: {len(findings)}\n\n")

        f.write("## 1. Executive Summary\n\n")
        f.write("| Metric | Count | Ratio |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| **True Positives (Caught Issues)** | {tp_count} | Recall: {recall:.1f}% |\n")
        f.write(f"| **False Negatives (Missed Vulnerabilities)** | {fn_count} | Miss Rate: {100 - recall:.1f}% |\n")
        f.write(f"| **True Negatives (Correctly Ignored Lookalikes)** | {tn_count} | Specificity: {specificity:.1f}% |\n")
        f.write(f"| **False Positive Candidates (Flagged Lookalikes)** | {fp_count} | Precision: {precision:.1f}% |\n")
        f.write(f"| **Debatable Hits (Policy / Sample Keys)** | {debatable_hits} | (Isolated from FP/FN) |\n")
        f.write(f"| **Unexpected Other Findings** | {len(unexpected_other)} | (Requires manual triage) |\n\n")

        f.write("## 2. Accuracy by Complexity Level\n\n")
        f.write("| Level | Targets | TP | FN | TN | FP | Precision | Recall |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for lvl in ["L1_BASIC", "L2_INTERMEDIATE", "L3_ADVANCED"]:
            s = level_stats[lvl]
            tot = s["TP"] + s["FN"] + s["TN"] + s["FP"]
            p = (s["TP"] / (s["TP"] + s["FP"]) * 100) if (s["TP"] + s["FP"]) > 0 else 0.0
            r = (s["TP"] / (s["TP"] + s["FN"]) * 100) if (s["TP"] + s["FN"]) > 0 else 0.0
            f.write(f"| `{lvl}` | {tot} | {s['TP']} | {s['FN']} | {s['TN']} | {s['FP']} | {p:.1f}% | {r:.1f}% |\n")
        f.write("\n")

        f.write("## 3. Accuracy by Scenario Family\n\n")
        f.write("| Family | Targets | TP | FN | TN | FP | Precision | Recall |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for fam in sorted(family_stats.keys()):
            s = family_stats[fam]
            tot = s["TP"] + s["FN"] + s["TN"] + s["FP"]
            p = (s["TP"] / (s["TP"] + s["FP"]) * 100) if (s["TP"] + s["FP"]) > 0 else 0.0
            r = (s["TP"] / (s["TP"] + s["FN"]) * 100) if (s["TP"] + s["FN"]) > 0 else 0.0
            f.write(f"| `{fam}` | {tot} | {s['TP']} | {s['FN']} | {s['TN']} | {s['FP']} | {p:.1f}% | {r:.1f}% |\n")
        f.write("\n")

        f.write("## 4. Accuracy by Language / File Format\n\n")
        f.write("| Extension / Format | Targets | TP | FN | TN | FP | Precision | Recall |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for ext in sorted(lang_stats.keys()):
            s = lang_stats[ext]
            tot = s["TP"] + s["FN"] + s["TN"] + s["FP"]
            p = (s["TP"] / (s["TP"] + s["FP"]) * 100) if (s["TP"] + s["FP"]) > 0 else 0.0
            r = (s["TP"] / (s["TP"] + s["FN"]) * 100) if (s["TP"] + s["FN"]) > 0 else 0.0
            f.write(f"| `{ext}` | {tot} | {s['TP']} | {s['FN']} | {s['TN']} | {s['FP']} | {p:.1f}% | {r:.1f}% |\n")
        f.write("\n")

        f.write("## 5. Top 20 FP-Prone Rules\n\n")
        if fp_rules:
            f.write("| Rule ID | False Positive Hits |\n")
            f.write("| :--- | :--- |\n")
            for rule_id, count in fp_rules.most_common(20):
                f.write(f"| `{rule_id}` | {count} |\n")
        else:
            f.write("No false positive candidates detected.\n")
        f.write("\n")

        f.write("## 6. Format-Robustness Verification\n\n")
        f.write("Testing parser invariance across syntax formatting, casing, line-endings, and comments.\n\n")
        f.write("| Test File | Target Scenario | Expect | Flagged | Status |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for r in results_rows:
            if "format_robustness" in r["file"] or "robustness" in r["file"]:
                f.write(f"| `{r['file']}:{r['line']}` | `{r['scenario_id']}` | {r['expect']} | {r['flagged(Y/N)']} | {r['verdict']} |\n")
        f.write("\n")

        if unexpected_other:
            f.write("## 7. Unexpected Other Findings (Manual Review Needed)\n\n")
            f.write("| File | Line | Rule ID | Message |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for uf in unexpected_other[:50]:
                f.write(f"| `{uf.file}` | {uf.line} | `{uf.rule_id}` | {uf.message} |\n")
            f.write("\n")

    print(f"\nGenerated scoring results: {results_csv_path}")
    print(f"Generated gap report: {report_md_path}")
    print(f"Summary: TP={tp_count}, FN={fn_count}, TN={tn_count}, FP={fp_count}, DEBATABLE={debatable_hits}")
    print(f"Precision: {precision:.1f}%, Recall: {recall:.1f}%, Specificity: {specificity:.1f}%\n")

if __name__ == "__main__":
    main()

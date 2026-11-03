#!/usr/bin/env python3
"""
build_all_gt.py - Master Ground Truth Builder for codesec-benchmark.
Scans all benchmark fixture files in basic/ and advanced/, extracts GT comments,
populates full schema, synchronizes ground_truth.json and ground_truth.csv.
"""

import os
import json
import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

COMMENT_PATTERN = re.compile(r'(?:"[^"]*":\s*"|#|//|<!--|--|/\*)\s*GT:\s*(.*?)(?:"|\*/|-->)?(?:,\s*)?$')
ATTR_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')

def get_category_and_language(rel_path):
    rel = rel_path.replace("\\", "/")
    if "/python/" in rel or rel.endswith(".py"):
        lang = "python"
    elif "/java/" in rel or rel.endswith(".java") or rel.endswith("pom.xml"):
        lang = "java"
    elif "/go/" in rel or rel.endswith(".go") or rel.endswith("go.mod"):
        lang = "go"
    elif "/node/" in rel or rel.endswith(".js") or rel.endswith("package.json"):
        lang = "node"
    elif rel.endswith(".tf") or "/terraform/" in rel:
        lang = "terraform"
    elif "Dockerfile" in rel:
        lang = "dockerfile"
    elif rel.endswith(".yaml") or rel.endswith(".yml"):
        if "/k8s/" in rel or "k8s-" in rel or "/kustomize/" in rel:
            lang = "kubernetes"
        else:
            lang = "yaml"
    else:
        lang = "generic"

    if "/sast/" in rel or "/taint/" in rel:
        cat = "SAST"
    elif "/secrets" in rel:
        cat = "secrets"
    elif "/sca/" in rel:
        cat = "SCA"
    elif "/iac/" in rel:
        cat = "IaC"
    elif "/evasion/" in rel:
        cat = "secrets" if "secrets" in rel else "SAST"
    elif "/mutants/" in rel:
        cat = "SAST"
    else:
        cat = "SAST"

    return cat, lang

def scan_files():
    file_list = []
    scan_roots = [REPO_ROOT / "basic", REPO_ROOT / "advanced"]
    ignore_dirs = {".git", "history-repo", "__pycache__", "node_modules", "target", "rendered", "harness"}

    for root_dir in scan_roots:
        for r, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for f in sorted(files):
                # Include source files, configs, dotfiles, and manifests
                if f.endswith((".pyc", ".class", ".png", ".jpg", ".zip", ".tar.gz", ".lock")):
                    continue
                p = Path(r) / f
                file_list.append(p.relative_to(REPO_ROOT).as_posix())
    return sorted(file_list)

def build_ground_truth():
    files = scan_files()
    entries = []

    for rel in files:
        full_path = REPO_ROOT / rel
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {rel}: {e}")
            continue

        cat, lang = get_category_and_language(rel)

        for idx, line in enumerate(lines):
            m = COMMENT_PATTERN.search(line.strip())
            if not m:
                continue
            raw_attrs = m.group(1).strip()
            attrs = {}
            for match in ATTR_PATTERN.finditer(raw_attrs):
                k = match.group(1)
                v = match.group(2) if match.group(2) is not None else match.group(3)
                attrs[k] = v

            item_id = attrs.get("id")
            if not item_id:
                continue

            typ = attrs.get("type", "TP")
            cwe = attrs.get("cwe", "")
            rule = attrs.get("rule", "")
            reason = attrs.get("reason", "")
            technique = attrs.get("technique", "")
            pair_id = attrs.get("pair_id", "")
            parent_id = attrs.get("parent_id", "")
            mutation = attrs.get("mutation", "")

            # Target line: next line after comment, skipping blank lines
            target_line = idx + 2
            curr = idx + 1
            while curr < len(lines):
                c_line = lines[curr].strip()
                if c_line and not COMMENT_PATTERN.search(c_line):
                    target_line = curr + 1
                    break
                curr += 1
            if target_line > len(lines):
                target_line = len(lines)

            # Determine difficulty
            difficulty = "medium"
            if "TAINT-" in item_id:
                # Marked hard cases
                if any(k in item_id for k in ["-001", "-002", "-004", "-008", "-011", "-012", "-014", "-018"]):
                    difficulty = "hard"
                else:
                    difficulty = "medium"
            elif typ == "TP" and ("basic" in rel or "easy" in rule):
                difficulty = "easy"
            elif typ == "FP":
                difficulty = "medium"

            # Determine technique
            if not technique:
                if typ == "FP":
                    technique = reason if reason else "defensive-pattern"
                else:
                    technique = rule if rule else "direct-sink"

            if typ == "TP" and not reason:
                reason = f"exploitable-{rule if rule else 'vulnerability'}"

            # Category override if ID has specific prefix
            if item_id.startswith("SEC-") or item_id.startswith("HIST-SEC-") or item_id.startswith("EVASION-SEC-"):
                cat = "secrets"
            elif item_id.startswith("SCA-") or item_id.startswith("ADV-SCA-"):
                cat = "SCA"
            elif item_id.startswith("IAC-") or item_id.startswith("ADV-IAC-"):
                cat = "IaC"
            elif item_id.startswith("SAST-") or item_id.startswith("TAINT-") or item_id.startswith("EVASION-") or item_id.startswith("MUTANT-"):
                cat = "SAST"

            entry = {
                "id": item_id,
                "category": cat,
                "language": lang,
                "file": rel,
                "line_start": target_line,
                "line_end": target_line,
                "type": typ,
                "cwe_or_cve": cwe if cwe else ("N/A" if typ == "FP" else "CWE-Other"),
                "rule_hint": rule if rule else (reason if typ == "FP" else "security-finding"),
                "difficulty": difficulty,
                "technique": technique,
                "pair_id": pair_id,
                "parent_id": parent_id,
                "mutation": mutation,
                "reason": reason,
                "notes": f"Codesec benchmark item {item_id}"
            }
            entries.append(entry)

    json_path = REPO_ROOT / "ground_truth.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

    csv_path = REPO_ROOT / "ground_truth.csv"
    fields = [
        "id", "category", "language", "file", "line_start", "line_end",
        "type", "cwe_or_cve", "rule_hint", "difficulty", "technique",
        "pair_id", "parent_id", "mutation", "reason", "notes"
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e in entries:
            writer.writerow(e)

    print(f"[OK] Generated {len(entries)} items in {json_path} and {csv_path}")

if __name__ == "__main__":
    build_ground_truth()

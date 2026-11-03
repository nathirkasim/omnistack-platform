#!/usr/bin/env python3
"""
validate_gt.py - Validate ground truth manifest and inline comments.

Checks:
1. Valid JSON and CSV manifests, consistent fields and counts.
2. Unique ID format: <CAT>-<LANG>-<NNN> (e.g., SAST-PY-004, SEC-GEN-001).
3. Required fields present: id, category, language, file, line_start, line_end,
   type, cwe_or_cve, rule_hint, difficulty, technique, pair_id, parent_id,
   mutation, reason, notes.
4. Difficulty is in [easy, medium, hard, disputed].
5. Type is in [TP, FP].
6. Every referenced file exists on disk.
7. line_start and line_end are valid within the target file bounds.
8. Inline comment exists directly above (or at) line_start and matches id & type.
9. Every inline comment found in the codebase maps to an entry in the manifest (no orphans).
10. Twin pair_id references exist and cross-reference symmetrically.
11. Mutants parent_id references exist.
"""

import os
import sys
import json
import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

REQUIRED_FIELDS = [
    "id", "category", "language", "file", "line_start", "line_end",
    "type", "cwe_or_cve", "rule_hint", "difficulty", "technique",
    "pair_id", "parent_id", "mutation", "reason", "notes"
]

VALID_DIFFICULTIES = {"easy", "medium", "hard", "disputed"}
VALID_TYPES = {"TP", "FP"}
VALID_CATEGORIES = {"SAST", "secrets", "SCA", "IaC"}

ID_REGEX = re.compile(r"^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9_]+$")
GT_COMMENT_REGEX = re.compile(r'(?:"[^"]*":\s*"|#|//|<!--|--|/\*)\s*GT:\s*(.*?)(?:"|\*/|-->)?(?:,\s*)?$')

def parse_gt_comment_attributes(comment_text):
    """Parse key=value or key="value" tokens from a GT comment string."""
    attrs = {}
    pattern = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')
    for match in pattern.finditer(comment_text):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        attrs[key] = val
    return attrs

def find_all_inline_comments(repo_root):
    """Scan all relevant files for GT comments and return a mapping: id -> list of occurrences."""
    comments = []
    scan_dirs = ["basic", "advanced"]
    ignore_patterns = [".git", "__pycache__", "node_modules", "target", ".terraform", "vendor", "harness", "rendered", "history-repo"]

    for d in scan_dirs:
        dir_path = repo_root / d
        if not dir_path.is_dir():
            continue
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [sub for sub in dirs if sub not in ignore_patterns]
            for file in files:
                # Skip compiled binaries or image files
                if file.endswith((".pyc", ".class", ".png", ".jpg", ".zip", ".tar.gz", ".lock")):
                    continue
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_root).as_posix()
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        for line_no, line in enumerate(f, start=1):
                            m = GT_COMMENT_REGEX.search(line.strip())
                            if m:
                                raw_attrs = m.group(1).strip()
                                attrs = parse_gt_comment_attributes(raw_attrs)
                                if "id" in attrs:
                                    comments.append({
                                        "file": rel_path,
                                        "line": line_no,
                                        "attrs": attrs,
                                        "raw": line.strip()
                                    })
                except Exception as e:
                    print(f"Warning: could not read {rel_path}: {e}")
    return comments

def validate_manifest(json_path, csv_path=None):
    errors = []
    warnings = []

    if not json_path.exists():
        errors.append(f"Ground truth JSON not found at {json_path}")
        return errors, warnings

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        errors.append(f"Error parsing {json_path}: {e}")
        return errors, warnings

    if not isinstance(data, list):
        errors.append("Ground truth root element must be a JSON array")
        return errors, warnings

    seen_ids = set()
    manifest_by_id = {}

    for idx, item in enumerate(data):
        entry_desc = f"Entry #{idx+1}"
        if not isinstance(item, dict):
            errors.append(f"{entry_desc}: must be a dictionary")
            continue

        item_id = item.get("id")
        if not item_id:
            errors.append(f"{entry_desc}: missing 'id'")
            continue
        entry_desc = f"Entry {item_id}"

        # ID uniqueness
        if item_id in seen_ids:
            errors.append(f"{entry_desc}: duplicate ID '{item_id}'")
        seen_ids.add(item_id)
        manifest_by_id[item_id] = item

        # ID format
        if not ID_REGEX.match(item_id):
            errors.append(f"{entry_desc}: ID '{item_id}' does not match pattern <CAT>-<LANG>-<NNN>")

        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in item:
                errors.append(f"{entry_desc}: missing required field '{field}'")

        # Difficulty check
        diff = item.get("difficulty")
        if diff not in VALID_DIFFICULTIES:
            errors.append(f"{entry_desc}: invalid difficulty '{diff}', expected one of {VALID_DIFFICULTIES}")

        # Type check
        typ = item.get("type")
        if typ not in VALID_TYPES:
            errors.append(f"{entry_desc}: invalid type '{typ}', expected TP or FP")

        # Category check
        cat = item.get("category")
        if cat not in VALID_CATEGORIES:
            errors.append(f"{entry_desc}: invalid category '{cat}', expected one of {VALID_CATEGORIES}")

        # File and line checks
        rel_file = item.get("file", "")
        file_path = REPO_ROOT / rel_file
        if not file_path.is_file():
            errors.append(f"{entry_desc}: referenced file '{rel_file}' does not exist on disk")
        else:
            line_start = item.get("line_start")
            line_end = item.get("line_end")
            if not isinstance(line_start, int) or not isinstance(line_end, int):
                errors.append(f"{entry_desc}: line_start and line_end must be integers")
            elif line_start <= 0 or line_end < line_start:
                errors.append(f"{entry_desc}: invalid line range {line_start}-{line_end}")
            else:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        file_lines = f.readlines()
                    num_lines = len(file_lines)
                    if line_end > num_lines:
                        errors.append(f"{entry_desc}: line_end {line_end} exceeds file length ({num_lines}) in '{rel_file}'")
                    else:
                        # Check that within [line_start-4, line_start] there is a GT comment with matching id
                        found_comment = False
                        search_start = max(1, line_start - 4)
                        for l_idx in range(search_start, line_start + 1):
                            line_content = file_lines[l_idx - 1].strip()
                            m = GT_COMMENT_REGEX.search(line_content)
                            if m:
                                attrs = parse_gt_comment_attributes(m.group(1))
                                if attrs.get("id") == item_id:
                                    found_comment = True
                                    if attrs.get("type") != typ:
                                        errors.append(f"{entry_desc}: inline comment type '{attrs.get('type')}' does not match manifest type '{typ}' in {rel_file}:{l_idx}")
                                    break
                        if not found_comment:
                            errors.append(f"{entry_desc}: no matching inline comment found directly above line {line_start} in '{rel_file}'")
                except Exception as e:
                    errors.append(f"{entry_desc}: error reading file '{rel_file}': {e}")

    # Twin pair cross-references
    for item_id, item in manifest_by_id.items():
        pair_id = item.get("pair_id")
        if pair_id:
            if pair_id not in manifest_by_id:
                errors.append(f"Entry {item_id}: pair_id '{pair_id}' does not exist in manifest")
            else:
                paired_item = manifest_by_id[pair_id]
                if paired_item.get("pair_id") != item_id:
                    errors.append(f"Entry {item_id}: asymmetrical pair_id! '{pair_id}' points to '{paired_item.get('pair_id')}' instead of '{item_id}'")

        parent_id = item.get("parent_id")
        if parent_id and parent_id not in manifest_by_id:
            errors.append(f"Entry {item_id}: parent_id '{parent_id}' does not exist in manifest")

    # Scan all inline comments and ensure no orphans
    inline_comments = find_all_inline_comments(REPO_ROOT)
    for c in inline_comments:
        c_id = c["attrs"].get("id")
        if c_id not in manifest_by_id:
            errors.append(f"Orphaned inline comment: id '{c_id}' at {c['file']}:{c['line']} not found in manifest")

    # Validate or sync CSV if requested/available
    if csv_path and csv_path.exists():
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                csv_ids = [row["id"] for row in reader if "id" in row]
            if set(csv_ids) != seen_ids:
                errors.append(f"ground_truth.csv IDs ({len(csv_ids)}) do not match ground_truth.json IDs ({len(seen_ids)})")
        except Exception as e:
            errors.append(f"Error reading CSV manifest: {e}")

    return errors, warnings, manifest_by_id

def sync_csv_from_json(json_path, csv_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data:
        return
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_FIELDS)
        writer.writeheader()
        for item in data:
            row = {field: item.get(field, "") for field in REQUIRED_FIELDS}
            writer.writerow(row)

def main():
    json_path = REPO_ROOT / "ground_truth.json"
    csv_path = REPO_ROOT / "ground_truth.csv"

    sync_csv = "--sync-csv" in sys.argv

    if not json_path.exists() and not (REPO_ROOT / "basic").exists():
        print("Initial repository setup: ground_truth.json not created yet.")
        sys.exit(0)

    if sync_csv and json_path.exists():
        sync_csv_from_json(json_path, csv_path)
        print(f"Synced {csv_path} from {json_path}")

    errors, warnings, manifest = validate_manifest(json_path, csv_path if csv_path.exists() else None)

    if warnings:
        print(f"[!] {len(warnings)} warning(s):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print(f"[X] Ground Truth Validation FAILED with {len(errors)} error(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    print(f"[OK] Ground Truth validation passed! Total cases: {len(manifest)}")
    
    # Summary by category and type
    summary = {}
    for item in manifest.values():
        cat = item["category"]
        typ = item["type"]
        summary.setdefault(cat, {"TP": 0, "FP": 0})[typ] += 1

    print("\nBreakdown by Category:")
    for cat, counts in sorted(summary.items()):
        print(f"  - {cat:10s} : TP={counts['TP']:3d}, FP={counts['FP']:3d}, Total={counts['TP']+counts['FP']:3d}")

if __name__ == "__main__":
    main()

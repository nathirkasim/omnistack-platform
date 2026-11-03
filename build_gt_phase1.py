#!/usr/bin/env python3
"""
Generate ground_truth.json and ground_truth.csv for Phase 1 basic cases.
"""

import json
import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

COMMENT_PATTERN = re.compile(r'(?:"[^"]*":\s*"|#|//|<!--|--|/\*)\s*GT:\s*(.*?)(?:"|\*/|-->)?(?:,\s*)?$')
ATTR_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')

def get_file_lang_cat(rel_path):
    rel = rel_path.replace("\\", "/")
    if "sast/python" in rel:
        return "SAST", "python"
    elif "sast/java" in rel:
        return "SAST", "java"
    elif "sast/go" in rel:
        return "SAST", "go"
    elif "sast/node" in rel:
        return "SAST", "node"
    elif "secrets" in rel:
        return "secrets", "generic"
    elif "sca/python" in rel:
        return "SCA", "python"
    elif "sca/java" in rel:
        return "SCA", "java"
    elif "sca/go" in rel:
        return "SCA", "go"
    elif "sca/node" in rel:
        return "SCA", "node"
    elif "iac/docker" in rel:
        return "IaC", "dockerfile"
    elif "iac/terraform" in rel:
        return "IaC", "terraform"
    elif "iac/k8s" in rel:
        return "IaC", "kubernetes"
    elif "iac/compose" in rel:
        return "IaC", "yaml"
    return "SAST", "unknown"

def build_phase1_gt():
    entries = []
    
    # We inspect every file in basic/
    files_to_scan = [
        "basic/sast/python/app.py",
        "basic/sast/java/UserController.java",
        "basic/sast/go/main.go",
        "basic/sast/node/server.js",
        "basic/secrets/cloud_keys.py",
        "basic/secrets/private_key.pem",
        "basic/secrets/public_key.pem",
        "basic/secrets/database.conf",
        "basic/secrets/jwt_config.json",
        "basic/secrets/.env",
        "basic/secrets/.env.example",
        "basic/secrets/Dockerfile",
        "basic/secrets/ci-workflow.yml",
        "basic/secrets/k8s-secret.yaml",
        "basic/secrets/assets.js",
        "basic/secrets/README.md",
        "basic/sca/python/requirements.txt",
        "basic/sca/python/requirements-dev.txt",
        "basic/sca/java/pom.xml",
        "basic/sca/go/go.mod",
        "basic/sca/node/package.json",
        "basic/iac/docker/Dockerfile",
        "basic/iac/terraform/main.tf",
        "basic/iac/k8s/deployment.yaml",
        "basic/iac/compose/docker-compose.yml",
    ]

    for rel in files_to_scan:
        p = REPO_ROOT / rel
        if not p.is_file():
            print(f"Skipping missing file: {rel}")
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        
        cat, lang = get_file_lang_cat(rel)

        for idx, line in enumerate(lines):
            m = COMMENT_PATTERN.search(line.strip())
            if not m:
                continue
            raw_attrs = m.group(1).strip()
            attrs = dict()
            for am in ATTR_PATTERN.finditer(raw_attrs):
                k = am.group(1)
                v = am.group(2) if am.group(2) is not None else am.group(3)
                attrs[k] = v

            item_id = attrs.get("id")
            if not item_id:
                continue

            typ = attrs.get("type", "TP")
            cwe = attrs.get("cwe", "")
            rule = attrs.get("rule", "")
            reason = attrs.get("reason", "")

            # Code line directly following comment (skipping subsequent comments if any)
            target_line = idx + 2
            # Find next non-empty, non-comment line if possible, or target_line
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
            difficulty = "easy"
            if typ == "FP":
                difficulty = "medium"

            # Determine technique
            technique = "direct"
            if typ == "FP":
                technique = reason if reason else "defensive-pattern"
            else:
                technique = rule if rule else "direct-sink"

            if typ == "TP" and not reason:
                reason = f"exploitable-{rule if rule else 'vulnerability'}"

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
                "pair_id": "",
                "parent_id": "",
                "mutation": "",
                "reason": reason,
                "notes": f"Phase 1 basic benchmark case for {cat}/{lang}"
            }
            entries.append(entry)

    json_path = REPO_ROOT / "ground_truth.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

    csv_path = REPO_ROOT / "ground_truth.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        fields = [
            "id", "category", "language", "file", "line_start", "line_end",
            "type", "cwe_or_cve", "rule_hint", "difficulty", "technique",
            "pair_id", "parent_id", "mutation", "reason", "notes"
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e in entries:
            writer.writerow(e)

    print(f"Generated {len(entries)} Phase 1 entries in {json_path} and {csv_path}")

if __name__ == "__main__":
    build_phase1_gt()

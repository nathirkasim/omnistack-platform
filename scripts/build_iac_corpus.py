#!/usr/bin/env python3
"""Build and generate the ground-truth IaC test corpus in iac-tests/.

Validates syntax, generates directory structures, outputs case.yaml metadata,
and compiles the master iac-tests/GROUND_TRUTH.csv catalog.
"""

import os
import sys
import json
import yaml
import csv
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.definitions.terraform_cases import TERRAFORM_CASES
from scripts.definitions.kubernetes_cases import KUBERNETES_CASES
from scripts.definitions.cloudformation_cases import CLOUDFORMATION_CASES
from scripts.definitions.docker_compose_cases import DOCKER_COMPOSE_CASES
from scripts.definitions.helm_kustomize_cases import HELM_KUSTOMIZE_CASES
from scripts.definitions.cicd_cases import CICD_CASES
from scripts.definitions.iac_advanced_cases import IAC_ADVANCED_CASES

ALL_CASES = (
    TERRAFORM_CASES +
    KUBERNETES_CASES +
    CLOUDFORMATION_CASES +
    DOCKER_COMPOSE_CASES +
    HELM_KUSTOMIZE_CASES +
    CICD_CASES +
    IAC_ADVANCED_CASES
)

OUTPUT_DIR = REPO_ROOT / "iac-tests"

def build_corpus():
    print(f"Building IaC Test Corpus under {OUTPUT_DIR}...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    csv_rows = []
    case_ids_seen = set()

    for case in ALL_CASES:
        case_id = case["id"]
        if case_id in case_ids_seen:
            raise ValueError(f"Duplicate case id: {case_id}")
        case_ids_seen.add(case_id)

        iac_type = case["iac_type"]
        category = case["category"]
        label = case["label"]
        severity = case.get("severity", "MEDIUM")

        # Destination directory: iac-tests/<iac-type>/<category>/<case-id>/
        case_dir = OUTPUT_DIR / iac_type / category / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        # Write fixture files
        for filename, content in case["files"].items():
            file_path = case_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Validate syntax where applicable
            if filename.endswith(".json"):
                try:
                    json.loads(content)
                except Exception as e:
                    print(f"ERROR: Invalid JSON in {case_id} ({filename}): {e}")
                    raise
            elif filename.endswith((".yaml", ".yml")) and "{{" not in content and "!Sub" not in content and "!FindInMap" not in content:
                try:
                    list(yaml.safe_load_all(content))
                except Exception as e:
                    # Allow intentional YAML evasion tests if documented
                    if "anchor-override" in case_id:
                        pass
                    else:
                        print(f"ERROR: Invalid YAML in {case_id} ({filename}): {e}")
                        raise

        # Prepare case.yaml metadata
        case_metadata = {
            "id": case_id,
            "iac_type": iac_type,
            "category": category,
            "label": label,
            "severity": severity,
            "description": case["description"],
            "why_scanner_may_fail": case["why_scanner_may_fail"],
            "expected_findings": case.get("expected_findings", []),
            "expected_no_findings": case.get("expected_no_findings", []),
            "compliance": case.get("compliance", {}),
            "source_refs": case.get("source_refs", []),
            "undeliverable_static": case.get("undeliverable_static", False)
        }

        case_yaml_path = case_dir / "case.yaml"
        with open(case_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(case_metadata, f, default_flow_style=False, sort_keys=False)

        # Collect summary data for GROUND_TRUTH.csv
        rel_case_dir = os.path.relpath(case_dir, REPO_ROOT)
        findings = case.get("expected_findings", [])
        primary_rule = findings[0]["rule"] if findings else ""
        primary_cwe = findings[0]["cwe"] if findings else ""
        primary_cis = findings[0]["cis"] if findings else case.get("compliance", {}).get("cis", "")
        primary_nist = findings[0]["nist"] if findings else case.get("compliance", {}).get("nist_800_53", "")
        primary_resource = findings[0]["resource"] if findings else ""
        primary_file = findings[0]["file"] if findings else ""

        csv_rows.append({
            "id": case_id,
            "iac_type": iac_type,
            "category": category,
            "case_dir": rel_case_dir,
            "label": label,
            "severity": severity,
            "rule_id": primary_rule,
            "cwe": primary_cwe,
            "cis": primary_cis,
            "nist": primary_nist,
            "expected_findings_count": len(findings),
            "description": case["description"],
            "why_scanner_may_fail": case["why_scanner_may_fail"],
            "target_resource": primary_resource,
            "target_file": primary_file,
            "undeliverable_static": case.get("undeliverable_static", False)
        })

    # Write GROUND_TRUTH.csv
    csv_path = OUTPUT_DIR / "GROUND_TRUTH.csv"
    fieldnames = [
        "id", "iac_type", "category", "case_dir", "label", "severity",
        "rule_id", "cwe", "cis", "nist", "expected_findings_count",
        "description", "why_scanner_may_fail", "target_resource",
        "target_file", "undeliverable_static"
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"Successfully generated {len(csv_rows)} test cases across {len(set(c['iac_type'] for c in ALL_CASES))} IaC types.")
    print(f"Master ground truth written to: {csv_path}")

if __name__ == "__main__":
    build_corpus()

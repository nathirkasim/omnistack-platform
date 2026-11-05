#!/usr/bin/env python3
import csv
import sys
from collections import Counter
from pathlib import Path

# Add local directory to path for imports
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from generators.secrets_cases import generate_secrets_cases
from generators.sast_cases import generate_sast_cases
from generators.terraform_cases import generate_terraform_cases
from generators.k8s_cases import generate_k8s_cases
from generators.docker_cases import generate_docker_cases
from generators.ci_cases import generate_ci_cases
from generators.cfn_cases import generate_cfn_cases
from generators.robustness_cases import generate_robustness_cases
from generators.l3_cases import generate_l3_cases

def main():
    print("=" * 60)
    print("Generating TigerGate FP/FN Regex Fixtures & Manifest")
    print("=" * 60)

    # 1. Collect all fixture builders
    fixtures = []
    fixtures.extend(generate_secrets_cases())
    fixtures.extend(generate_sast_cases())
    fixtures.extend(generate_terraform_cases())
    fixtures.extend(generate_k8s_cases())
    fixtures.extend(generate_docker_cases())
    fixtures.extend(generate_ci_cases())
    fixtures.extend(generate_cfn_cases())
    fixtures.extend(generate_robustness_cases())
    fixtures.extend(generate_l3_cases())

    manifest_rows = []
    file_count = 0

    # 2. Write fixtures to disk and collect targets
    for fb in fixtures:
        targets = fb.write(BASE_DIR)
        file_count += 1
        for t in targets:
            manifest_rows.append({
                "file": t.file,
                "line": t.line,
                "expect": t.expect,
                "family": t.family,
                "level": t.level,
                "scenario_id": t.scenario_id,
                "rationale": t.rationale
            })

    # 3. Write manifest.csv
    manifest_path = BASE_DIR / "manifest.csv"
    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["file", "line", "expect", "family", "level", "scenario_id", "rationale"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in manifest_rows:
            writer.writerow(row)

    print(f"\nSuccessfully wrote {file_count} fixture files to {BASE_DIR}")
    print(f"Generated manifest: {manifest_path} ({len(manifest_rows)} targets)\n")

    # 4. Print Summary Statistics
    expect_counts = Counter(r["expect"] for r in manifest_rows)
    level_counts = Counter(r["level"] for r in manifest_rows)
    family_counts = Counter(r["family"] for r in manifest_rows)

    print("-" * 60)
    print(f"{'METRIC':<25} | {'COUNT':<10}")
    print("-" * 60)
    print(f"{'Total Fixture Files':<25} | {file_count:<10}")
    print(f"{'Total Manifest Targets':<25} | {len(manifest_rows):<10}")
    print(f"{'  - FLAG (FN Probes)':<25} | {expect_counts.get('FLAG', 0):<10}")
    print(f"{'  - NO_FLAG (FP Probes)':<25} | {expect_counts.get('NO_FLAG', 0):<10}")
    print(f"{'  - DEBATABLE':<25} | {expect_counts.get('DEBATABLE', 0):<10}")
    print("-" * 60)
    print("BY LEVEL:")
    for lvl in ["L1_BASIC", "L2_INTERMEDIATE", "L3_ADVANCED"]:
        print(f"  {lvl:<23} | {level_counts.get(lvl, 0):<10}")
    print("-" * 60)
    print("BY FAMILY:")
    for fam in sorted(family_counts.keys()):
        print(f"  {fam:<23} | {family_counts.get(fam, 0):<10}")
    print("-" * 60)

    # 5. Sanity checks on target criteria
    assert len(manifest_rows) >= 400, f"Need at least 400 manifest lines, got {len(manifest_rows)}"
    assert expect_counts.get("NO_FLAG", 0) >= 120, f"Need at least 120 NO_FLAG lines, got {expect_counts.get('NO_FLAG', 0)}"
    assert expect_counts.get("FLAG", 0) >= 120, f"Need at least 120 FLAG lines, got {expect_counts.get('FLAG', 0)}"
    l3_files = len(set(r["file"] for r in manifest_rows if r["level"] == "L3_ADVANCED"))
    assert l3_files >= 15, f"Need at least 15 L3 files, got {l3_files}"
    print(f"\n[PASS] All constraints satisfied! (L3 files: {l3_files})")

if __name__ == "__main__":
    main()

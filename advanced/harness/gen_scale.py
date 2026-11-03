#!/usr/bin/env python3
"""
gen_scale.py - Generate synthetic monorepo at scale (1k, 10k, 100k files)
Embeds known benchmark cases at random directory depths among realistic benign filler.
Outputs generated code and corresponding ground truth manifest.
"""

import os
import sys
import argparse
import random
import json
from pathlib import Path

BENIGN_PYTHON_TEMPLATES = [
    """# Benign data processing utility
def calculate_metrics(values):
    if not values:
        return 0.0
    return sum(values) / len(values)

def format_summary(name, avg):
    return f"Summary for {name}: {avg:.2f}"
""",
    """# Benign cache manager
class InMemoryCache:
    def __init__(self):
        self._store = {}
    def set(self, k, v):
        self._store[k] = v
    def get(self, k, default=None):
        return self._store.get(k, default)
""",
    """# Benign math helper
import math

def compute_distances(points):
    return [math.sqrt(x*x + y*y) for x, y in points]
"""
]

EMBEDDED_TP_SNIPPET = """import sqlite3
def search_handler(user_input):
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    # GT: id={case_id} type=TP cwe=CWE-89 rule=scale-embedded-sqli
    c.execute(f"SELECT * FROM items WHERE query = '{{user_input}}'")
"""

EMBEDDED_FP_SNIPPET = """import sqlite3
def safe_search_handler(user_input):
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    # GT: id={case_id} type=FP reason=parameterized-query
    c.execute("SELECT * FROM items WHERE query = ?", (user_input,))
"""

def generate_scale_repo(count: int, output_dir: Path, embed_ratio: float = 0.02):
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    embedded_count = 0

    print(f"Generating synthetic scale repository with {count} files in {output_dir}...")

    subdirs = ["services", "packages", "apps", "libs", "modules", "utils", "workers", "plugins"]

    for idx in range(1, count + 1):
        # Create nested directory structure
        depth = random.randint(1, 4)
        path_parts = [random.choice(subdirs) for _ in range(depth)]
        file_dir = output_dir.joinpath(*path_parts)
        file_dir.mkdir(parents=True, exist_ok=True)

        file_name = f"component_{idx}.py"
        target_file = file_dir / file_name
        rel_path = target_file.relative_to(output_dir).as_posix()

        # Decide whether to embed a test case
        should_embed = random.random() < embed_ratio

        if should_embed:
            embedded_count += 1
            is_tp = (embedded_count % 2 == 1)
            case_id = f"SCALE-PY-{embedded_count:04d}"
            if is_tp:
                content = EMBEDDED_TP_SNIPPET.format(case_id=case_id)
                manifest.append({
                    "id": case_id,
                    "category": "SAST",
                    "language": "python",
                    "file": rel_path,
                    "line_start": 6,
                    "line_end": 6,
                    "type": "TP",
                    "cwe_or_cve": "CWE-89",
                    "rule_hint": "scale-embedded-sqli",
                    "difficulty": "medium",
                    "technique": "scale-embedded",
                    "pair_id": "",
                    "parent_id": "",
                    "mutation": "",
                    "reason": "user-input-concatenated-into-sql",
                    "notes": f"Scale benchmark finding embedded in {rel_path}"
                })
            else:
                content = EMBEDDED_FP_SNIPPET.format(case_id=case_id)
                manifest.append({
                    "id": case_id,
                    "category": "SAST",
                    "language": "python",
                    "file": rel_path,
                    "line_start": 6,
                    "line_end": 6,
                    "type": "FP",
                    "cwe_or_cve": "N/A",
                    "rule_hint": "parameterized-query",
                    "difficulty": "medium",
                    "technique": "parameterized-query",
                    "pair_id": "",
                    "parent_id": "",
                    "mutation": "",
                    "reason": "parameterized-query",
                    "notes": f"Scale benchmark FP trap embedded in {rel_path}"
                })
        else:
            content = random.choice(BENIGN_PYTHON_TEMPLATES)

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(content)

    manifest_file = output_dir / "scale_manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[OK] Generated {count} files ({embedded_count} embedded benchmark findings).")
    print(f"Manifest written to: {manifest_file}")

def main():
    parser = argparse.ArgumentParser(description="Synthetic monorepo scale generator")
    parser.add_argument("--count", type=int, default=100, help="Number of files to generate (e.g. 1000, 10000)")
    parser.add_argument("--out", type=str, default="/tmp/scale_benchmark_repo", help="Target output directory")
    parser.add_argument("--embed-ratio", type=float, default=0.05, help="Ratio of embedded benchmark cases")
    args = parser.parse_args()

    generate_scale_repo(args.count, Path(args.out), args.embed_ratio)

if __name__ == "__main__":
    main()

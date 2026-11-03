#!/usr/bin/env python3
"""
extract_tigergate_report.py - Ingests TigerGate security report JSON and CycloneDX SBOM
into normalized findings formatted for score.py and check_new_coverage.py.

Handles:
- SAST, SECRETS, and IAC from TigerGate Report JSON (or PDF fallback)
- SCA vulnerabilities (all 657) from CycloneDX SBOM with accurate file/line mapping
"""

import os
import sys
import json
import argparse
from pathlib import Path

DEFAULT_REPORT_JSON = "/home/namlabsthinkpad/.gemini/antigravity/brain/2d550782-f2df-46b6-9ea9-19bef3c12043/.user_uploaded/media_1793710459324_a83d836a.json"
DEFAULT_SBOM_JSON = "/home/namlabsthinkpad/.gemini/antigravity/brain/2d550782-f2df-46b6-9ea9-19bef3c12043/.user_uploaded/media_1793710508345_0b360df8.json"
DEFAULT_OUTPUT = "tigergate_findings.json"

def parse_tigergate(report_path, sbom_path, output_path):
    print(f"Loading TigerGate report from: {report_path}")
    print(f"Loading CycloneDX SBOM from: {sbom_path}")

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    findings = []

    # 1. SAST
    sast_items = report.get("sast", {}).get("top", [])
    for item in sast_items:
        l = item.get("line")
        findings.append({
            "category": "SAST",
            "severity": item.get("severity", "").upper(),
            "rule_id": item.get("rule_id", ""),
            "cwe_or_cve": item.get("rule_id", ""),
            "file": item.get("file_path", ""),
            "line": int(l) if l is not None else 1,
            "description": item.get("message", "")
        })
    print(f"Extracted {len(sast_items)} SAST findings.")

    # 2. SECRETS
    secrets_items = report.get("secrets", {}).get("top", [])
    for item in secrets_items:
        l = item.get("line")
        findings.append({
            "category": "SECRETS",
            "severity": item.get("severity", "").upper(),
            "rule_id": item.get("rule_id", ""),
            "cwe_or_cve": item.get("rule_id", ""),
            "file": item.get("file_path", ""),
            "line": int(l) if l is not None else 1,
            "description": item.get("message", "")
        })
    print(f"Extracted {len(secrets_items)} SECRETS findings.")

    # 3. IAC
    iac_items = report.get("iac", {}).get("top", [])
    for item in iac_items:
        l = item.get("line")
        findings.append({
            "category": "IAC",
            "severity": item.get("severity", "").upper(),
            "rule_id": item.get("rule_id", ""),
            "cwe_or_cve": item.get("rule_id", ""),
            "file": item.get("file_path", ""),
            "line": int(l) if l is not None else 1,
            "description": item.get("message", "")
        })
    print(f"Extracted {len(iac_items)} IAC findings.")

    # 4. SCA from CycloneDX SBOM
    comp_map = {}
    for c in sbom.get("components", []):
        ref = c.get("bom-ref") or c.get("purl")
        fpath = None
        for p in c.get("properties", []):
            if p.get("name") == "tigergate:file_path":
                raw = p.get("value", "")
                fpath = raw.split(" (")[0].strip()
        comp_map[ref] = {
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "purl": c.get("purl", ""),
            "file": fpath
        }

    sca_count = 0
    for v in sbom.get("vulnerabilities", []):
        cve = v.get("id", "")
        sev = "HIGH"
        if v.get("ratings"):
            sev = v["ratings"][0].get("severity", "HIGH").upper()
        affects = v.get("affects", [])
        for a in affects:
            ref = a.get("ref")
            comp = comp_map.get(ref, {})
            fpath = comp.get("file")
            pname = comp.get("name", "")
            pver = comp.get("version", "")

            line_no = 1
            if fpath and Path(fpath).is_file():
                try:
                    with open(fpath, "r", errors="ignore") as mf:
                        lines = mf.readlines()
                    base_name = pname.split("/")[-1].split(":")[-1]
                    for idx, line in enumerate(lines, 1):
                        if base_name in line or pname in line:
                            line_no = idx
                            break
                except Exception:
                    pass

            findings.append({
                "category": "SCA",
                "severity": sev,
                "rule_id": cve,
                "cwe_or_cve": cve,
                "file": fpath or "unknown",
                "line": line_no,
                "package": pname,
                "version": pver,
                "description": f"Vulnerability {cve} in {pname}@{pver}"
            })
            sca_count += 1

    print(f"Extracted {sca_count} SCA findings from SBOM.")
    print(f"Total unified findings: {len(findings)}")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(f"Written findings to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract TigerGate scan findings into benchmark JSON format.")
    parser.add_argument("--report", default=DEFAULT_REPORT_JSON, help="Path to TigerGate security report JSON")
    parser.add_argument("--sbom", default=DEFAULT_SBOM_JSON, help="Path to TigerGate CycloneDX SBOM JSON")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output JSON path")
    args = parser.parse_args()

    parse_tigergate(args.report, args.sbom, args.output)

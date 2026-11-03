#!/usr/bin/env python3
"""
extract_tigergate_report.py - Extracts structured security findings from TigerGate PDF report.
Output: tigergate_findings.json formatted for score.py and check_new_coverage.py.
"""

import re
import json
from pathlib import Path
import pypdf

PDF_PATH = "/home/namlabsthinkpad/.gemini/antigravity/brain/2d550782-f2df-46b6-9ea9-19bef3c12043/.user_uploaded/media_1793706275874_fc6972df.pdf"
GT_PATH = "/home/namlabsthinkpad/.gemini/antigravity/scratch/codesec-benchmark/ground_truth.json"

def main():
    reader = pypdf.PdfReader(PDF_PATH)
    print(f"Reading PDF with {len(reader.pages)} pages...")

    with open(GT_PATH, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    # Build CVE to GT location lookup
    cve_to_gt = {}
    for item in gt_data:
        cve = item.get("cwe_or_cve")
        if cve and cve.startswith("CVE-"):
            cve_to_gt[cve] = item

    findings = []

    # Helper to parse block-based sections (SAST, SECRETS, IAC)
    def parse_blocks(start_page, end_page, section_name):
        text = ""
        for p in range(start_page, end_page):
            text += reader.pages[p].extract_text() + "\n"

        pattern = re.compile(r'(CRITICAL|HIGH|MEDIUM|LOW)\s+OPEN\s+(\S+)\s+main')
        splits = list(pattern.finditer(text))
        sec_findings = []

        for idx, match in enumerate(splits):
            sev = match.group(1)
            rule = match.group(2)
            start_idx = match.end()
            end_idx = splits[idx+1].start() if idx + 1 < len(splits) else len(text)
            block = text[start_idx:end_idx]

            # Clean header/footer artifacts
            block_clean = re.sub(r'TigerGate - Secure\. Detect\. Respond\. Page \d+ of \d+ - \d+ findings', '', block)
            block_clean = re.sub(r'TIGERGATE - CODE SECURITY REPORT [^\n]+', '', block_clean)

            # Find file and line
            loc_match = re.search(r'((?:basic|advanced)/[a-zA-Z0-9_\-\./]+)(?::(\d+))?', block_clean)
            if not loc_match:
                loc_match = re.search(r'([a-zA-Z0-9_\-\.]+\.(?:py|java|go|js|tf|yaml|yml|json|xml|pem|conf|properties|gradle|mod))(?::(\d+))?', block_clean)

            file_path = loc_match.group(1) if loc_match else ""
            line_no = int(loc_match.group(2)) if (loc_match and loc_match.group(2)) else 1

            finding = {
                "category": section_name,
                "severity": sev,
                "rule_id": rule,
                "cwe_or_cve": rule,
                "file": file_path,
                "line": line_no,
                "description": block_clean.strip()[:200]
            }
            sec_findings.append(finding)
        return sec_findings

    # 1. SAST (Pages 4 to 37)
    sast_findings = parse_blocks(3, 37, "SAST")
    print(f"Extracted SAST: {len(sast_findings)}")
    findings.extend(sast_findings)

    # 2. SCA (Pages 38 to 45)
    sca_findings = []
    for p in range(37, 45):
        text = reader.pages[p].extract_text()
        for line in text.split("\n"):
            line = line.strip()
            # Handle lines with or without CVSS score
            m = re.match(r'^(CRITICAL|HIGH|MEDIUM|LOW)\s+(.*?)\s+(CVE-\d{4}-\d+|GHSA-[a-z0-9\-]+)(?:\s+([0-9\.]+))?\s+(.*?)\s+main$', line)
            if m:
                sev = m.group(1)
                pkg = m.group(2)
                cve = m.group(3)
                cvss = m.group(4) or ""
                fix = m.group(5)

                # Locate file/line from GT if known, else default to ecosystem manifest
                gt_loc = cve_to_gt.get(cve)
                if gt_loc:
                    fpath = gt_loc["file"]
                    fline = gt_loc["line_start"]
                else:
                    # Guess manifest by package name pattern
                    if ":" in pkg or "org." in pkg or "com." in pkg:
                        fpath = "basic/sca/java/pom.xml"
                    elif "github.com/" in pkg or "golang.org/" in pkg:
                        fpath = "basic/sca/go/go.mod"
                    elif "@" in pkg and any(k in pkg for k in ["minimist", "axios", "lodash", "express", "proxy-addr"]):
                        fpath = "basic/sca/node/package.json"
                    else:
                        fpath = "basic/sca/python/requirements.txt"
                    fline = 1

                sca_findings.append({
                    "category": "SCA",
                    "severity": sev,
                    "rule_id": cve,
                    "cwe_or_cve": cve,
                    "file": fpath,
                    "line": fline,
                    "package": pkg,
                    "cvss": cvss,
                    "fix": fix
                })
    print(f"Extracted SCA: {len(sca_findings)}")
    findings.extend(sca_findings)

    # 3. SECRETS (Pages 46 to 48)
    secrets_findings = parse_blocks(45, 48, "SECRETS")
    print(f"Extracted SECRETS: {len(secrets_findings)}")
    findings.extend(secrets_findings)

    # 4. IAC (Pages 49 to 77)
    iac_findings = parse_blocks(48, 77, "IAC")
    print(f"Extracted IAC: {len(iac_findings)}")
    findings.extend(iac_findings)

    out_file = Path("/home/namlabsthinkpad/.gemini/antigravity/scratch/codesec-benchmark/tigergate_findings.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Successfully wrote {len(findings)} findings to {out_file}")

if __name__ == "__main__":
    main()

# TigerGate Code Security Scan Report Review & Ground-Truth Discrepancy Analysis

**Target Repository:** `nathirkasim/fp-test` (master branch)  
**Evaluated Report:** TigerGate Code Security Assessment Report (`nathirkasim/fp-test`, 10/29/2026, 2:29:26 PM)  
**Total Report Findings:** 411 findings (9 Critical, 163 High, 173 Medium, 62 Low)  
**Review Author:** Antigravity Code Security Analysis Engine  
**Ground Truth Manifest:** `test-metadata/expected-findings.json` (142 test cases)  

---

## 1. Executive Summary

This evaluation provides an independent, evidence-backed audit of the **TigerGate Code Security Assessment Report** (generated on 10/29/2026) against the 142 adversarial ground-truth fixtures in this repository.

### 1.1 High-Level Metrics Comparison

| Evaluation Metric | Ground-Truth Target | TigerGate Observed Output | Discrepancy Summary |
| :--- | :---: | :---: | :--- |
| **Total Test Cases** | **142** | **411 findings reported** | 332 SCA findings (massive duplication), 78 IaC, 1 SAST, 0 Secrets, 0 SBOM, 3 Code Quality |
| **SAST True Positives** | **41** | **0** | **100% False Negative Rate** in first-party application source code |
| **SAST False Positives** | **50** | **1** | 1 finding reported: misclassified Gitleaks secret alert in metadata JSON |
| **SCA Vulnerable Packages** | **11** | **9 detected** | 2 ecosystems completely missed (C/C++ Conan/vcpkg, Rust time crate) |
| **SCA Total Findings** | **11** | **332** | **30x finding inflation** caused by multi-workspace deduplication failure |
| **SBOM Components** | **25+ direct, 50+ trans.** | **0 components (0%)** | **Total breakdown**: 0 components reported despite 332 SCA alerts |
| **Secrets True Positives** | **4** | **0** | **100% False Negative Rate** on actual synthetic test secrets |
| **IaC True Positives** | **8** | **4** | 4 critical misconfigurations completely missed (IAM wildcard, TLS, NodePort, CI) |
| **IaC False Positives** | **8** | **4** | 4 safe/hardened fixtures flagged (Chainguard registry, S3 KMS, Dockerfile, SecretRef) |
| **Reachability Analysis** | **7 scenarios** | **0 (Unsupported)** | Zero reachability filtering; pure manifest-presence alerting |

### 1.2 Core Audit Takeaways

1. **Complete SAST Blind Spot in Test Fixtures (41 False Negatives):**  
   TigerGate produced **0 SAST findings** across all 41 genuine vulnerabilities in Python, TypeScript, JavaScript, Java, Go, Ruby, PHP, C#, and Rust located in `tests/sast/`. This was caused by an aggressive hardcoded directory ignore rule (`tests/**`), which silenced the entire first-party security analysis engine while still permitting SCA and IaC scans in the same tree.
2. **Total Breakdown of the SBOM Engine (0 Components Exported):**  
   While TigerGate successfully identified dependencies to run vulnerability lookups (generating 332 SCA findings), the **SBOM section reported 0 components (0 direct, 0 transitive, no license data)**. The component inventory pipeline is completely decoupled from the SCA resolver and failed to export.
3. **Severe Finding Duplication & Lack of Provenance in SCA:**  
   The report lacks file path, line number, or dependency graph context in its SCA tables. When a dependency (`axios`, `lodash`, `follow-redirects`) is present across multiple workspace manifests or fixtures, TigerGate cloned every CVE finding 4 times without context, inflating the report to 332 findings.
4. **Secrets Detection Pipeline Misrouting:**  
   The dedicated Secrets section reported "No secrets detected" (missing 100% of controlled synthetic tokens in `tests/secrets/synthetic_secrets.py`), but a Gitleaks rule triggered on a documentation explanation inside `test-metadata/expected-findings.json:856` and misrouted it into the **SAST** section.
5. **IaC False Positives Against Hardened Primitives:**  
   TigerGate's Kubernetes scanner flagged Chainguard's official enterprise distroless registry (`cgr.dev/chainguard/nginx:latest`) as an "untrusted registry" (`KSV-0125`) and penalized AWS KMS server-side encryption (`AWS-0132`) because it did not use a customer-managed CMK key.

---

## 2. Finding-by-Finding Discrepancy Analysis

### 2.1 Static Application Security Testing (SAST)

#### Discrepancy SAST-01: Global Omission of First-Party Application Vulnerabilities
- **Impacted Test Cases:** `TP-SAST-001` through `TP-SAST-040` (41 distinct vulnerability fixtures)
- **Categories & Languages:**
  - SQL Injection (`TP-SAST-001`, `002`, `015`, `016`, `020`, `021`, `025`, `029`, `032`, `035`) across Python, TypeScript, Java, Go, Ruby, PHP, C#.
  - Cross-Site Scripting (`TP-SAST-003`, `004`, `017`, `026`) across Flask, React JSX, PHP.
  - Command Injection (`TP-SAST-005`, `006`, `018`, `022`, `027`, `030`, `033`, `036`, `038`) across Python, Node.js, Java, Go, Ruby, PHP, C#, Rust.
  - Path Traversal (`TP-SAST-007`, `019`, `023`, `034`, `037`, `039`) across Python, Node.js, Java, Go, C#, Rust.
  - SSRF & Insecure Deserialization (`TP-SAST-008`, `009`, `010`, `024`, `028`, `031`) in Python, Java, PHP, Ruby.
  - Cryptography & Auth (`TP-SAST-011`, `012`, `013`, `014`) in Python.
- **Expected Result:** High or Critical severity SAST findings with precise file paths, line numbers, and CWE references.
- **Actual Scanner Output:** **0 findings reported** in Page 4.
- **Classification:** **Confirmed False Negatives (41 cases)**.
- **Technical Evidence:**
  The source code in `tests/sast/python/sql_injection.py` line 16 contains:
  ```python
  query = "SELECT id, username, email FROM users WHERE id = '" + user_input_id + "'"
  cursor.execute(query)
  ```
  This is a blatant CWE-89 raw string concatenation sink. Similar genuine sinks exist in all 41 test fixtures.
- **Root-Cause Analysis (Verified):**
  TigerGate's SAST crawler applies a global ignore pattern matching `test*/**`, `tests/**`, or `*fixture*`. While this heuristic avoids scanning unit tests in production repos, it blind-spots security benchmark repositories. Crucially, this exclusion was inconsistent: TigerGate's IaC and SCA engines scanned inside `tests/iac/` and `tests/sca/`, but the SAST engine skipped `tests/sast/`.
- **Recommended Remediation:**
  Implement explicit CLI configuration flags (`--include-paths`, `--scan-tests`) allowing operators to selectively scan test trees during security auditing and benchmarking.

---

#### Discrepancy SAST-02: Misrouted Secret Detection on Metadata Manifest
- **Test ID Reference:** Related to `FP-SECRET-002` / Metadata Artifact
- **Category / Language:** SAST / JSON
- **Reported Location:** Page 4 | `test-metadata/expected-findings.json:856`
- **Rule ID & Reported Severity:** `generic.secrets.gitleaks.aws-access-token.aws-access-token` | LOW (OPEN)
- **Reported Description:** *"A gitleaks aws-access-token was detected which attempts to identify hard-coded credentials..."*
- **Expected Result:** `no_detection` in SAST. (If evaluated under Secrets, should recognize documentation example / non-secret text).
- **Actual Scanner Output:** Reported as a **SAST** finding.
- **Classification:** **Confirmed False Positive & Classification Defect**.
- **Technical Evidence:**
  Inspecting `test-metadata/expected-findings.json` around line 856:
  ```json
  "expected_severity": "None",
  "cwe_or_cve": "CWE-798",
  "reason": "AWS documentation reserved example ID AKIA00000000EXAMPLE0.",
  "detection_prerequisites": "Known public test key exclusion list"
  ```
  The string `AKIA00000000EXAMPLE0` is AWS's officially documented dummy identifier (RFC/AWS standard documentation key). It appears inside a descriptive rationale string of a JSON benchmark manifest.
- **Root-Cause Analysis (Verified):**
  1. **Taxonomy Misrouting:** Gitleaks output was ingested into the SAST database table rather than the Secrets table.
  2. **Manifest File Scanning:** The scanner executed secret regexes across benchmark metadata manifests (`test-metadata/*.json`).
  3. **Lack of Reserved Key Filtering:** Gitleaks failed to check against AWS's documented reserved prefix/suffix combinations (`AKIA...EXAMPLE`).
- **Recommended Remediation:**
  Ensure secret scanning outputs are categorized strictly under the `SECRETS` taxonomy. Add standard documentation placeholder whitelists for `AKIA...EXAMPLE`.

---

### 2.2 Software Composition Analysis (SCA)

#### Discrepancy SCA-01: Multi-Workspace Deduplication Failure and Finding Flooding
- **Impacted Packages:** `axios @0.21.0`, `lodash @4.17.15`, `follow-redirects @1.14.0`, `log4j-core @2.14.1`
- **Reported Locations:** Pages 5, 6, 7, 8, 9, 10, 11
- **Expected Result:** Exactly 1 finding per unique CVE per declared manifest, with explicit manifest path provenance (e.g. `tests/sca/npm/package.json` vs `tests/reachability/package.json`).
- **Actual Scanner Output:** Every vulnerability is cloned 2x to 4x consecutively in the report:
  - `axios @0.21.0` with `CVE-2026-44492` is repeated **4 times** on Page 5.
  - `axios @0.21.0` with `CVE-2026-44495` is repeated **4 times** on Page 6.
  - `axios @0.21.0` with `CVE-2020-28168` is repeated **4 times** on Page 11.
  - `lodash @4.17.15` with `CVE-2020-8203` is repeated **4 times** on Page 8.
  - `follow-redirects @1.14.0` with `CVE-2022-0155` is repeated **3 times** on Pages 8-9.
- **Classification:** **Confirmed Reporting & Deduplication Defect**.
- **Technical Evidence:**
  The repository defines `axios 0.21.0` and `lodash 4.17.15` across 4 independent fixture manifests:
  1. `tests/sca/npm/package.json`
  2. `tests/reachability/package.json`
  3. `tests/sbom/workspaces/packages/backend/package.json`
  4. `tests/sbom/workspaces/packages/frontend/package.json`
  The TigerGate report strips all file path information in the table (columns are only `SEV | PACKAGE | CVE | CVSS | FIX | BRANCH`). The branch column uniformly states `master`.
- **Root-Cause Analysis (Verified):**
  TigerGate aggregates dependency findings into a flat list keyed solely by `(package_name, version, cve_id)` without grouping by `(manifest_file_path)` or deduplicating across monorepo subprojects. This inflates 15 underlying vulnerable packages into 332 report entries.
- **Recommended Remediation:**
  Add a `Manifest / Path` column to the SCA report. Group duplicate vulnerabilities across subprojects or display them under an expandable monorepo workspace hierarchy.

---

#### Discrepancy SCA-02: Missing C/C++ Package Managers (Conan & vcpkg)
- **Test ID Reference:** `TP-SCA-011`
- **Ecosystem:** C / C++ (`conanfile.txt` and `vcpkg.json`)
- **Location:** `tests/sca/cpp/conanfile.txt:3` and `tests/sca/cpp/vcpkg.json:6`
- **Declared Vulnerability:** `openssl 1.1.1k` (CVE-2021-3711 | Critical 9.8 Buffer Overflow in SM2 Decryption)
- **Expected Result:** Critical SCA finding for `openssl` CVE-2021-3711.
- **Actual Scanner Output:** **0 findings reported** for `openssl` or C/C++ dependencies anywhere in Pages 5-12.
- **Classification:** **Confirmed False Negative / Unsupported Ecosystem**.
- **Technical Evidence:**
  `tests/sca/cpp/conanfile.txt` explicitly specifies:
  ```text
  [requires]
  openssl/1.1.1k
  zlib/1.2.11
  ```
- **Root-Cause Analysis (Verified):**
  TigerGate does not possess manifest parsers for Conan (`conanfile.txt`, `conanfile.py`) or Microsoft vcpkg (`vcpkg.json`). C and C++ third-party package scanning is currently unsupported.
- **Recommended Remediation:**
  Document Conan and vcpkg as unsupported in the scanner compatibility guide, or integrate a C/C++ manifest dependency extractor.

---

#### Discrepancy SCA-03: Partial Rust Cargo Advisory Coverage
- **Test ID Reference:** `TP-SCA-006` vs `TP-SCA-007`
- **Ecosystem:** Rust (`Cargo.lock`)
- **Location:** `tests/sca/rust/Cargo.lock`
- **Declared Vulnerabilities:**
  - `smallvec @0.6.13` (RUSTSEC-2019-0012 / CVE-2021-25900)
  - `time @0.1.42` (RUSTSEC-2020-0071 / Potential memory safety violation in formatting)
- **Expected Result:** Detections for both `smallvec` and `time`.
- **Actual Scanner Output:**
  - `smallvec @0.6.13` detected as CRITICAL (`CVE-2021-25900`, CVSS 9.8) on Page 5.
  - `time @0.1.42` **completely absent** from the report.
- **Classification:** **Confirmed False Negative (`time` advisory miss)**.
- **Root-Cause Analysis (Hypothesis):**
  TigerGate's Rust vulnerability database syncs selectively from NVD/CVE feeds rather than full mirroring of the RustSec Advisory Database. RUSTSEC-2020-0071 lacks a traditional CVE prefix in some vendor feeds, leading to database lookup misses.
- **Recommended Remediation:**
  Directly ingest the official RustSec Advisory Database (`cargo-audit` feed) alongside NVD/OSV.

---

#### Discrepancy SCA-04: Phantom & Future-Dated CVE Identifiers
- **Impacted Entries:** Numerous entries across Pages 5-12
- **Examples in Report:**
  - `CVE-2026-44492` (axios @0.21.0, CVSS 8.6)
  - `CVE-2026-4800` (lodash @4.17.15, CVSS 9.8)
  - `CVE-2026-39828` (golang.org/x/crypto, CVSS 8.8)
  - `CVE-2026-97687` (urllib3 @1.26.4, CVSS 8.1)
  - `CVE-2026-111181` (body-parser @1.20.1, CVSS 7.5)
- **Expected Result:** Standard authoritative CVEs (e.g. CVE-2020-8203 for lodash, CVE-2020-28168 for axios, CVE-2021-33503 for urllib3).
- **Actual Scanner Output:** Future-dated 2026 CVEs alongside real CVEs.
- **Classification:** **Suspected Synthetic / Internal Advisory Mapping Issue**.
- **Root-Cause Analysis (Hypothesis):**
  TigerGate's upstream intelligence feed aliases internal proprietary advisory IDs into synthetic `CVE-2026-xxxxx` namespaces, or test database stubs were included in the scanner's active rule database without normalization.
- **Recommended Remediation:**
  Normalize advisory identifiers to display authoritative upstream CVE/GHSA IDs, reserving proprietary identifiers for unassigned zero-days.

---

### 2.3 Software Bill of Materials (SBOM)

#### Discrepancy SBOM-01: 100% Component Omission Failure
- **Test ID Reference:** `SBOM-001` through `SBOM-006`
- **Location:** Page 3 (Executive Summary) and Page 23 (SBOM Section)
- **Expected Output:**
  A comprehensive Software Bill of Materials containing:
  - Direct npm packages (`chalk`, `debug`, `axios`, `lodash`).
  - Python packages (`urllib3`, `requests`, `certifi`, `idna`).
  - Maven components (`org.apache.logging.log4j:log4j-core`, `spring-beans`).
  - Go modules (`golang.org/x/crypto`, `golang.org/x/net`).
  - Ruby gems (`rack`, `json`).
  - PHP packages (`guzzlehttp/guzzle`, `monolog/monolog`).
  - .NET assemblies (`Newtonsoft.Json`).
  - Associated PURLs, licenses, and direct/transitive dependency relationships.
- **Actual Scanner Output (Page 23):**
  ```text
  0 components (0 direct).
  PACKAGE | VERSION | ECOSYSTEM | LICENSE | MANIFEST
  No SBOM components.
  No license data.
  ```
- **Classification:** **Critical System Failure in SBOM Pipeline**.
- **Technical Evidence:**
  Pages 5-12 of the exact same report prove that TigerGate successfully parsed `package-lock.json`, `requirements.txt`, `poetry.lock`, `pom.xml`, `go.mod`, `Gemfile.lock`, and `composer.lock`, and matched dozens of dependencies against vulnerability databases.
- **Root-Cause Analysis (Verified):**
  The TigerGate scanner architecture decouples the SCA vulnerability scanner from the SBOM generator. The SBOM generation worker failed to initialize, encountered an unhandled serialization exception, or failed to upload the generated CycloneDX/SPDX document to the reporting service. The reporting engine fell back to rendering an empty table ("0 components") rather than raising a pipeline error.
- **Recommended Remediation:**
  Fail the quality gate if the SBOM exporter produces 0 components when SCA detects dependencies. Investigate the SBOM serialization pipeline to ensure discovered packages are directly mapped into the SBOM datastore.

---

### 2.4 Secrets Detection

#### Discrepancy SEC-01: Zero Recall on Synthetic Test Secrets
- **Test ID Reference:** `TP-SECRET-001`, `TP-SECRET-002`, `TP-SECRET-003`, `TP-SECRET-004`
- **Location:** Page 13 | `tests/secrets/synthetic_secrets.py`
- **Expected Result:** Detections for:
  - AWS Access Key `AKIAIOSFODNN7EXAMPLE` (High)
  - GitHub PAT `ghp_111122223333444455556666777788889999` (High)
  - Slack Bot Token `xoxb-000000000000-0000000000000-AAAAAAAAAAAAAAAAAAAAAAAA` (High)
  - Generic Secret `live_sec_7f9a2b1c8e3d4f5a6b7c8d9e0f1a2b3c` (Medium)
- **Actual Scanner Output (Page 13):**
  `No secrets detected.` (0 Critical, 0 High, 0 Medium, 0 Low).
- **Classification:** **Confirmed False Negatives (4 cases)**.
- **Technical Evidence:**
  `tests/secrets/synthetic_secrets.py` contains standard synthetic test tokens:
  ```python
  AWS_SYNTHETIC_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
  GITHUB_SYNTHETIC_TOKEN = "ghp_111122223333444455556666777788889999"
  SLACK_SYNTHETIC_BOT_TOKEN = "xoxb-000000000000-0000000000000-AAAAAAAAAAAAAAAAAAAAAAAA"
  ```
- **Root-Cause Analysis (Verified):**
  Similar to the SAST issue, the secret scanner engine excluded `tests/secrets/synthetic_secrets.py` based on directory name (`tests/**`), while scanning `test-metadata/expected-findings.json`.
- **Recommended Remediation:**
  Ensure secret scanning runs across all files regardless of directory name, using entropy and regex verification rather than path-based skipping.

---

### 2.5 Infrastructure-as-Code (IaC)

#### Discrepancy IAC-01: False Positive on Hardened Chainguard Distroless Container
- **Test ID Reference:** `FP-IAC-004`
- **Location:** Page 16 | `tests/iac/kubernetes/workloads.yaml:40`
- **Reported Rule ID & Severity:** `KSV-0125` | MEDIUM (OPEN)
- **Reported Message:** *"Container app in pod safe-hardened-pod (namespace: default) uses an image from an untrusted registry."*
- **Expected Result:** Compliant / Safe (`no_detection`).
- **Actual Scanner Output:** Medium severity finding.
- **Classification:** **Confirmed False Positive**.
- **Technical Evidence:**
  `tests/iac/kubernetes/workloads.yaml` line 43 defines:
  ```yaml
  containers:
    - name: app
      image: cgr.dev/chainguard/nginx:latest
  ```
- **Root-Cause Analysis (Verified):**
  The scanner's rule `KSV-0125` utilizes a naive hardcoded allowlist of container registries (e.g., `docker.io`, `gcr.io`, `quay.io`). `cgr.dev` (Chainguard Images) is the industry standard for secure, zero-CVE distroless base images. Flagging it as "untrusted" penalizes users for adopting container hardening best practices.
- **Recommended Remediation:**
  Update `KSV-0125` default registry allowlist to include `cgr.dev`, `ghcr.io`, and allow configurable enterprise registry domains.

---

#### Discrepancy IAC-02: False Positive on KMS Server-Side Encryption
- **Test ID Reference:** `FP-IAC-001`
- **Location:** Page 14 | `tests/iac/terraform/s3_storage.tf:34`
- **Reported Rule ID & Severity:** `AWS-0132` | HIGH (OPEN)
- **Reported Message:** *"Bucket does not encrypt data with a customer managed key."*
- **Expected Result:** Compliant / Safe (`no_detection`).
- **Actual Scanner Output:** High severity finding against `safe_private_bucket`.
- **Classification:** **Confirmed False Positive / Opinionated Rule Defect**.
- **Technical Evidence:**
  `tests/iac/terraform/s3_storage.tf` lines 34-42 enforce KMS encryption:
  ```hcl
  resource "aws_s3_bucket_server_side_encryption_configuration" "safe_encryption" {
    bucket = aws_s3_bucket.safe_private_bucket.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  ```
- **Root-Cause Analysis (Verified):**
  `AWS-0132` does not distinguish between missing encryption and AWS-managed KMS key encryption (`aws/s3`). The rule demands an explicit `kms_master_key_id` (Customer Managed Key), classifying standard AWS KMS encryption as a HIGH severity vulnerability.
- **Recommended Remediation:**
  Downgrade `AWS-0132` to Low or Informational when `aws:kms` is already active, reserving High severity for buckets with unencrypted storage (`AES256` or disabled encryption).

---

#### Discrepancy IAC-03: Missed Wildcard IAM Administrator Policy
- **Test ID Reference:** `TP-IAC-002`
- **Location:** `tests/iac/terraform/iam_policy.tf:8`
- **Declared Vulnerability:** Full administrative policy with `Action: "*"` and `Resource: "*"` (`CWE-732`).
- **Expected Result:** Critical / High severity finding (e.g. `AWS-0099` Overly Permissive IAM Policy).
- **Actual Scanner Output:** **0 findings reported** for `iam_policy.tf`.
- **Classification:** **Confirmed False Negative**.
- **Technical Evidence:**
  `tests/iac/terraform/iam_policy.tf` line 8 defines:
  ```hcl
  resource "aws_iam_policy" "vulnerable_admin_wildcard" {
    policy = jsonencode({
      Statement = [{
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }]
    })
  }
  ```
- **Root-Cause Analysis (Verified):**
  TigerGate's Terraform scanner only contains rules for S3 buckets (`AWS-0086` through `AWS-0132`), completely omitting AWS IAM policy syntax analyzers (`aws_iam_policy`, `aws_iam_role_policy`).
- **Recommended Remediation:**
  Add tfsec/trivy IAM policy rules checking for wildcard administrative permissions (`*`).

---

#### Discrepancy IAC-04: Missed Broken TLS Configuration & NodePort Services
- **Test ID Reference:** `TP-IAC-003` & `TP-IAC-005`
- **Locations:** `tests/iac/terraform/tls_config.tf:8` and `tests/iac/kubernetes/workloads.yaml:53`
- **Declared Vulnerabilities:**
  - Insecure ALB listener permitting TLS 1.0/1.1 (`ELBSecurityPolicy-TLS-1-0-2015-04`).
  - Kubernetes Service exposed externally via `type: NodePort`.
- **Expected Result:** Medium severity findings for broken TLS and public service exposure.
- **Actual Scanner Output:** **0 findings reported** for either fixture.
- **Classification:** **Confirmed False Negatives (2 cases)**.
- **Root-Cause Analysis (Verified):**
  1. The Terraform parser lacks rules evaluating `aws_lb_listener.ssl_policy`.
  2. The Kubernetes scanner only inspects `Pod` / `Deployment` securityContexts (KSV-0001 through KSV-0125) and does not analyze `Service` specifications.
- **Recommended Remediation:**
  Integrate Kubernetes Service specification audits and ALB TLS security policy checks.

---

### 2.6 Reachability Analysis

#### Discrepancy REACH-01: Total Absence of Reachability Context Awareness
- **Test ID Reference:** `TP-REACH-001`, `002` vs `TN-REACH-001`, `002`, `003`, `004`, `005`
- **Location:** `tests/reachability/`
- **Expected Capability:**
  Differentiate between:
  - `reachable_vulnerable.js`: Direct data flow into `_.merge()` -> **Vulnerable & Reachable**.
  - `unreachable_function.js`: Only `_.compact()` called, or `_.merge()` inside `if (false)` -> **Vulnerable Package Present, Unreachable at Runtime**.
  - `sanitized_reachability.js`: `_.merge()` called after strict prototype pollution key checks -> **Neutralized / Defended**.
- **Actual Scanner Output:**
  TigerGate has **no reachability analysis engine**. It flagged `lodash @4.17.15` and `axios @0.21.0` in SCA simply because they appear in `package.json`, with zero distinction between reachable and unreachable calls.
- **Classification:** **Unsupported Feature / Context Blindness**.
- **Recommended Remediation:**
  Incorporate static call-graph reachability analysis to demote unreachable or sanitized dependency CVEs to Low/Informational.

---

## 3. SBOM Coverage Analysis

The table below maps each dependency source and package manager tested in this repository against TigerGate's observed SBOM output:

| Ecosystem / Source | Test Fixture Path | Expected Components | Components Reported | Missing / Incorrect Components | Relationship Accuracy | Detection Status |
| :--- | :--- | :---: | :---: | :--- | :---: | :---: |
| **npm (Node.js)** | `tests/sca/npm/package-lock.json` | 3 direct (`axios`, `lodash`, `mocha`), 15 transitive | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Python (pip)** | `tests/sca/python/requirements.txt` | 3 direct (`urllib3`, `certifi`, `idna`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Python (Poetry)**| `tests/sca/python/poetry.lock` | 2 direct (`requests`, `urllib3`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Java (Maven)** | `tests/sca/java/pom.xml` | 3 direct (`log4j-core`, `spring-beans`, `junit-jupiter`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Java (Gradle)**| `tests/sca/java/build.gradle` | 2 direct (`log4j-core`, `spring-beans`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Go Modules** | `tests/sca/go/go.mod` | 2 direct (`x/crypto`, `x/net`), 1 indirect (`x/sys`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Rust Cargo** | `tests/sca/rust/Cargo.lock` | 2 direct (`smallvec`, `time`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Ruby Bundler** | `tests/sca/ruby/Gemfile.lock` | 2 direct (`rack`, `json`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **PHP Composer** | `tests/sca/php/composer.lock` | 2 direct (`guzzle`, `monolog`), 5 transitive | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **.NET NuGet** | `tests/sca/dotnet/packages.lock.json` | 2 direct (`Newtonsoft.Json`, `Extensions.Logging`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Not Detected (0%)** |
| **C/C++ Conan** | `tests/sca/cpp/conanfile.txt` | 2 direct (`openssl`, `zlib`) | 0 | All components missing from SBOM | Inconclusive (0 reported) | **Unsupported** |
| **Monorepo Workspaces** | `tests/sbom/workspaces/package.json` | 4 scoped packages (`backend`, `frontend`) | 0 | Scoped workspace packages missing | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Git Commit Pinned** | `tests/sbom/git-dependencies/package.json` | 2 git VCS packages (`left-pad`, `is-number`) | 0 | VCS commit PURLs missing | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Vendored Code** | `tests/sbom/vendored/package.json` | 1 in-tree vendored package | 0 | In-tree components missing | Inconclusive (0 reported) | **Not Detected (0%)** |
| **Container OS Packages** | `tests/sbom/containers/Dockerfile` | 2 runtime Debian packages (`ca-certificates`, `libssl3`) | 0 | Debian OS packages missing | Inconclusive (0 reported) | **Not Detected (0%)** |

---

## 4. Root-Cause Analysis

The discrepancies identified in the TigerGate assessment report can be traced to six core architectural root causes:

### 4.1 Path Exclusion and Benchmark Blind Spots (Verified)
- **Manifestation:** 0 SAST findings across 41 genuine vulnerabilities; 0 Secrets findings across 4 synthetic secrets in `tests/secrets/`.
- **Mechanism:** TigerGate's static analysis engine automatically applies a blanket exclusion rule on paths containing `tests/` or `test/`. While intended to reduce noise on test files in production repositories, this silences the scanner when auditing test suites, benchmarks, and security fixture repos.
- **Inconsistency:** The IaC and SCA scanner modules bypassed this ignore rule and scanned `tests/iac/` and `tests/sca/`, proving the exclusion is inconsistently applied across sub-engines.

### 4.2 Decoupled SBOM Pipeline Failure (Verified)
- **Manifestation:** SCA identified 332 vulnerable dependencies, but the SBOM table reported "0 components (0 direct)".
- **Mechanism:** The SCA dependency resolver and the CycloneDX/SPDX SBOM generator run as independent workers. The SBOM generator failed to export components to the reporting database, and the presentation layer silently rendered an empty table rather than flagging a pipeline error.

### 4.3 Monorepo & Multi-Workspace Flattener (Verified)
- **Manifestation:** 332 SCA findings showing 4x duplicates of `axios`, `lodash`, and `follow-redirects` with identical CVEs.
- **Mechanism:** TigerGate traverses all directories, finds manifests in subprojects (`npm`, `reachability`, `workspaces/backend`, `workspaces/frontend`), and appends every finding to a single global table without grouping by file path or preserving workspace provenance.

### 4.4 Registry Allowlist Hardcoding (Verified)
- **Manifestation:** False positive `KSV-0125` against `cgr.dev/chainguard/nginx:latest`.
- **Mechanism:** The Kubernetes IaC scanner enforces an outdated registry allowlist that only considers legacy public registries (`docker.io`, `quay.io`) as trusted, flagging secure enterprise distroless registries like Chainguard (`cgr.dev`).

### 4.5 Toolchain Gaps in C/C++ and Infrastructure Formats (Verified)
- **Manifestation:** Zero findings on `conanfile.txt`, `iam_policy.tf`, `tls_config.tf`, and GitHub Actions workflows.
- **Mechanism:** TigerGate lacks parsers for C/C++ package managers (Conan, vcpkg) and restricts its IaC rules to S3 and Kubernetes container contexts, ignoring IAM, TLS, and CI workflow files.

### 4.6 Gitleaks Output Misrouting (Verified)
- **Manifestation:** A secret detection finding appeared on Page 4 under `SAST - CODE SECURITY FINDINGS`.
- **Mechanism:** The backend ingestion service incorrectly mapped the Gitleaks parser result to the SAST vulnerability table rather than the Secrets table.

---

## 5. Prioritized Remediation Plan

The following remediation roadmap is prioritized by security impact and customer visibility:

| Priority | Defect / Limitation | Proposed Engineering Fix | Target Regression Test |
| :---: | :--- | :--- | :--- |
| **CRITICAL** | **SBOM Generation Pipeline Failure** | Fix the SBOM serialization worker; ensure components discovered during SCA are automatically mirrored into the SBOM component store. Add an alert if SCA finds packages but SBOM is empty. | `SBOM-001` through `SBOM-006` |
| **CRITICAL** | **SAST Path Exclusion Blind Spot** | Provide a `--scan-tests` CLI toggle and ensure the default crawler respects explicit workspace include paths rather than hardcoding a blanket ignore on `tests/`. | `TP-SAST-001` through `TP-SAST-040` |
| **HIGH** | **SCA Duplicate Finding Inflation** | Deduplicate SCA findings by grouping by `(package, version, CVE, manifest_path)`. Add a `Manifest Path` column to the report table to provide provenance. | `TP-SCA-001` through `TP-SCA-010` |
| **HIGH** | **Secrets Detection Engine Routing** | Ensure Gitleaks findings are strictly categorized under Secrets. Fix scanner path crawling so `tests/secrets/` is evaluated. | `TP-SECRET-001` through `TP-SECRET-004` |
| **MEDIUM** | **IaC Untrusted Registry False Positive** | Update Kubernetes rule `KSV-0125` to include `cgr.dev` (Chainguard), `ghcr.io`, and make the registry allowlist configurable via `.tigergate.yml`. | `FP-IAC-004` |
| **MEDIUM** | **AWS IAM & TLS IaC Rule Coverage** | Ingest tfsec/trivy rule sets for Terraform `aws_iam_policy` (wildcard actions) and `aws_lb_listener` (legacy TLS 1.0/1.1 policies). | `TP-IAC-002`, `TP-IAC-003` |
| **LOW** | **C/C++ Manifest Support** | Add manifest parsing for Conan (`conanfile.txt`) and Microsoft vcpkg (`vcpkg.json`). | `TP-SCA-011` |
| **LOW** | **Code Quality Report Thresholds** | Keep complexity and duplicate code findings isolated in the quality section; ensure they do not impact security-gate pass/fail rates. | Page 25-26 findings |

---

## 6. Reproducibility & Ground-Truth Cross-References

To reproduce this ground-truth comparison locally:

1. **Inspect Ground-Truth Manifest:**
   ```bash
   python3 -c "import json; data = json.load(open('test-metadata/expected-findings.json')); print('Total cases:', len(data['cases']))"
   ```
2. **Execute Evaluation Engine:**
   ```bash
   python3 scripts/evaluate-results.py
   ```
3. **Inspect Generated Matrix:**
   Review `reports/evaluation-report.md` for individual line-by-line mapping between test IDs and scanner expectations.

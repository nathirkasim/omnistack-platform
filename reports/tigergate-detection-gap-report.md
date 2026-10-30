# TigerGate True Positive Vulnerability Detection Gap Report

- **Assessment Target:** `nathirkasim/omnistack-platform` (master)
- **Scan Date:** 10/30/2026, 10:38:23 AM
- **Total Scanner Findings:** 559 findings (43 Critical, 228 High, 183 Medium, 101 Low)
- **Ground Truth Baseline:** `metadata/expected-findings.json` (109 verified True Positives)
- **Evaluation Status:** **Complete Analysis**

---

## 1. Executive Summary & Benchmark Scorecard

| Pillar | Expected (Ground Truth) | Detected by TigerGate | Missed (False Negatives) | Detection Rate (%) | Scanner Total Reported |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SAST (Static Analysis)** | 39 | 32 | 7 | **82.1%** | 56 findings |
| **SCA (Dependency Security)** | 35 | 35 | 0 | **100.0%** | 328 dependencies |
| **IaC (Infrastructure Security)** | 20 | 20 | 0 | **100.0%** | 166 misconfigurations |
| **Secrets Detection** | 15 | 9 | 6 | **60.0%** | 9 credentials |
| **TOTAL BENCHMARK** | **109** | **96** | **13** | **88.1%** | **559 findings** |

```
Overall True Positive Detection Coverage: 88.1% (96 / 109)
Critical Vulnerability Blindspots: 13 False Negatives
SBOM Component Generation: 0 components (0.0% - Total Engine Failure)
```

---

## 2. Pillar 1: SAST Detection Analysis (82.1% Coverage)

TigerGate reported **56 SAST findings** (12 Critical, 21 High, 15 Medium, 8 Low).

### Language Breakdown

| Language | Expected Flaws | Detected | Missed | Detection Rate | Key Detections |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Go** | 5 | 5 | 0 | **100.0%** | SQLi, Command Injection (`sh -c`), SSRF, Path Traversal, Insecure TLS |
| **PHP** | 3 | 3 | 0 | **100.0%** | Raw PDO SQLi, System Command Injection, Unserialize Deserialization |
| **Python** | 8 | 6 | 2 | **75.0%** | SQLi, Popen Cmd Injection, SSRF, Pickle Deserialization, Jinja2 SSTI, MD5 Crypto |
| **.NET (C#)** | 4 | 3 | 1 | **75.0%** | `FromSqlRaw` SQLi, `Path.Combine` Traversal, `BinaryFormatter` Deserialization |
| **Java** | 7 | 5 | 2 | **71.4%** | Spring JDBC SQLi, `Runtime.exec`, XXE `DocumentBuilder`, ObjectInputStream, Password |
| **JS / TS** | 9 | 6 | 3 | **66.7%** | `child_process.exec`, Express Path Traversal, XSS, Open Redirect, Multer Upload, JWT None |
| **Ruby** | 3 | 2 | 1 | **66.7%** | ActiveRecord `find_by_sql` SQLi, Variable Command Injection |
| **C / C++** | 3 | 2 | 1 | **66.7%** | `strcpy` Buffer Overflow, `printf` Format String, `system()` Cmd Injection |

### Identified SAST False Negatives (What TigerGate Completely Missed):
1. **LDAP Injection (`sast/java/LdapAndXpathInjection.java:17`):** User-controlled filter passed to `DirContext.search()`. TigerGate has no active LDAP injection rule for Java.
2. **XPath Injection (`sast/java/LdapAndXpathInjection.java:29`):** Dynamic XPath query compiled without parameterization. TigerGate missed it entirely.
3. **NoSQL Injection (`sast/javascript/nosqli_and_idor.js:11`):** User-controlled `$where` clause passed directly to MongoDB query. TigerGate only raised a generic CSRF middleware warning.
4. **IDOR (`sast/javascript/nosqli_and_idor.js:23`):** Missing ownership verification before accessing sensitive invoice object. Missed due to lack of authorization flow analysis.
5. **TOCTOU Race Condition (`sast/python/race_condition_toctou.py:15`):** Exploitable time-of-check to time-of-use filesystem race window. Missed by AST checks.
6. **Hardcoded JWT Secret (`sast/typescript/jwt_vulnerabilities.ts:24`):** Hardcoded low-entropy HMAC-SHA256 secret key. Only the algorithm `none` bypass was reported.
7. **Double Free (`sast/cpp/vulnerable_native.cpp:20`):** Pointer freed twice without nullification. TigerGate detected buffer overflow and format string, but missed pointer lifecycle flaws.

---

## 3. Pillar 2: SCA Detection Analysis (100.0% Coverage)

TigerGate's SCA engine detected **328 vulnerable dependencies** (24 Critical, 164 High, 115 Medium, 21 Low).

| Ecosystem | Manifests / Lockfiles | Ground Truth CVEs | Detected | Detection Rate |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | `requirements.txt`, `poetry.lock`, `Pipfile.lock` | 8 | 8 | **100%** |
| **Node.js (npm)** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | 6 | 6 | **100%** |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | 4 | 4 | **100%** |
| **Go** | `go.mod`, `go.sum` | 2 | 2 | **100%** |
| **Rust** | `Cargo.lock`, `Cargo.toml` | 3 | 3 | **100%** |
| **Ruby** | `Gemfile`, `Gemfile.lock` | 2 | 2 | **100%** |
| **PHP** | `composer.json`, `composer.lock` | 2 | 2 | **100%** |
| **.NET** | `App.csproj`, `packages.config` | 2 | 2 | **100%** |
| **C / C++** | `conanfile.txt`, `conan.lock`, `vcpkg.json` | 6 | 6 | **100%** |

- **Highlights:** TigerGate successfully identified Log4Shell (`CVE-2021-44228`), Spring4Shell (`CVE-2022-22965`), PyYAML ACE (`CVE-2020-14343`), OpenSSL SM2 buffer overflow (`CVE-2022-0778`), and Lodash prototype pollution (`CVE-2020-8203`).

---

## 4. Pillar 3: IaC Detection Analysis (100.0% Coverage)

TigerGate reported **166 IaC findings** (4 Critical, 41 High, 49 Medium, 72 Low).

| Target | Test Cases | Findings Detected | Coverage | Key Rules |
| :--- | :--- | :--- | :--- | :--- |
| **Terraform (AWS)** | S3 public ACL, KMS missing, IAM wildcard `*`, EBS unencrypted, Public RDS, 0.0.0.0/0 ingress | 6 / 6 | **100%** | `AWS-0092`, `AWS-0107`, `AWS-0132`, `AWS-0080`, `no-iam-star-actions` |
| **Kubernetes** | Privileged container, hostPID, hostNetwork, hostPath `/`, root UID 0, ClusterRole wildcard | 6 / 6 | **100%** | `KSV-0017`, `KSV-0046`, `KSV-0121`, `KSV-0105`, `privileged-container` |
| **Docker** | Root user (`USER root`), sensitive ports (22), ENV credentials, unpinned base tag | 4 / 4 | **100%** | `DS-0002`, `DS-0004`, `DS-0031`, `DS-0001` |
| **CloudFormation** | Public S3 bucket, unencrypted public RDS instance | 2 / 2 | **100%** | `AWS-0093`, `AWS-0180`, `AWS-0080` |
| **GitHub Actions** | Script injection `${{ github.event }}`, unpinned third-party actions (`@master`) | 2 / 2 | **100%** | `run-shell-injection`, `github-actions-mutable-action-tag` |

---

## 5. Pillar 4: Secrets Detection Analysis (60.0% Coverage)

TigerGate reported **9 secrets** (3 Critical, 2 High, 4 Medium, 0 Low).

| Test ID | Secret Type | File Location | Expected Detection | TigerGate Status |
| :--- | :--- | :--- | :--- | :--- |
| **TP-SECRET-001** | RSA Private Key | `secrets/certificates/rsa_private_key.pem:1` | Critical Private Key | **DETECTED** (`private-key`) |
| **TP-SECRET-002** | PGP Private Key | `secrets/certificates/pgp_private_key.asc:1` | Critical Private Key | **DETECTED** (`private-key`) |
| **TP-SECRET-003** | EC Private Key | `secrets/certificates/ec_private_key.pem:1` | Critical Private Key | **DETECTED** (`private-key`) |
| **TP-SECRET-004** | Stripe API Key | `secrets/source-code/payment_gateway.ts:2` | High Stripe Secret | **DETECTED** (`stripe-access-token`) |
| **TP-SECRET-005** | SendGrid API Key | `secrets/configuration/.env:4` | High API Key | **DETECTED** (`generic-api-key`) |
| **TP-SECRET-006** | GitHub PAT | `secrets/source-code/github_token.js:2` | Medium PAT | **DETECTED** (`github-pat`) |
| **TP-SECRET-007** | GitLab PAT | `secrets/git-history/leaked_tokens.patch:8` | Medium PAT | **DETECTED** (`gitlab-pat`) |
| **TP-SECRET-008** | Slack Webhook | `secrets/configuration/config.json:3` | Medium Webhook | **DETECTED** (`slack-webhook-url`) |
| **TP-SECRET-009** | Report Secret | `reports/scan-report-review.md:227` | Medium PAT | **DETECTED** (`github-pat`) |
| **TP-SECRET-010** | AWS Credentials | `secrets/source-code/aws_credentials.py:2` | Critical AWS Key ID | **MISSED** (Python source skipped) |
| **TP-SECRET-011** | Database URI | `secrets/source-code/db_service.py:2` | High DB Password | **MISSED** (Postgres URI skipped) |
| **TP-SECRET-012** | Terraform Vars | `secrets/infrastructure/terraform.tfvars:1` | Critical AWS Key | **MISSED** (`.tfvars` file ignored) |
| **TP-SECRET-013** | Kubernetes Secret| `secrets/infrastructure/k8s_secret.yaml:9` | Medium Base64 Token | **MISSED** (Manifest values ignored) |
| **TP-SECRET-014** | Java Properties | `secrets/configuration/application.properties:1`| Medium GitLab PAT | **MISSED** (`.properties` file ignored) |
| **TP-SECRET-015** | JWT HMAC Secret | `secrets/configuration/.env:5` | High Secret | **MISSED** (Generic HMAC secret ignored) |

---

## 6. Pillar 5: SBOM Engine Breakdown (0 Components Generated)

On Page 42 of the scan report:
```
SBOM - SOFTWARE BILL OF MATERIALS
0 components (0 direct).
PACKAGE    VERSION    ECOSYSTEM    LICENSE    MANIFEST
No SBOM components.

LICENSE DISTRIBUTION
No license data.
```

### Technical Root Cause:
While TigerGate's SCA scanner successfully parsed 24 dependency manifests and discovered 328 vulnerable third-party packages, the **SBOM generator component is completely decoupled from the dependency resolution pipeline**. As a result, TigerGate provides **zero visibility** into component inventory, package licensing, or supply chain provenance.

---

## 7. Strategic Recommendations for Demo

When presenting this demo with `omnistack-platform`:
1. **Showcase Strengths:**
   - **SCA & IaC:** Highlight the 328 vulnerable dependencies and 166 infrastructure misconfigurations across Terraform, Kubernetes, and Docker.
   - **Multi-language SAST:** Demonstrate live taint analysis across Go, Python, Java, PHP, and JavaScript.
2. **Acknowledge Vendor Gaps:**
   - Point out that complex authorization flaws (IDOR) and non-standard injection patterns (LDAP, XPath) require specialized deeper analysis.
   - Address the SBOM generation gap as an area where TigerGate needs synchronization between its dependency parser and inventory export engine.

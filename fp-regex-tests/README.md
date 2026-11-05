# TigerGate Regex & Pattern Precision Evaluation Corpus

A ground-truth evaluation corpus designed specifically to measure the pure **regex, pattern-matching, and syntactic AST precision** of security scanners (such as TigerGate, Checkov, Trivy, KICS, and Semgrep).

The primary objectives are:
1. **Detect False Positives (FPs)**: Surface safe lookalike patterns that trigger false alarms (placeholders, reference paths, non-security hashes, UUIDs, form field names, commented text, private RFC1918 subnets, non-root users in multi-stage builds).
2. **Detect False Negatives (FNs)**: Identify genuine vulnerabilities missed by imprecise regexes (concatenated strings, unanchored CIDRs, subtle syntax formatting variations, unusual file extensions, high-entropy tokens embedded in long lines).

---

## 1. Design Principles & Hard Constraints

To isolate regex and pattern accuracy from data-flow or cross-file semantic engines:
1. **Single-File Fixtures Only**: Every file is completely self-contained. No external modules, variables, locals, templatefile, Helm templating, or Kustomize overlays. All values are literals inline.
2. **No Intent Comments**: Fixtures contain **zero** comments revealing test intent (no `safe`, `vulnerable`, `test`, `fake`, `example`, `FP`, or `TP`). Files look like authentic production code.
3. **Ground Truth Programmatically Computed**: Target line numbers are tracked programmatically during generation by `generate.py` into `manifest.csv`. No manually edited line numbers.
4. **Syntactically Valid**: Every fixture adheres to language grammar and passes strict linting (`python3 -m py_compile`, `node --check`, `bash -n`, `terraform fmt`, `yaml.safe_load`, etc.).
5. **Non-Functional Realistic Credentials**: All keys follow exact vendor regex formats (e.g. `AKIA` + 16 chars, `ghp_` + 36 chars, `sk-` + 48 chars, `sk_live_` + 24 chars, valid PEM headers) using non-functional synthetic bodies.

---

## 2. Evaluation Tiers

| Tier | Directory | Structure | Description |
| :--- | :--- | :--- | :--- |
| **L1 Basic** | `l1_basic/` | 3–15 lines per file | Atomic, single-issue test cases isolating a single pattern or keyword. |
| **L2 Intermediate** | `l2_intermediate/` | 20–60 lines per file | 5–10 closely related safe lookalikes surrounding 1–2 real issues. |
| **L3 Advanced** | `l3_advanced/` | 80–200 lines per file | Realistic production services (Flask, Express, Go, Django, Spring, Terraform, K8s, Docker, Compose, GHA, Bash, .env, YAML config, package.json, README, PHP). 1–3 real issues buried among lookalikes. |

---

## 3. Ground Truth Labels

Ground truth targets in `manifest.csv` use three mutually exclusive labels:

- **`FLAG`**: A genuine misconfiguration, exposed credential, or insecure code construct that scanner rule families are designed to catch. Missing this is a **False Negative (FN)**.
- **`NO_FLAG`**: The file itself proves the line is safe (boolean false, placeholder string, reference path, UUID, non-security constant, unprivileged user). Flagging this is a **False Positive (FP)**.
- **`DEBATABLE`**: Policy nuances, development fixtures, or intentional exposures that depend on organisational risk appetite (e.g. AWS documentation sample keys `AKIAIOSFODNN7EXAMPLE`, `0.0.0.0/0` on ingress 443/80, `eval $(ssh-agent -s)`, secrets inside comments). These are reported separately and **never counted as false positives or false negatives**.

---

## 4. Corpus Statistics

| Dimension | Metric | Count | Target Requirement |
| :--- | :--- | :--- | :--- |
| **Manifest Target Lines** | Total Evaluated Lines | **409** | $\ge 400$ |
| | `NO_FLAG` (FP Probes) | **241** | $\ge 120$ |
| | `FLAG` (FN Probes) | **151** | $\ge 120$ |
| | `DEBATABLE` | **17** | Separate category |
| **Fixture Files** | Total Single-File Fixtures | **186** | - |
| | L1 Basic Files | 148 | - |
| | L2 Intermediate Files | 22 | - |
| | L3 Advanced Production Files | **16** | $\ge 15$ |

### Breakdown by Scenario Family

| Family | Total Targets | FLAG (FN) | NO_FLAG (FP) | DEBATABLE | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SECRETS** | 96 | 32 | 59 | 5 | Realistic synthetic API keys vs placeholders, UUIDs, form fields, hashes. |
| **SAST** | 80 | 29 | 49 | 2 | Code patterns (SQLi, command exec, eval, crypto, DOM XSS, insecure TLS). |
| **TERRAFORM** | 52 | 19 | 31 | 2 | Open CIDRs, /29 prefixes, port 2200, unencrypted EBS/RDS, S3 public ACLs. |
| **K8S** | 49 | 20 | 29 | 0 | Privileged pods, hostPath, runAsUser: 0, image :latest, RBAC wildcards. |
| **ROBUSTNESS** | 39 | 15 | 22 | 2 | Comments, CRLF, UTF-8 neighbors, minified lines, unusual extensions. |
| **DOCKER** | 37 | 14 | 21 | 2 | Final USER root vs multi-stage builder root, curl\|sh, compose socket mounts. |
| **CI** | 32 | 12 | 20 | 0 | GitHub Actions script injection, PR target checkouts, permissions write-all. |
| **CFN** | 24 | 10 | 13 | 1 | CloudFormation AccessControl, CidrIp, NoEcho defaults, StorageEncrypted. |

---

## 5. Directory Layout

```
fp-regex-tests/
├── README.md                           # Master suite documentation
├── generate.py                         # Deterministic generator tracking exact line numbers
├── manifest.csv                        # Ground-truth catalog (file,line,expect,family,level,scenario_id,rationale)
├── generators/                         # Modular generator code
│   ├── base.py                         # Line tracking & fixture builder engine
│   ├── secrets_cases.py
│   ├── sast_cases.py
│   ├── terraform_cases.py
│   ├── k8s_cases.py
│   ├── docker_cases.py
│   ├── ci_cases.py
│   ├── cfn_cases.py
│   ├── robustness_cases.py
│   └── l3_cases.py
├── l1_basic/                           # Atomic 3-15 line test fixtures
│   ├── cfn/
│   ├── ci/
│   ├── docker/
│   ├── k8s/
│   ├── robustness/
│   ├── sast/
│   ├── secrets/
│   └── terraform/
├── l2_intermediate/                    # 20-60 line contextual fixtures
│   ├── cfn/
│   ├── ci/
│   ├── docker/
│   ├── k8s/
│   ├── robustness/
│   ├── sast/
│   ├── secrets/
│   └── terraform/
├── l3_advanced/                        # 80-200 line production single files (16 distinct apps)
│   ├── app_config/                     # Production YAML config
│   ├── compose_stack/                  # Multi-service docker-compose.yml
│   ├── deploy_script/                  # Bash deployment script
│   ├── django_portal/                  # Django settings.py
│   ├── docker_build/                   # Multi-stage Dockerfile
│   ├── docs_readme/                    # Markdown engineering documentation
│   ├── env_config/                     # .env production configuration
│   ├── express_api/                    # Express.js REST API
│   ├── flask_service/                  # Flask authentication microservice
│   ├── github_ci/                      # GitHub Actions release workflow
│   ├── go_microservice/                # Go HTTP backend
│   ├── k8s_workload/                   # Kubernetes Deployment & Service
│   ├── node_pkg/                       # package.json
│   ├── php_portal/                     # PHP customer backend
│   ├── spring_backend/                 # Spring Boot Java configuration
│   └── terraform_infra/                # Complete AWS VPC/RDS/S3 Terraform stack
├── scripts/
│   ├── run_scan.sh                     # Scanner test runner accepting $SCANNER_CMD
│   ├── score.py                        # Automated ±1 line tolerance benchmark scorer
│   └── validate_fixtures.sh            # Multi-language syntax validator
└── reports/
    ├── gap-report.md                   # Evaluation results & gap analysis
    ├── results.csv                     # Per-scenario benchmark results
    └── raw/                            # Raw SARIF/JSON scanner outputs
```

---

## 6. How to Run & Score

### Step 1: Validate Fixture Syntax
Validate that all generated fixtures are syntactically valid code:
```bash
./scripts/validate_fixtures.sh
```

### Step 2: Regenerate Fixtures & Manifest (Optional)
If modifying scenarios, regenerate fixtures and manifest programmatically:
```bash
python3 generate.py
```

### Step 3: Run Security Scanner
Run any scanner producing SARIF or JSON output:
```bash
# Option A: Run custom scanner command via environment variable
SCANNER_CMD="tigergate scan fp-regex-tests/ --output-format sarif" ./scripts/run_scan.sh

# Option B: Run baseline tools
./scripts/run_scan.sh checkov
./scripts/run_scan.sh trivy
```

### Step 4: Evaluate Precision & Recall
The scoring script automatically parses the scanner output with $\pm 1$ line tolerance:
```bash
python3 scripts/score.py --report reports/raw/scanner_output.json
```

Outputs generated:
- `reports/gap-report.md`: Executive summary, precision/recall per level, family, and format, top 20 FP-prone rules, and robustness consistency analysis.
- `reports/results.csv`: Per-target scenario evaluation status (`TRUE_POSITIVE`, `FALSE_NEGATIVE`, `TRUE_NEGATIVE`, `FP_CANDIDATE (UNREVIEWED)`).

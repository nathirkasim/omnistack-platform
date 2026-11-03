# codesec-benchmark

A standardized, multi-language security evaluation suite designed to benchmark Code Security Scanners across **Static Application Security Testing (SAST)**, **Secrets Detection**, **Software Composition Analysis (SCA)**, and **Infrastructure-as-Code (IaC)**.

The benchmark evaluates:
- **True-Positive Recall**: Does the scanner identify genuine, exploitable vulnerabilities and leaked credentials?
- **False-Positive Noise**: Does the scanner fall for defensive idioms, validation traps, mock fixtures, and safe scopes?
- **Blind Spots & Evasion**: Can the scanner handle deep multi-hop taint flows, framework bypasses, syntactic obfuscation, git history commits, and resolved/rendered IaC?

> [!IMPORTANT]
> **SYNTHETIC FIXTURES DISCLAIMER**: All credentials, secret tokens, private keys, cloud IDs, hostnames, and passwords committed in this repository are **strictly synthetic test fixtures**. No real credentials, proprietary hosts, or production data are contained within this benchmark.

---

## Repository Layout

```
codesec-benchmark/
├── basic/                                # Phase 1: Direct sinks, standard vulnerabilities, and classic traps
│   ├── sast/                             # Multi-language web applications (Flask, Spring, Gin, Express)
│   │   ├── python/                       # Flask application (app.py)
│   │   ├── java/                         # Spring Boot controller & stubs (UserController.java)
│   │   ├── go/                           # net/http service (main.go)
│   │   └── node/                         # Express / Node HTTP server (server.js)
│   ├── secrets/                          # Cloud keys, PEMs, URIs, base64 tokens, and FP traps
│   ├── sca/                              # Direct dependency manifests with verified CVEs
│   │   ├── python/                       # requirements.txt, requirements-dev.txt
│   │   ├── java/                         # pom.xml
│   │   ├── go/                           # go.mod
│   │   └── node/                         # package.json
│   └── iac/                              # Infrastructure-as-code manifests
│       ├── docker/                       # Dockerfile (root, ADD, latest, secrets)
│       ├── terraform/                    # main.tf (open S3, SSH, RDS, IAM)
│       ├── k8s/                          # deployment.yaml (privileged, hostNetwork, hostPath)
│       └── compose/                      # docker-compose.yml (privileged, docker.sock)
│
├── advanced/                             # Phase 2: Advanced detection challenges
│   ├── taint/                            # Multi-file deep taint (3-5 hops, closures, async, DI, channels)
│   │   ├── python/                       # Controller -> Service -> Repository -> Sanitizer
│   │   ├── java/                         # Spring controller, services, repository, reflection
│   │   ├── go/                           # Goroutines, channels, struct fields, closures
│   │   └── node/                         # Event emitters, callbacks, class fields, async
│   ├── evasion/                          # Symmetrical twin pairs (plain vs evasion)
│   │   ├── python/                       # Dynamic getattr, string joins, function aliasing
│   │   ├── java/                         # ProcessBuilder reflection, String.join, class loading
│   │   ├── go/                           # Slice unpack, strings.Builder, custom HTTP clients
│   │   ├── node/                         # Computed property access, global scope eval
│   │   └── secrets/                      # Base64, hex, unicode, YAML/XML embedded secrets
│   ├── sca/                              # Reachability, transitive depths (1-5), diamond deps, confusion
│   │   ├── python/                       # Reachability demo, lockfile mismatch, typosquatting
│   │   ├── java/                         # Shaded jars, transitive depth 4, method call reachability
│   │   ├── go/                           # go.mod replace directives, transitive fasthttp
│   │   └── node/                         # Overrides, prototype pollution call reachability
│   ├── secrets-history/                  # Git commit history, CI workflows (GHA, GitLab, Jenkins)
│   ├── iac/                              # Rendered IaC (Terraform locals/dynamic blocks, Kustomize, Helm)
│   │   ├── terraform/                    # Dynamic ingress, count blocks, cross-resource correlation
│   │   ├── kustomize/                    # Base vs Overlay patches (unsafe base fixed by safe overlay)
│   │   ├── helm/                         # Go template conditional rendering
│   │   └── rendered/                     # Resolved output manifests for ground truth comparison
│   ├── mutants/                          # Programmatically mutated test case variants
│   └── harness/                          # Mutation and scale generation tooling
│       ├── mutate.py                     # Generates mutants across 5 mutation strategies
│       └── gen_scale.py                  # Generates synthetic monorepos (1k, 10k, 100k files)
│
├── ground_truth.json                     # Primary JSON manifest containing all 543 test cases
├── ground_truth.csv                      # Synchronized CSV manifest
├── validate_gt.py                        # Strict integrity validator for manifest and inline comments
├── score.py                              # Evaluation engine (SARIF, JSON, CSV -> Precision/Recall/F1)
├── check_new_coverage.py                 # Advanced coverage analyzer and blind-spot reporter
├── check_builds.sh                       # Multi-language compilation verifier
└── README.md                             # Benchmark documentation and usage guide
```

---

## Ground Truth Schema

Every test case in the benchmark is assigned a unique identifier following the `<CAT>-<LANG>-<NNN>` pattern (e.g. `SAST-PY-001`, `SEC-GEN-002`, `SCA-JAVA-101`, `IAC-TF-004`).

### Manifest Fields
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | string | Unique case identifier (`<CAT>-<LANG>-<NNN>`) |
| `category` | string | One of: `SAST`, `secrets`, `SCA`, `IaC` |
| `language` | string | `python`, `java`, `go`, `node`, `terraform`, `dockerfile`, `kubernetes`, `yaml` |
| `file` | string | Relative path from repo root |
| `line_start` | integer | Target finding start line number |
| `line_end` | integer | Target finding end line number |
| `type` | string | `TP` (True Positive) or `FP` (False Positive trap) |
| `cwe_or_cve` | string | CWE ID (`CWE-89`), CVE ID (`CVE-2021-44228`), or `N/A` |
| `rule_hint` | string | Suggested scanner rule classification (e.g. `sql-injection`) |
| `difficulty` | string | `easy`, `medium`, `hard`, or `disputed` |
| `technique` | string | Detection challenge (e.g. `deep-taint`, `reflection`, `parameterized-query`) |
| `pair_id` | string | Symmetrical twin case ID (for obfuscation/evasion testing) |
| `parent_id` | string | Parent case ID (for mutation testing) |
| `mutation` | string | Mutation strategy applied (`rename_vars`, `extract_helper`, etc.) |
| `reason` | string | Detailed explanation of exploitability (TP) or safety mechanism (FP) |
| `notes` | string | Additional contextual notes |

### Inline Comment Syntax
Every finding in code has an inline comment placed directly above the target line:
- In Python / Shell / Dockerfile / YAML / Terraform:
  `# GT: id=SAST-PY-001 type=TP cwe=CWE-89 rule=sql-injection`
- In Java / Go / JavaScript:
  `// GT: id=SAST-JAVA-001 type=TP cwe=CWE-89 rule=sql-injection`
- In XML / HTML:
  `<!-- GT: id=SCA-JAVA-001 type=TP cwe=CVE-2021-44228 rule=cve-log4j-rce -->`
- For False Positive Traps:
  `// GT: id=SAST-NODE-015 type=FP reason=parameterized-query`

---

## Case Count Summary

### Breakdown by Category and Type
| Category | True Positives (TP) | False Positives (FP) | Total Cases |
| :--- | :---: | :---: | :---: |
| **SAST** | 172 | 117 | **289** |
| **Secrets** | 46 | 28 | **74** |
| **SCA** | 64 | 64 | **128** |
| **IaC** | 29 | 23 | **52** |
| **Total** | **311** | **232** | **543** |

### Breakdown by Phase and Language
| Phase | Python | Java | Go | Node/JS | Infra / Config | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 1 (Basic)** | 48 | 48 | 48 | 48 | 52 | **244** |
| **Phase 2 (Advanced)** | 91 | 56 | 55 | 60 | 37 | **299** |
| **Total** | **139** | **104** | **103** | **108** | **89** | **543** |

---

## How to Run Benchmark Tools

### 1. Validate Ground Truth Integrity
Validates that every manifest entry exists on disk, line numbers align with inline comments, pair IDs cross-reference symmetrically, and no duplicate or orphaned comments exist:
```bash
python3 validate_gt.py
```
To re-synchronize CSV from JSON:
```bash
python3 validate_gt.py --sync-csv
```

### 2. Verify Code Compiles and Parses
Verifies syntax parsing and builds across Python (`py_compile`), Java (`javac`), Go (`go build`), and Node (`node --check`):
```bash
./check_builds.sh
```

### 3. Score Scanner Output
Evaluate scanner findings (SARIF, JSON, or CSV format) against `ground_truth.json`:
```bash
python3 score.py --findings scanner_output.sarif --gt ground_truth.json
```
Configurable options:
```bash
# Set line tolerance (+/- 5 lines) and enforce quality gate thresholds
python3 score.py --findings scanner_output.json --tolerance 5 --min-recall 0.85 --max-fp-rate 0.10

# Compare two scanner runs for regressions
python3 score.py --compare run_v1.json run_v2.json
```

### 4. Check Advanced Coverage & Blind Spots
Evaluates scanner detection on advanced cases (`advanced/`), computes twin evasion delta, and writes `new_cases_report.md`:
```bash
python3 check_new_coverage.py --findings scanner_output.json --allow-misses 5
```

### 5. Generate Mutants and Scale Repositories
Generate equivalent mutants:
```bash
python3 advanced/harness/mutate.py
```

Generate synthetic monorepos at scale (e.g., 10,000 files with embedded findings):
```bash
python3 advanced/harness/gen_scale.py --count 10000 --out /tmp/monorepo_10k --embed-ratio 0.02
```


# TigerGate Adversarial Code Security, False-Positive & SBOM Detection Suite

A realistic, multi-language adversarial test suite for validating **TigerGate Code Security** against genuine vulnerabilities (True Positives), safe implementations (False Positives), scanner misses (False Negatives), reachability nuance, and Software Bill of Materials (SBOM) fidelity.

---

## 1. Repository Structure

```text
code-security-testing/
├── .github/
│   └── workflows/
│       └── TIGERGATE.YML           # CI pipeline configuration for TigerGate scans
├── tests/
│   ├── sast/                       # SAST paired true-positive & false-positive cases
│   │   ├── python/                 # Python SQLi, XSS, CmdInj, Path Traversal, SSRF, Crypto
│   │   ├── javascript-typescript/  # TS/JS pg, react XSS, child_process, path traversal
│   │   ├── java/                   # Java JDBC, JPA, Runtime.exec, ObjectInputStream
│   │   ├── go/                     # Go database/sql, exec.Command, path traversal
│   │   ├── ruby/                   # Ruby ActiveRecord SQLi, system CmdInj, Marshal
│   │   ├── php/                    # PHP PDO SQLi, echo XSS, shell_exec, unserialize
│   │   ├── dotnet/                 # C# SqlCommand, Process.Start, Path.Combine
│   │   └── rust/                   # Rust Command::new, path canonicalize, unsafe ptr
│   ├── sca/                        # Package manager manifests with verified CVEs
│   │   ├── python/                 # requirements.txt, pyproject.toml, poetry.lock
│   │   ├── npm/                    # package.json, package-lock.json, yarn.lock, pnpm
│   │   ├── java/                   # pom.xml (Log4Shell), build.gradle, build.gradle.kts
│   │   ├── go/                     # go.mod, go.sum
│   │   ├── rust/                   # Cargo.toml, Cargo.lock
│   │   ├── ruby/                   # Gemfile, Gemfile.lock
│   │   ├── php/                    # composer.json, composer.lock
│   │   ├── dotnet/                 # .csproj, packages.lock.json, Directory.Packages.props
│   │   └── cpp/                    # conanfile.txt, vcpkg.json
│   ├── sbom/                       # Dependency acquisition and inventory edge cases
│   │   ├── direct/                 # Direct pinned dependencies
│   │   ├── transitive/             # Deeply nested transitive dependencies
│   │   ├── workspaces/             # Monorepo with conflicting version resolutions
│   │   ├── git-dependencies/       # VCS commit-pinned dependencies
│   │   ├── vendored/               # In-tree committed third-party packages
│   │   └── containers/             # Multi-stage Dockerfile OS package layers
│   ├── secrets/                    # False-positive placeholders & synthetic secrets
│   ├── iac/                        # Terraform, Kubernetes, Dockerfile, GitHub Actions
│   └── reachability/               # Real CVE reachable vs unreachable call graph cases
├── test-metadata/
│   ├── expected-findings.json      # Machine-readable ground truth manifest
│   └── dependency-source-matrix.json # Ecosystem & package manager coverage matrix
├── scripts/
│   ├── run-scanner.sh              # Local scanner execution harness
│   └── evaluate-results.py         # Automated comparison & evaluation report generator
├── reports/
│   ├── README.md                   # Reporting guide
│   └── evaluation-report.md        # Comprehensive evaluation matrix & metrics
└── docs/
    ├── adversarial-test-plan.md    # Methodology, objectives & taxonomy
    ├── sbom-coverage-matrix.md     # Package manager & PURL attribution specifications
    └── known-limitations.md        # Architectural scanner gaps & recommendations
```

---

## 2. Test Taxonomy

- **`TP-SAST-xxx`**: Intentionally vulnerable code (genuine true positive).
- **`FP-SAST-xxx`**: Safe, defended implementation syntactically resembling a vulnerability.
- **`FN-SAST-xxx`**: Genuine vulnerability designed with complex data flow to identify scanner misses.
- **`TP-SCA-xxx`**: Verified CVE in pinned dependency manifest or lockfile.
- **`SBOM-xxx`**: Component inventory, PURL generation, and graph edge validation.
- **`FP-SECRET-xxx`**: Safe placeholder, documentation example, or high-entropy non-secret.
- **`TP-SECRET-xxx`**: Controlled synthetic test secret matching regex detection patterns.
- **`TP-IAC-xxx` / `FP-IAC-xxx`**: Paired insecure and compliant infrastructure configurations.
- **`TP-REACH-xxx` / `TN-REACH-xxx`**: Reachable vs unreachable / sanitized vulnerable dependency call paths.

---

## 3. Running the Test Suite

### Local Offline Ground Truth Evaluation
```bash
python3 scripts/evaluate-results.py
```

### Running TigerGate Scans (with API credentials)
```bash
export TIGERGATE_API_KEY="<your-api-key>"
export TIGERGATE_API_URL="https://api.tigergate.dev/api/ci"

./scripts/run-scanner.sh
```

---

## 4. Documentation Links

- [Adversarial Test Plan](docs/adversarial-test-plan.md)
- [SBOM Coverage Matrix](docs/sbom-coverage-matrix.md)
- [Known Limitations & Recommendations](docs/known-limitations.md)
- [Evaluation Report](reports/evaluation-report.md)

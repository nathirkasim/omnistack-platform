# TigerGate True Positive Vulnerability Detection Gap Report

- **Date:** YYYY-MM-DD
- **Target Repository:** `tigergate-true-positive-benchmark` (nathir-fptest)
- **Scanner Tested:** TigerGate Code Security
- **Ground Truth Baseline:** `metadata/expected-findings.json`

---

## 1. Executive Detection Scorecard

| Category | Total Expected (True Positives) | Detected by TigerGate | Missed (False Negatives) | Detection Coverage (%) |
| :--- | :--- | :--- | :--- | :--- |
| **SAST (Static Analysis)** | 35 | | | % |
| **SCA (Vulnerable Dependencies)**| 35 | | | % |
| **IaC (Infrastructure Security)**| 20 | | | % |
| **Secrets Detection** | 15 | | | % |
| **TOTAL BENCHMARK** | **105** | | | **%** |

---

## 2. SAST Detection Breakdown by Language

| Language | Expected Flaws | Detected | Missed | Coverage (%) |
| :--- | :--- | :--- | :--- | :--- |
| Python | 6 | | | % |
| JavaScript / TypeScript | 8 | | | % |
| Java | 6 | | | % |
| Go | 5 | | | % |
| PHP | 3 | | | % |
| Ruby | 3 | | | % |
| .NET (C#) | 2 | | | % |
| C / C++ | 2 | | | % |

---

## 3. SCA Detection Breakdown by Ecosystem

| Ecosystem | Manifest / Lockfile | Expected CVEs | Detected | Missed |
| :--- | :--- | :--- | :--- | :--- |
| Python (pip/poetry) | requirements.txt, poetry.lock | 7 | | |
| JavaScript (npm/yarn) | package-lock.json, yarn.lock | 7 | | |
| Java (Maven/Gradle) | pom.xml, build.gradle | 5 | | |
| Go | go.mod, go.sum | 3 | | |
| Rust | Cargo.lock | 3 | | |
| Ruby | Gemfile.lock | 3 | | |
| PHP | composer.lock | 2 | | |
| .NET | App.csproj, packages.config | 2 | | |
| C/C++ | conan.lock, vcpkg.json | 3 | | |

---

## 4. IaC Detection Breakdown by Technology

| Target | Expected Misconfigurations | Detected | Missed |
| :--- | :--- | :--- | :--- |
| Terraform (AWS) | 6 | | |
| Kubernetes | 6 | | |
| Dockerfile | 4 | | |
| CloudFormation | 2 | | |
| GitHub Actions | 2 | | |

---

## 5. Secrets Detection Breakdown by Secret Type

| Secret Type | Expected Instances | Detected | Missed |
| :--- | :--- | :--- | :--- |
| AWS Access Keys | 2 | | |
| GitHub / GitLab Tokens | 2 | | |
| Private Key Material (RSA/EC/PGP)| 3 | | |
| Database Connection URIs | 2 | | |
| API Keys (Stripe, SendGrid) | 2 | | |
| JWT Signing Secrets | 2 | | |
| Configuration & .env Secrets | 2 | | |

---

## 6. Critical Gap Analysis & Scanner Limitations
[Detailed technical notes on data-flow tracking failures, missed parsers, and unflagged vulnerabilities.]

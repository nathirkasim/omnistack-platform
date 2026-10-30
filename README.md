# TigerGate True Positive Vulnerability Detection Benchmark

A comprehensive, realistic, and independently verified **True Positive** security benchmark designed specifically to test the detection coverage and depth of **TigerGate Code Security**.

## 1. Benchmark Scope & Purpose

Unlike false-positive test suites, this repository contains **only genuine, independently exploitable security vulnerabilities** across four core testing pillars:

1. **SAST (Static Application Security Testing):**
   - 21 vulnerability classes across 9 languages: Python, JavaScript, TypeScript, Java, Go, PHP, Ruby, .NET (C#), and C/C++.
   - Real, authentic vulnerable code patterns with data flow, framework integrations, and precise line markers.
2. **SCA (Software Composition Analysis):**
   - 9 package ecosystems: Python (pip, poetry, pipenv), npm (npm, yarn, pnpm), Java (Maven, Gradle), Go, Rust (Cargo), Ruby (Bundler), PHP (Composer), .NET (NuGet), and C/C++ (Conan, vcpkg).
   - Exact pinned versions matched against confirmed NVD, OSV, and GitHub Security Advisories.
   - Direct, transitive, dev, workspace, and git dependencies.
3. **IaC (Infrastructure as Code Security):**
   - Terraform, Kubernetes manifests, Dockerfiles, AWS CloudFormation, and GitHub Actions CI/CD workflows.
   - Critical misconfigurations: unrestricted network ingress, public storage, container privilege escalation, root containers, script injection.
4. **Secrets Detection:**
   - Realistic synthetic credentials: AWS keys, GitHub/GitLab PATs, SSH/TLS private keys, database connection strings, JWT signing keys, OAuth secrets, API tokens across code, config, `.env`, and certificates.

---

## 2. Repository Layout

```
nathir-fptest/
├── sast/                               # SAST True Positive Fixtures
│   ├── python/                         # SQLi, Cmdi, SSRF, Path Traversal, SSTI, Deserialization, Insecure TLS
│   ├── javascript/                     # XSS, NoSQLi, Cmdi, Path Traversal, Open Redirect, IDOR, Unsafe Upload
│   ├── typescript/                     # Type-safe SQLi bypass, JWT algorithm confusion
│   ├── java/                           # SQLi, XXE, Deserialization, Cmdi, LDAP Injection, XPath Injection
│   ├── go/                             # SQLi, Cmdi, SSRF, Path Traversal, Insecure TLS
│   ├── php/                            # SQLi, Cmdi, Local File Inclusion (LFI), Insecure Deserialization
│   ├── ruby/                           # SQLi, Cmdi, Insecure YAML Deserialization
│   ├── dotnet/                         # SQLi, Path Traversal, BinaryFormatter Deserialization
│   └── cpp/                            # Buffer Overflow, Format String, Command Injection
│
├── sca/                                # SCA True Positive Fixtures
│   ├── python/                         # requests, urllib3, flask, jinja2, pyyaml, fastapi, starlette
│   ├── npm/                            # lodash, express, axios, minimist, json5, moment, semver
│   ├── java/                           # Log4j (Log4Shell), Jackson, Spring4Shell, Commons-Collections
│   ├── go/                             # crypto, gin, net
│   ├── rust/                           # tokio, time, smallvec
│   ├── ruby/                           # rails, rack, nokogiri
│   ├── php/                            # guzzle, monolog
│   ├── dotnet/                         # Newtonsoft.Json, System.Text.Encodings.Web
│   └── cpp/                            # openssl, zlib, libxml2
│
├── iac/                                # IaC True Positive Fixtures
│   ├── terraform/                      # Public S3, 0.0.0.0/0 SG ingress, wildcard IAM, unencrypted RDS
│   ├── kubernetes/                     # Privileged container, hostPID/hostNetwork, hostPath mount, root user
│   ├── docker/                         # Root user, unpinned tags, hardcoded ENV secret, exposed SSH
│   ├── cloudformation/                 # Public S3 bucket policy, unencrypted DB, wildcard role
│   └── github-actions/                 # Context expression script injection, unpinned 3rd-party actions
│
├── secrets/                            # Secrets True Positive Fixtures
│   ├── source-code/                    # AWS keys, GitHub PAT, Stripe secret, DB credentials in code
│   ├── configuration/                  # .env, config.json, application.properties
│   ├── infrastructure/                 # terraform.tfvars, k8s Secret manifest
│   ├── certificates/                   # RSA private key, EC private key, PGP private key
│   └── git-history/                    # Historical synthetic commit secrets
│
├── metadata/
│   ├── expected-findings.json          # Machine-readable ground truth (100+ true positive findings)
│   └── schema.json                     # JSON Schema validating expected finding records
│
├── docs/                               # Detailed methodology and testing guides
├── references/                         # Vulnerability research notes & CVE advisories
├── reports/                            # Evaluation reports & gap analysis templates
└── scripts/                            # Verification and comparison engines
```

---

## 3. Evaluation Methodology

1. Run TigerGate Code Security across this repository.
2. Compare scan findings against `metadata/expected-findings.json` using:
   ```bash
   python3 scripts/evaluate-tigergate-benchmark.py \
     --expected metadata/expected-findings.json \
     --actual /path/to/tigergate-report.json \
     --output reports/tigergate-detection-gap-report.md
   ```
3. Generate metric scorecards:
   - **True Positive Detection Rate (%):** Overall and broken down by category (SAST, SCA, IaC, Secrets).
   - **False Negative Rate (%):** Critical security flaws completely missed by the engine.
   - **Metadata Accuracy (%):** Accuracy of rule identification, CWE, CVSS score, and affected line numbers.

# Adversarial Code Security, False-Positive & SBOM Detection Test Plan

## 1. Overview & Objective

This test suite is designed to objectively evaluate **TigerGate Code Security** against genuine vulnerabilities, false positives, false negatives, reachability nuance, and software bill of materials (SBOM) fidelity.

**Key Rule:** The test suite does not modify TigerGate's scanning rules or detection engine. Instead, it tests the product's behavior against independently justified security ground truth.

---

## 2. Taxonomy & Test Identification Scheme

Every test fixture is assigned a distinct identifier reflecting its category and validation role:

| Prefix | Definition | Description |
| :--- | :--- | :--- |
| `TP-SAST-xxx` | True Positive SAST | Genuine, exploitable vulnerability in application code. |
| `FP-SAST-xxx` | False Positive SAST | Safe, defended code that syntactically resembles an exploit pattern. |
| `FN-SAST-xxx` | False Negative SAST | Documented vulnerability that evades simple syntactic pattern matchers. |
| `TP-SCA-xxx` | True Positive SCA | Known vulnerable dependency declared in manifest or lockfile with verified CVE. |
| `SBOM-xxx` | SBOM Accuracy Test | Component attribution, dependency edge verification, and inventory completeness. |
| `FP-SECRET-xxx`| Safe Secrets Defense | Harmless placeholders, documentation examples, masked tokens, or UUIDs. |
| `TP-SECRET-xxx`| Controlled Synthetic Secret | High-entropy synthetic tokens matching active pattern recognition rules. |
| `TP-IAC-xxx` | True Positive IaC | Misconfigured cloud infrastructure, permissive IAM, or insecure container specs. |
| `FP-IAC-xxx` | Compliant / Hardened IaC | Paired secure configuration adhering to least-privilege standards. |
| `TP-REACH-xxx` | Reachable Vulnerability | Vulnerable package where the affected method is called with user input. |
| `TN-REACH-xxx` | Unreachable / Neutralized | Vulnerable package present, but unaffected API called, dead code, or sanitized. |

---

## 3. Scope of Testing

### 3.1 Static Application Security Testing (SAST)
- **Languages Covered:** Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C# (.NET), Rust.
- **Vulnerability Classes:**
  - SQL Injection (raw concatenation, prepared statements, ORM text/raw APIs, constant queries, multi-step dict flows).
  - Cross-Site Scripting (XSS) (unescaped templates, JSX interpolation, DOMPurify sanitization, explicit Markup overrides).
  - Command Injection (`os.system`, `child_process.exec`, `Runtime.exec`, `sh -c`, safe argv arrays, ineffective sanitizers).
  - Path Traversal (`os.path.join`, canonical path guards, `pathlib.Path.is_relative_to`, test relative fixtures).
  - SSRF, Insecure Deserialization & Open Redirects (`pickle`, `unserialize`, `ObjectInputStream`, URL allowlists).
  - Cryptography & Authentication (MD5 for passwords vs MD5 for ETag caching, CSPRNG vs PRNG, password hashing).

### 3.2 Software Composition Analysis (SCA) & SBOM
- **Ecosystems Covered:**
  - Python (pip `requirements.txt`, Poetry `pyproject.toml` + `poetry.lock`)
  - JavaScript/Node.js (`package.json`, `package-lock.json` v2, `yarn.lock`, `pnpm-lock.yaml`)
  - Java (Maven `pom.xml`, Gradle `build.gradle`, Kotlin `build.gradle.kts`)
  - Go (`go.mod`, `go.sum`)
  - Rust (`Cargo.toml`, `Cargo.lock`)
  - Ruby (`Gemfile`, `Gemfile.lock`)
  - PHP (`composer.json`, `composer.lock`)
  - .NET (`.csproj`, `packages.lock.json`, `Directory.Packages.props`)
  - C/C++ (`conanfile.txt`, `vcpkg.json`)
  - Container OS Packages (Multi-stage `Dockerfile`, Debian/Ubuntu apt)
- **Dependency Sources Tested:**
  - Public package registries (npm, PyPI, Maven Central, crates.io, Packagist, NuGet).
  - Monorepo workspaces (`packages/*` with conflicting dependency versions).
  - Git commit-pinned and release-tag dependencies.
  - Vendored third-party code in-tree.
  - Multi-stage container build-time vs runtime isolation.

### 3.3 Secrets Detection False-Positive Matrix
- Harmless templates (`YOUR_API_KEY_HERE`, `CHANGEME`).
- Documentation code blocks and markdown guides.
- Masked credentials (`ghp_xxxxxxxx...`).
- Dummy test certificates with explicit test disclaimers.
- Environment variable dereferencing (`os.environ.get(...)`).
- High-entropy non-secret identifiers (UUIDs, git commit hashes, SHA256 cache keys).

### 3.4 Infrastructure as Code (IaC)
- Terraform AWS S3 public bucket vs private bucket with public access block and KMS.
- Overly permissive wildcard IAM policies vs scoped least-privilege policies.
- Kubernetes privileged root pods vs hardened non-root security contexts.
- Kubernetes NodePort vs ClusterIP services.
- Dockerfile latest tag and root execution vs pinned digest multi-stage non-root containers.
- GitHub Actions unpinned branch references vs pinned commit SHAs.

### 3.5 Context Awareness & Reachability Analysis
- Real CVE scenarios (e.g. `lodash 4.17.15` CVE-2020-8203):
  - Direct call path from controller.
  - Safe function invoked (`_.compact`), vulnerable function untouched.
  - Vulnerable function in dead/unreachable branch (`if (false)`).
  - Vulnerable function called with strict prototype pollution validation guard.
  - DevDependency isolation (tools present only in test runner).

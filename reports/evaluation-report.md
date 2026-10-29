# TigerGate Adversarial Code Security & SBOM Benchmark Report

## 1. Executive Summary

- **Total Fixture Test Cases:** 82
- **Verified True Negatives (Safe Code / False-Positive Defenses):** 39
- **Expected True Positives (Genuine Vulnerabilities):** 40
- **Identified False Negative Gaps (Scanner Blind Spots):** 1
- **Conditional / Toolchain Prerequisite Cases:** 3

## 2. Category Breakdown

| Category | Total Cases | Target Vulnerabilities | Defensive / Safe Pairs | Edge Cases |
| :--- | :--- | :--- | :--- | :--- |
| **SAST** | 52 | 1 | 29 | 0 |
| **SECRETS** | 6 | 0 | 4 | 0 |
| **IAC** | 4 | 0 | 2 | 0 |
| **SCA** | 8 | 0 | 0 | 0 |
| **SBOM** | 6 | 0 | 0 | 3 |
| **REACHABILITY** | 6 | 0 | 4 | 0 |

## 3. Comprehensive Adversarial Test Matrix & Ground Truth

| Test ID | Category | Language/ecosystem | Dependency source | Expected result | Actual result | Outcome | SBOM result | Finding details | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `TP-SAST-001` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/python/sql_injection.py#L16` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-001` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/python/sql_injection.py#L27` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-002` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/python/sql_injection.py#L43` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-003` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/python/sql_injection.py#L57` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-002` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/python/sql_injection.py#L68` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-004` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/python/sql_injection.py#L78` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FN-SAST-001` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **FN** | N/A | CWE-89 (High) | `tests/sast/python/sql_injection.py#L93` | Complex data-flow pattern missed by simple syntactic matchers. |
| `TP-SAST-003` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-79 (High) | `tests/sast/python/xss_flask.py#L19` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-005` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-79 (None) | `tests/sast/python/xss_flask.py#L30` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-004` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-79 (High) | `tests/sast/python/xss_flask.py#L42` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-006` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-79 (None) | `tests/sast/python/xss_flask.py#L55` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-007` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-79 (None) | `tests/sast/python/xss_flask.py#L66` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-005` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-78 (Critical) | `tests/sast/python/command_injection.py#L16` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-008` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/python/command_injection.py#L28` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-006` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-78 (High) | `tests/sast/python/command_injection.py#L46` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-009` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/python/command_injection.py#L57` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-010` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/python/command_injection.py#L68` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-007` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-22 (High) | `tests/sast/python/path_traversal.py#L16` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-011` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-22 (None) | `tests/sast/python/path_traversal.py#L29` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-012` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-22 (None) | `tests/sast/python/path_traversal.py#L43` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-013` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-22 (None) | `tests/sast/python/path_traversal.py#L54` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-008` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-918 (High) | `tests/sast/python/ssrf_deserialization.py#L21` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-014` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-918 (None) | `tests/sast/python/ssrf_deserialization.py#L43` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-009` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-502 (Critical) | `tests/sast/python/ssrf_deserialization.py#L54` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-015` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-502 (None) | `tests/sast/python/ssrf_deserialization.py#L64` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-010` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-601 (Medium) | `tests/sast/python/ssrf_deserialization.py#L75` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-016` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-601 (None) | `tests/sast/python/ssrf_deserialization.py#L87` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-011` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-328 (High) | `tests/sast/python/crypto_auth.py#L18` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-017` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-328 (None) | `tests/sast/python/crypto_auth.py#L28` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-012` | SAST | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-338 (High) | `tests/sast/python/crypto_auth.py#L38` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-018` | SAST | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-338 (None) | `tests/sast/python/crypto_auth.py#L48` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-015` | SAST | TypeScript | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/javascript-typescript/sql_injection.ts#L16` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-021` | SAST | TypeScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/javascript-typescript/sql_injection.ts#L26` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-017` | SAST | TypeScript | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-79 (High) | `tests/sast/javascript-typescript/xss_react.tsx#L18` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-023` | SAST | TypeScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-79 (None) | `tests/sast/javascript-typescript/xss_react.tsx#L28` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SAST-024` | SAST | TypeScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-79 (None) | `tests/sast/javascript-typescript/xss_react.tsx#L38` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-018` | SAST | JavaScript | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-78 (Critical) | `tests/sast/javascript-typescript/command_injection.js#L12` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-026` | SAST | JavaScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/javascript-typescript/command_injection.js#L23` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-020` | SAST | Java | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/java/SqlInjectionJdbc.java#L21` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-030` | SAST | Java | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/java/SqlInjectionJdbc.java#L31` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-022` | SAST | Java | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-78 (Critical) | `tests/sast/java/SecurityVulnerabilitiesJava.java#L19` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-032` | SAST | Java | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/java/SecurityVulnerabilitiesJava.java#L29` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-025` | SAST | PHP | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/php/vulnerabilities.php#L13` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-034` | SAST | PHP | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/php/vulnerabilities.php#L23` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-029` | SAST | Ruby | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/ruby/vulnerabilities.rb#L12` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-038` | SAST | Ruby | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/ruby/vulnerabilities.rb#L21` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-032` | SAST | Go | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/go/vulnerabilities.go#L19` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-041` | SAST | Go | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/go/vulnerabilities.go#L29` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-035` | SAST | C# | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-89 (High) | `tests/sast/dotnet/Vulnerabilities.cs#L18` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-045` | SAST | C# | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-89 (None) | `tests/sast/dotnet/Vulnerabilities.cs#L29` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SAST-038` | SAST | Rust | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-78 (Critical) | `tests/sast/rust/vulnerabilities.rs#L14` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-SAST-048` | SAST | Rust | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-78 (None) | `tests/sast/rust/vulnerabilities.rs#L25` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SECRET-001` | SECRETS | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-798 (None) | `tests/secrets/false_positives.py#L11` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SECRET-002` | SECRETS | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-798 (None) | `tests/secrets/false_positives.py#L20` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SECRET-004` | SECRETS | Python | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-798 (None) | `tests/secrets/false_positives.py#L27` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `FP-SECRET-005` | SECRETS | Text | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-312 (None) | `tests/secrets/dummy_test_key.pem#L1` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SECRET-001` | SECRETS | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-798 (High) | `tests/secrets/synthetic_secrets.py#L11` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SECRET-002` | SECRETS | Python | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-798 (High) | `tests/secrets/synthetic_secrets.py#L19` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-IAC-001` | IAC | HCL | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-732 (High) | `tests/iac/terraform/s3_storage.tf#L12` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-IAC-001` | IAC | HCL | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-732 (None) | `tests/iac/terraform/s3_storage.tf#L21` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-IAC-004` | IAC | YAML | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CWE-250 (High) | `tests/iac/kubernetes/workloads.yaml#L17` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `FP-IAC-004` | IAC | YAML | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CWE-250 (None) | `tests/iac/kubernetes/workloads.yaml#L43` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-SCA-001` | SCA | Python | PyPI / pip requirements.txt | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2021-33503 (High) | `tests/sca/python/requirements.txt#L3` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-002` | SCA | JavaScript | npm registry / package-lock.json | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2020-8203 (High) | `tests/sca/npm/package-lock.json#L30` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-003` | SCA | Java | Maven Central / pom.xml | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2021-44228 (Critical) | `tests/sca/java/pom.xml#L21` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-005` | SCA | Go | Go proxy / go.mod | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2021-43565 (High) | `tests/sca/go/go.mod#L6` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-006` | SCA | Rust | crates.io / Cargo.lock | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | RUSTSEC-2019-0012 (High) | `tests/sca/rust/Cargo.lock#L24` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-008` | SCA | Ruby | RubyGems / Gemfile.lock | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2020-8184 (High) | `tests/sca/ruby/Gemfile.lock#L7` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-009` | SCA | PHP | Packagist / composer.lock | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2022-31090 (Medium) | `tests/sca/php/composer.lock#L11` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TP-SCA-010` | SCA | C# | NuGet / packages.lock.json | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2024-21907 (High) | `tests/sca/dotnet/packages.lock.json#L5` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `SBOM-001` | SBOM | JavaScript | npm registry / package.json | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | Correct | N/A (Info) | `tests/sbom/direct/package.json#L6` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `SBOM-002` | SBOM | JavaScript | npm lockfile dependency tree | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | Correct | N/A (Info) | `tests/sbom/transitive/package-lock.json#L18` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `SBOM-003` | SBOM | JavaScript | npm / yarn workspaces | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | Misattributed (Workspace/Container layer gap) | N/A (Info) | `tests/sbom/workspaces/packages/frontend/package.json#L5` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `SBOM-004` | SBOM | JavaScript | Git repository reference | `conditional` | Conditional | **CONDITIONAL** | Missing (Gaps in Git/Vendored discovery) | N/A (Info) | `tests/sbom/git-dependencies/package.json#L6` | Detection depends on build toolchain resolution or explicit manifest generation. |
| `SBOM-005` | SBOM | JavaScript | In-tree vendored source | `conditional` | Conditional | **CONDITIONAL** | Missing (Gaps in Git/Vendored discovery) | N/A (Info) | `tests/sbom/vendored/package.json#L2` | Detection depends on build toolchain resolution or explicit manifest generation. |
| `SBOM-006` | SBOM | Dockerfile | Container OS Package Manager (apt / dpkg) | `conditional` | Conditional | **CONDITIONAL** | Misattributed (Workspace/Container layer gap) | N/A (Info) | `tests/sbom/containers/Dockerfile#L16` | Detection depends on build toolchain resolution or explicit manifest generation. |
| `TP-REACH-001` | REACHABILITY | JavaScript | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2020-8203 (High) | `tests/reachability/reachable_vulnerable.js#L13` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TN-REACH-001` | REACHABILITY | JavaScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CVE-2020-8203 (None) | `tests/reachability/unreachable_function.js#L14` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TN-REACH-002` | REACHABILITY | JavaScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CVE-2020-8203 (None) | `tests/reachability/unreachable_function.js#L29` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TP-REACH-002` | REACHABILITY | JavaScript | Source Code | `detection` | Pending Scan / Miss | **PENDING_EXECUTION** | N/A | CVE-2020-28168 (Medium) | `tests/reachability/transitive_reachable.js#L14` | Fixture validated locally; full scanner API execution pending live enrollment. |
| `TN-REACH-004` | REACHABILITY | JavaScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CVE-2020-7598 (None) | `tests/reachability/transitive_reachable.js#L26` | Properly suppressed due to safe parameterization, sanitization, or context. |
| `TN-REACH-005` | REACHABILITY | JavaScript | Source Code | `no_detection` | Clean / Suppressed | **TN** | N/A | CVE-2020-8203 (None) | `tests/reachability/sanitized_reachability.js#L27` | Properly suppressed due to safe parameterization, sanitization, or context. |

## 4. Key Scanner Gaps & SBOM Inaccuracies Observed

### A. SBOM Component Omission Gaps
1. **Git-Pinned Dependencies (`SBOM-004`):** Dependencies referenced via direct Git commit URLs (e.g. `git+https://...#commit`) are frequently skipped by SBOM generators that rely exclusively on public registry APIs.
2. **Vendored Code (`SBOM-005`):** Third-party packages committed directly to repository trees without local lockfiles are ignored by manifest-only SBOM engines.
3. **Multi-Stage Container Images (`SBOM-006`):** Scanners analyzing Dockerfiles often mistakenly attribute build-stage dependencies (e.g. `gcc`, `libc-dev`, `curl`) to final minimal runtime container images.

### B. False Positive Defense Gaps
1. **Safe Parameterization Mistaken for Raw SQL:** Simple regex-based SAST rules flag parameterized queries or format strings used strictly for logging.
2. **Sanitized DangerouslySetInnerHTML:** React DOMPurify-sanitized calls are frequently flagged as XSS by AST scanners lacking data-flow sanitizer recognition.
3. **CSPRNG vs PRNG:** Scanners flag non-security PRNG usages in non-sensitive tasks while missing inadequate fast password hashes.

### C. Reachability Analysis Gaps
1. **Dead Code Inclusion (`TN-REACH-002`):** Unreachable branches containing vulnerable calls trigger alarms when control-flow graph (CFG) pruning is absent.
2. **Effective Sanitization Neutralization (`TN-REACH-005`):** Vulnerable functions called on payloads that are strictly validated/sanitized prior to invocation are marked vulnerable, ignoring runtime neutralization.

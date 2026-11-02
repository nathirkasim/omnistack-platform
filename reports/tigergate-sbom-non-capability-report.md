# Technical Evaluation Report: TigerGate SBOM Engine Non-Capabilities

- **Target Evaluated:** [`nathirkasim/tigergate-sbom-coverage-testing`](https://github.com/nathirkasim/tigergate-sbom-coverage-testing) (branch `main`)
- **Evaluation Date:** November 2, 2026
- **Test Baseline:** 9 ground-truth binary targets across Java, Python, .NET, Go, Rust, C/C++, and Android
- **Verified Scan Report:** TigerGate Code Security Assessment Report (`11/2/2026, 7:05:39 AM`)

---

## 1. Executive Summary

Empirical testing reveals that **TigerGate is fundamentally incapable of generating a Software Bill of Materials (SBOM) from compiled binary archives, native executables, container layers, or unmanifested artifacts**.

When evaluated against a clean repository containing only standard compiled binary archives and native executables, TigerGate experienced a **100% engine failure in SBOM generation**:
- **Expected Components:** 9 production-grade dependencies
- **TigerGate SBOM Generated:** **0 components (0.0% coverage)**
- **Reported License Data:** **None (0.0%)**

In addition, the assessment identified a **critical architectural decoupling** between TigerGate's vulnerability scanner (SCA) and its inventory generator (SBOM), where vulnerable packages detected in raw file streams are omitted entirely from the generated Bill of Materials.

---

## 2. Evidence from Live TigerGate Scan Report

The following data points are transcribed directly from the verified 14-page TigerGate scan report:

### A. Total SBOM Failure (Pages 3 & 8)
- **Page 3 (Executive Summary):** Explicitly lists `0 SBOM Components` alongside `18 Vulnerable Deps`.
- **Page 8 (Software Bill of Materials):**
  > **"0 components (0 direct)."**  
  > **"No SBOM components."**  
  > **"No license data."**

### B. The SCA vs. SBOM Decoupling Defect (Page 5 vs. Page 8)
- **Page 5 (SCA):** Flags 18 vulnerable dependency findings (`org.apache.logging.log4j:log4j-core` and `commons-io:commons-io`).
- **Page 8 (SBOM):** Contains **0 components**.
- **Root Cause:** TigerGate’s backend performs naive regex searching for `pom.properties` strings inside zip streams to trigger CVE alert rules, but its SBOM builder pipeline is completely decoupled and fails to construct component nodes without an outer manifest (`pom.xml`).

### C. The NuGet Manifest Crutch Proof
- **Prior Run (with `App.deps.json`):** TigerGate detected `Newtonsoft.Json 12.0.3`.
- **Current Run (with `App.deps.json` removed, `.nupkg` archive remaining):** TigerGate detected **0** NuGet packages.
- **Conclusion:** TigerGate never inspected the NuGet binary archive; it was entirely dependent on reading the plaintext JSON manifest.

---

## 3. Comprehensive Breakdown of TigerGate Non-Capabilities

| Category | Specific Non-Capability | Real-World Impact | Verified Test Result |
| :--- | :--- | :--- | :---: |
| **Compiled Binary Archives** | Cannot unpack or inspect `.jar`, `.war`, `.whl`, `.tar.gz`, `.nupkg`, or `.aar` archives. | Packaged microservices, shaded JARs, and vendor libraries are invisible in SBOMs. | 🔴 **0% Coverage** (0/9 detected) |
| **Native Executables (Go/Rust)** | Cannot read compiled Go `runtime.buildinfo` tables or Rust `.dep-v0` (`cargo-auditable`) sections. | Monolithic Go/Rust compiled binaries appear as 0 dependencies. | 🔴 **0% Coverage** (0/2 detected) |
| **Shared Libraries (.so / .dll)** | Cannot inspect ELF dynamic string tables, `DT_SONAME`, or PE assembly metadata. | Native C/C++ third-party dependencies are missed entirely. | 🔴 **0% Coverage** (0/1 detected) |
| **Container Images & OS Packages** | Does not parse `RUN apk/apt/yum` in Dockerfiles, container layers, or base image digests. | Complete blindspot for OS-level vulnerabilities (OpenSSL, glibc, curl). | 🔴 **0% Coverage** (0/13 in full suite) |
| **Infrastructure as Code (IaC)** | Only runs static linting; does not extract Terraform providers/modules or Helm chart dependencies into SBOM. | Cloud infrastructure supply-chain dependencies are untracked. | 🔴 **0% Coverage** (0/8 in full suite) |
| **CI/CD Pipeline Dependencies** | Ignores GitHub Actions (`uses:`), GitLab CI templates, and Jenkins shared libraries. | Build-time supply chain attacks (e.g., poisoned actions) go undetected. | 🔴 **0% Coverage** (0/7 in full suite) |
| **Installed-on-Disk / Vendored** | Skips `node_modules/`, `site-packages/`, and inlined JS/C++ headers without root manifests. | Vendored code (e.g., jQuery, STB headers) is treated as first-party code. | 🔴 **0% Coverage** (0/8 in full suite) |
| **Cryptographic Integrity** | Generates zero cryptographic hashes (SHA-256, SHA-1) in component records. | Fails modern federal and regulatory compliance (e.g., US Executive Order 14028). | 🔴 **0% Hash Presence** |

---

## 4. Benchmark Comparison: TigerGate vs. Open-Source Standards

When the exact same isolated repository was evaluated against open-source industry standard tools (**Anchore Syft 1.55.0** and **OWASP cdxgen**):

```
┌────────────────────────────────────────────────────────────────────────┐
│                        COVERAGE COMPARISON                             │
├────────────────────────────────┬──────────────┬────────────────────────┤
│ Tool                           │ SBOM Output  │ Binary Detection Rate  │
├────────────────────────────────┼──────────────┼────────────────────────┤
│ TigerGate                      │ 0 components │  0.0% (Total Failure)  │
│ Anchore Syft                   │ 34 components│ 100.0% (Full Graph)    │
│ OWASP cdxgen                   │ 12 components│ 100.0% (Full Graph)    │
└────────────────────────────────┴──────────────┴────────────────────────┘
```
*Note: Syft detected all 9 ground-truth components plus the transitive dependency graph embedded in the Go binary (`gin-contrib/sse`, `protobuf`, `validator`, etc.).*

---

## 5. Architectural Root Cause & Recommendations

### Root Cause
TigerGate's architecture is restricted to **shallow filesystem pattern matching** on standard manifest filenames (`package.json`, `pom.xml`, `requirements.txt`). It lacks:
1. **Archive Catalogers:** No internal extraction engines for ZIP, tar, or nested archives.
2. **Binary Introspection:** No ELF/PE/Mach-O symbol or section parsers.
3. **Pipeline Cohesion:** The vulnerability detection rules operate in a silo disconnected from the SBOM inventory builder.

### Recommendations for TigerGate Product Team
1. **Embed a Binary Cataloger Sub-engine:** Adopt or embed an established open-source binary engine like [Anchore Syft](https://github.com/anchore/syft) to handle file unpacking and native binary symbol analysis.
2. **Unify SCA and SBOM Pipelines:** Ensure that any dependency triggering a vulnerability alert is automatically registered as a first-class component node in the SBOM graph.
3. **Add Native Container & Archive Parsers:** Implement dedicated parsers for Dockerfile OS commands, `.nupkg`, `.whl`, and Go `runtime.buildinfo`.

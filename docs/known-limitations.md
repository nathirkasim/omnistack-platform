# Known Scanner Limitations & Engineering Recommendations

This document outlines architectural limitations, detection blind spots, and concrete recommendations for enhancing TigerGate Code Security.

---

## 1. Static Application Security Testing (SAST)

### 1.1 Context-Unaware String Matching
- **Limitation:** SAST rules matching query construction (`SELECT * FROM ... + var`) flag instances where strings are constructed purely for logging, audit trails, or internal string formatting, even when the downstream database call is safely parameterized.
- **Recommendation:** Implement inter-procedural taint flow analysis that verifies whether tainted strings reach actual database sink functions (`execute()`, `query()`) rather than intermediate formatters.

### 1.2 Sanitizer Recognition
- **Limitation:** React components wrapping properties in `dangerouslySetInnerHTML` are flagged even when passed through standard sanitizers like `DOMPurify.sanitize()`.
- **Recommendation:** Register trusted sanitizer functions (`DOMPurify.sanitize`, `bleach.clean`, `htmlspecialchars`) as taint-cleansing nodes in the data-flow graph.

### 1.3 Cryptography & Randomness Context
- **Limitation:** `MD5` and `SHA1` are flagged universally as insecure cryptography, producing false positives for non-security checksums (ETags, static asset cache keys, git SHAs).
- **Recommendation:** Differentiate cryptographic hashing sinks (passwords, signatures, HMAC) from non-security checksum operations based on method call context.

---

## 2. Software Composition Analysis (SCA) & SBOM

### 2.1 Git and URL Dependency Omission
- **Limitation:** Dependencies defined with Git URLs (`git+https://github.com/...#commit`) are frequently dropped from SBOM generation because standard package registry metadata cannot be queried.
- **Recommendation:** Support VCS-based PURLs (`pkg:generic/...` or `pkg:github/...`) with commit SHA attribution when registry resolution is unavailable.

### 2.2 Monorepo Version Collisions
- **Limitation:** In monorepos with multiple workspaces declaring different versions of the same package (e.g. `react@17.0.2` in frontend vs `react@18.2.0` in backend), scanners flatten the inventory and attribute only one version.
- **Recommendation:** Index dependencies scoped to each workspace `package.json` subpath and support multi-component SBOM trees.

### 2.3 Container Layer vs Dockerfile Static Parsing
- **Limitation:** Parsing Dockerfiles statically treats build-time dependencies (`gcc`, `curl`) as runtime vulnerabilities, corrupting the runtime SBOM.
- **Recommendation:** Implement layer-differentiated container SBOM analysis (using Syft/Trivy filesystem scanning) rather than purely regex-parsing the `Dockerfile`.

---

## 3. Reachability Analysis

### 3.1 Dead Code Elimination
- **Limitation:** Vulnerable functions located in dead code (e.g., branches governed by compile-time constants or `if (false)`) trigger high-severity alerts.
- **Recommendation:** Integrate control-flow graph (CFG) pruning to discard unreachable code blocks before evaluating reachability call graphs.

### 3.2 Effective Pre-Validation Guards
- **Limitation:** If user input is strictly validated by schema validators (e.g., rejecting `__proto__` and `constructor` keys before passing to `lodash.merge`), scanners still report reachable prototype pollution.
- **Recommendation:** Detect schema validation guards that dominate vulnerable method invocations.

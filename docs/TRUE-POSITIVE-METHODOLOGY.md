# True Positive Testing Methodology

## 1. Definition of True Positive
Every fixture in this repository meets three strict criteria:
1. **Real Vulnerability:** The code contains an actual, unmitigated flaw that violates confidentiality, integrity, or availability.
2. **Reachable & Exploitable:** The flaw is not dead code or blocked by existing sanitizers.
3. **Documented Ground Truth:** Every finding maps to an official CWE, CVE, or CIS Benchmark identifier with an authoritative reference.

## 2. Category Testing Standards

### SAST Standards
- **Data Flow & Taint Tracking:** Sources, sinks, and sanitizers are clearly structured. Test fixtures include direct, multi-function, and cross-file taint propagation.
- **Framework Realism:** Real frameworks (Flask, Express, Spring Boot, Gin, Rails, ASP.NET Core) are used instead of synthetic dummy snippets.

### SCA Standards
- **Exact Pinned Versions:** All package manifests and lockfiles pin versions directly linked to published advisories.
- **Dependency Paths:** Direct and transitive relationships are mapped to test dependency graph reconstruction.

### IaC Standards
- **Cloud Security Best Practices:** Misconfigurations are modeled against CIS Benchmarks for AWS, Kubernetes, and Docker.

### Secrets Standards
- **Pattern Authenticity:** Secrets strictly follow realistic provider prefixes (`AKIA...`, `ghp_...`, `glpat-...`, `sk_test_...`) using safe, nonfunctional synthetic entropy.

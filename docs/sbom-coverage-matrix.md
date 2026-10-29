# Software Bill of Materials (SBOM) Coverage Matrix

This matrix documents the package managers, manifest formats, lockfile specifications, and acquisition methods evaluated in this suite.

## 1. Supported Ecosystems & Manifest Inventory

| Ecosystem | Manifest Format | Lockfile Format | Test Fixture Path | Expected PURL Format |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | `requirements.txt` | N/A (Pinned) | `tests/sca/python/requirements.txt` | `pkg:pypi/urllib3@1.26.4` |
| **Python (Poetry)** | `pyproject.toml` | `poetry.lock` | `tests/sca/python/poetry.lock` | `pkg:pypi/requests@2.19.1` |
| **npm (Node.js)** | `package.json` | `package-lock.json` | `tests/sca/npm/package-lock.json` | `pkg:npm/lodash@4.17.15` |
| **Yarn (Node.js)** | `package.json` | `yarn.lock` | `tests/sca/npm/yarn.lock` | `pkg:npm/axios@0.21.0` |
| **pnpm (Node.js)** | `package.json` | `pnpm-lock.yaml` | `tests/sca/npm/pnpm-lock.yaml` | `pkg:npm/lodash@4.17.15` |
| **Java (Maven)** | `pom.xml` | N/A (Direct) | `tests/sca/java/pom.xml` | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| **Java (Gradle)** | `build.gradle` | `gradle.lockfile` | `tests/sca/java/build.gradle` | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| **Go** | `go.mod` | `go.sum` | `tests/sca/go/go.mod` | `pkg:golang/golang.org/x/crypto@0.0.0-20201221181555-eec23a3978ad` |
| **Rust** | `Cargo.toml` | `Cargo.lock` | `tests/sca/rust/Cargo.lock` | `pkg:cargo/smallvec@0.6.13` |
| **Ruby** | `Gemfile` | `Gemfile.lock` | `tests/sca/ruby/Gemfile.lock` | `pkg:gem/rack@2.0.8` |
| **PHP** | `composer.json` | `composer.lock` | `tests/sca/php/composer.lock` | `pkg:composer/guzzlehttp/guzzle@7.4.2` |
| **.NET** | `.csproj` | `packages.lock.json` | `tests/sca/dotnet/packages.lock.json`| `pkg:nuget/Newtonsoft.Json@12.0.2` |
| **C/C++** | `conanfile.txt` | N/A | `tests/sca/cpp/conanfile.txt` | `pkg:conan/openssl@1.1.1k` |
| **Container OS** | `Dockerfile` | Container Layers | `tests/sbom/containers/Dockerfile` | `pkg:deb/debian/libssl3` |

---

## 2. Dependency Acquisition Methods & Discovery Expectations

| Acquisition Method | Expected Behavior | Scanner Limitation / Risk |
| :--- | :--- | :--- |
| **Public Registry** | Direct component identified, version pinned, CVE mapped. | None. Standard baseline for all scanners. |
| **Transitive Graph** | Resolved transitively; dependency edge linked to direct parent. | Missing parent edges; flat listing without graph relationships. |
| **Monorepo Workspaces** | Independent subprojects tracked separately; conflicting versions recorded per package. | Version flattening; picking first version encountered across all workspaces. |
| **Git URL Pinned** | VCS component recognized, commit hash preserved in PURL. | Often omitted because scanner cannot fetch metadata from standard registry. |
| **Vendored Code** | In-tree library discovered via filename or AST signature. | Frequently omitted unless file-level hash scanning is specifically enabled. |
| **Multi-Stage Docker** | Build dependencies (`gcc`, `curl`) excluded from runtime image; only runtime layers indexed. | Scanners reading raw Dockerfile without image inspection over-report build dependencies. |

# OmniFlow Enterprise CRM & Predictive Analytics Platform

OmniFlow is an enterprise-grade full-stack customer relationship management (CRM) and predictive revenue analytics application built with modern PHP 8.2+, PostgreSQL, Redis, and a client-side JavaScript dashboard.

In addition to functioning as a full-stack enterprise architecture, this codebase serves as a benchmark and verification suite for application security engines across **SAST**, **SCA**, **SECRETS**, **IAC**, **SBOM**, **AIBOM**, and **CBOM** to evaluate detection precision and identify **False Positives (FPs)** vs **True Positives (TPs)**.

---

## 🏛 System Architecture

- **Backend Framework**: Modern PSR-4 modular PHP 8.2 backend with layered architecture (`Core`, `Controller`, `Service`, `Repository`, `Security`).
- **Database & Cache**: PostgreSQL 15 (relational entities, invoices, customer telemetry) & Redis 7 (rate limiting, transient query caching).
- **Frontend & Assets**: Responsive dark-mode executive dashboard with Chart.js analytics telemetry.
- **AI & Predictive Engine**: AIBOM-traceable Lead Scoring Engine powered by gradient boosting classifier models and ONNX pipeline manifests (`ai/`).
- **Cryptography & Security**: Argon2id password hashing, AES-256-GCM envelope encryption, and CycloneDX 1.5 CBOM cryptography inventory (`cbom/`).
- **Infrastructure as Code**: Multi-stage production `Dockerfile`, `docker-compose.yml`, Kubernetes deployment manifests (`kubernetes/`), and AWS Terraform configurations (`terraform/`).

---

## 🛡️ False Positive Security Matrix & Analysis Guide

This repository contains intentional, production-style coding patterns designed to test whether security scanners rely on simplistic regex / AST pattern matching (yielding False Positives) or perform deep semantic taint and data-flow analysis.

### 1. Static Application Security Testing (SAST)

| Vulnerability Type | Triggering Code Sink | Why Scanners Flag It (False Positive) | Why It Is Actually Safe | Code Reference |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection** | `PDO::query($sql)` | Concatenation of `$sortColumn` and `$sortDirection` into SQL statement. | Strict whitelist validation against allowed schema columns and uppercase `DESC`/`ASC` enum enforcement in `Database::buildSafeOrderedQuery`. | [`Database.php`](src/Core/Database.php) |
| **SQL Injection** | `SELECT ... WHERE id = " . $id` | Direct string concatenation into WHERE clause. | `$id` is strictly cast to integer using `(int)$id`, mathematically preventing syntax injection. | [`CustomerRepository.php`](src/Repository/CustomerRepository.php) |
| **Command Injection** | `exec($cmd)` | System command string execution with dynamic title parameter. | Absolute binary path used; file paths generated with `bin2hex(random_bytes(16))`; titles strictly escaped via `escapeshellarg()`. | [`ReportGeneratorService.php`](src/Service/ReportGeneratorService.php) |
| **Path Traversal / LFI** | `file_get_contents($path)` | File read on variable path derived from request query. | Directory traversal stripped via `basename()`, resolved with `realpath()`, and strictly bounded to authorized storage via `str_starts_with()`. | [`ReportGeneratorService.php`](src/Service/ReportGeneratorService.php) |
| **SSRF** | `curl_setopt($ch, CURLOPT_URL, $url)` | Outbound cURL HTTP request dispatched to tenant-provided URL. | Validated HTTPS protocol, host DNS resolution, and strict exclusion of RFC 1918 private, loopback, and cloud metadata (169.254.169.254) IP spaces. | [`WebhookDispatcher.php`](src/Service/WebhookDispatcher.php) |
| **Insecure Deserialization** | `unserialize($blob)` | Native PHP deserialization on cache blob. | Explicitly disallows object instantiation via `['allowed_classes' => false]`, preventing any POP/gadget chain execution. | [`CustomerService.php`](src/Service/CustomerService.php) |
| **Open Redirect** | `header("Location: ...")` | Redirection based on user query string `return_to`. | Normalized relative URL check enforces leading slash `/` and rejects protocol-relative `//` or external domains. | [`Sanitizer.php`](src/Security/Sanitizer.php) |
| **Reflected XSS** | Dynamic JSON API output | Scanners flag request inputs returned in response body. | Sanitized with `htmlspecialchars()` in HTML views and serialized with `JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP` in API responses. | [`Response.php`](src/Core/Response.php) |

---

### 2. Software Composition Analysis (SCA) & SBOM

- **PHP Composer Dependency Graph**: Complete `composer.json` and locked `composer.lock` containing hashes, licenses, and packages (`symfony/http-foundation`, `doctrine/dbal`, `twig/twig`, `monolog/monolog`, `guzzlehttp/guzzle`, `ramsey/uuid`).
- **Dev-Scoped CVE Isolation**: Development tools (`phpunit/phpunit`, `mockery/mockery`, `fakerphp/faker`) are isolated in `require-dev`. Scanners should distinguish runtime vs build-time CVE impact.
- **Frontend Dependencies**: Includes locked `package.json` and `package-lock.json` (`chart.js`, `lucide`, `vite`, `tailwindcss`) for comprehensive full-stack SBOM extraction.

---

### 3. Secrets Detection

- **AWS Credential Fixture**: Sample `AKIAIOSFODNN7EXAMPLE` with standard documentation secret in `.env.example` and `TokenService.php`. Scanners should identify RFC 5737 documentation credentials rather than active leaks.
- **Stripe Sample Test Key**: Official Stripe documentation test key `sk_test_4eC39HqLyjWDarjtT1zdp7dc`.
- **JWT RFC 7519 Test Token**: Standard public documentation JWT with mock signature.

---

### 4. Infrastructure as Code (IAC)

- **Dockerfile Non-Root Dropping**: Scanners flag `apk` operations running as root; however, the multi-stage build switches to unprivileged `USER www-data` before port `8080` exposure.
- **Kubernetes Pod Security**: `kubernetes/deployment.yaml` specifies `runAsNonRoot: true` with dropped capabilities. The `readOnlyRootFilesystem: false` setting is accompanied by an architectural justification for ephemeral PDF generation.
- **Terraform IAM Scoping**: `terraform/main.tf` features an S3 bucket IAM policy with resource ARN `arn:aws:s3:::omniflow-crm-reports/*` which scanners flag for wildcard usage, despite being properly scoped to bucket object keys.

---

### 5. AI Bill of Materials (AIBOM)

- **Model Provenance**: Documented in [`ai/models/lead_scorer/model-card.json`](ai/models/lead_scorer/model-card.json) specifying architecture, training datasets, ethical fairness audits, and hyperparameters.
- **Weights Integrity**: Tracked in [`ai/models/lead_scorer/weights_manifest.json`](ai/models/lead_scorer/weights_manifest.json) with SHA-256 hashes and ONNX v1.17 format specifications.
- **Inference Pipeline**: Configured in [`ai/pipeline_manifest.yaml`](ai/pipeline_manifest.yaml) mapping feature ranges, normalization constraints, and inference runtime parameters.

---

### 6. Cryptography Bill of Materials (CBOM)

- **Inventory Specification**: Declared in [`cbom/cryptography-inventory.json`](cbom/cryptography-inventory.json) conforming to CycloneDX 1.5 CBOM schema.
- **Non-Cryptographic Hashing**:
  - `MD5`: Used in `AuthenticationManager::generateRateLimitCacheKey` strictly for uniform Redis rate-limit key distribution.
  - `SHA-1`: Used in `Response::withETag` strictly for RFC 7232 HTTP entity tag validation.
- **Legacy Cipher Rejection**: `CryptoPolicyManager::BANNED_CIPHERS` defines deprecated ciphers (`RC4`, `DES`, `3DES`) inside a rejection list to enforce NIST SP 800-131A standards. Scanners scanning for cipher strings should not misidentify the blacklist as insecure usage.

---

## 🚀 Getting Started

### Local Development via Docker Compose

```bash
# Clone the repository
git clone git@greedily-defrost-proclaim.ngrok-free.dev:nathir-selfhosted/nathir-gradlew.git
cd nathir-gradlew

# Launch full stack application
docker compose up -d

# Access Dashboard
open http://localhost:8000
```

### Running Unit Tests

```bash
docker compose exec app vendor/bin/phpunit
```

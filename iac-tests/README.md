# Ground-Truth IaC Security Test Corpus

A standardized, multi-cloud Infrastructure-as-Code (IaC) test corpus designed to benchmark and evaluate IaC security scanners (e.g., Checkov, Trivy, tfsec, KICS, Terrascan, Prowler).

The corpus is built to identify both:
1. **False Negatives (Blind Spots & Evasions)**: What real vulnerabilities can the scanner NOT detect due to syntactic evasion, multi-file indirection, dynamic functions, nested modules, or template metaprogramming?
2. **False Positives (Noise)**: What safe, mitigated, or intentional configurations does the scanner wrongly flag as vulnerabilities?

> [!IMPORTANT]
> **SYNTHETIC FIXTURES ONLY**: All credentials, secret tokens, private keys, AWS account numbers, hostnames, and passwords in this corpus are strictly synthetic test fixtures (e.g. AWS documentation example keys like `AKIAIOSFODNN7EXAMPLE`). No real infrastructure is deployed, and no real cloud APIs are ever contacted.

---

## 1. Directory Structure

Every test case is self-contained in its own directory:

```
iac-tests/
├── <iac-type>/
│   └── <category>/
│       └── <case-id>/
│           ├── case.yaml              # Structured test metadata & ground truth
│           └── <fixture-files>        # Minimal, syntactically valid manifest(s)
└── GROUND_TRUTH.csv                   # Master compiled catalog of all test cases
```

### Supported IaC Types (19 Total)

1. `terraform`: HashiCorp Terraform / OpenTofu (`.tf`, `.tf.json`, `.tfvars`)
2. `terragrunt`: Terragrunt configurations (`terragrunt.hcl`, inputs, includes)
3. `cloudformation`: AWS CloudFormation (`template.yaml`, `template.json`, SAM, nested stacks)
4. `cdk`: AWS CDK, CDKTF, and Pulumi (synthesized outputs + source code)
5. `kubernetes`: Native Kubernetes manifests (`Deployment`, `Pod`, `DaemonSet`, `CronJob`, RBAC, PSA)
6. `helm`: Templated Helm charts (`Chart.yaml`, `values.yaml`, `templates/`)
7. `kustomize`: Kustomize overlays & patches (strategic merge, RFC 6902 JSON patches)
8. `argocd-flux`: GitOps manifests (ArgoCD `Application`, Flux `Kustomization` & `HelmRelease`)
9. `dockerfile`: Container build files (`Dockerfile`)
10. `docker-compose`: Multi-container Compose specifications (`docker-compose.yml`)
11. `ansible`: Configuration management playbooks (`playbook.yml`, tasks)
12. `packer`: Machine image templates (HCL2, JSON)
13. `bicep-arm`: Azure Bicep (`.bicep`) and Azure Resource Manager (`azuredeploy.json`)
14. `serverless`: Serverless Framework services (`serverless.yml`)
15. `github-actions`: GitHub Actions CI/CD workflows (`workflow.yml`)
16. `gitlab-ci`: GitLab CI pipelines (`.gitlab-ci.yml`)
17. `azure-pipelines`: Azure DevOps pipelines (`azure-pipelines.yml`)
18. `cloudbuild`: Google Cloud Build specifications (`cloudbuild.yaml`)
19. `crossplane`: Kubernetes Crossplane Compositions & Managed Resources (`Bucket`, `RDSInstance`)

---

## 2. Test Case Labels

Each test case is assigned exactly one of three ground-truth labels:

| Label | Definition | Evaluated Verdict |
| :--- | :--- | :--- |
| **`TRUE_POSITIVE`** | Obvious, direct baseline misconfiguration (e.g., world-readable S3 bucket, privileged container). Scanners must detect this. | Finding = **TP**<br>No Finding = **FN** |
| **`EVASIVE_MISCONFIG`** | Genuine vulnerability deliberately disguised through HCL indirection, split files, nested modules, function composition, or parser tricks to test scanner limits. | Finding = **TP**<br>No Finding = **FN** |
| **`SAFE_LOOKALIKE`** | Manifest that superficially resembles a misconfiguration but is architecturally secure (e.g., conditional `count = 0`, IAM wildcard neutralized by `Condition`, split resources in AWS provider v4+). Scanners should NOT alert. | Finding = **FP**<br>No Finding = **TN** |

---

## 3. Case Metadata Schema (`case.yaml`)

Every case directory contains a `case.yaml` file conforming to the following specification:

```yaml
id: "TF-VAR-002"
iac_type: "terraform"
category: "variables-indirection"
label: "EVASIVE_MISCONFIG"
severity: "HIGH"
description: "S3 bucket has safe default 'private' in variables.tf but overridden to 'public-read' in terraform.tfvars"
why_scanner_may_fail: "Scanners that analyze only main.tf or ignore .tfvars files will only see the safe default 'private' and fail to flag the real vulnerability (False Negative)."
expected_findings:
  - rule: "CKV_AWS_20"
    cwe: "CWE-732"
    cis: "CIS AWS 1.4 - 2.1.5"
    nist: "AC-3, MP-2"
    resource: "aws_s3_bucket.app_bucket"
    file: "main.tf"
    line: 6
    severity: "HIGH"
expected_no_findings: []
compliance:
  cis: "2.1.5"
  nist_800_53: "AC-3"
  pci_dss: "1.3"
  soc2: "CC6.1"
source_refs:
  - "https://docs.bridgecrew.io/docs/bc_aws_s3_1"
undeliverable_static: false
```

---

## 4. Test Case Distribution Matrix

| IaC Type | TRUE_POSITIVE | EVASIVE_MISCONFIG | SAFE_LOOKALIKE | Total Cases |
| :--- | :---: | :---: | :---: | :---: |
| `terraform` | 10 | 14 | 11 | **35** |
| `kubernetes` | 2 | 4 | 2 | **8** |
| `cloudformation` | 4 | 2 | 1 | **7** |
| `helm` | 1 | 1 | 1 | **3** |
| `kustomize` | 1 | 1 | 1 | **3** |
| `dockerfile` | 1 | 1 | 1 | **3** |
| `docker-compose` | 1 | 1 | 1 | **3** |
| `github-actions` | 1 | 1 | 1 | **3** |
| `gitlab-ci` | 1 | 0 | 1 | **2** |
| `azure-pipelines` | 1 | 0 | 1 | **2** |
| `cloudbuild` | 1 | 0 | 1 | **2** |
| `terragrunt` | 1 | 1 | 1 | **3** |
| `cdk` | 1 | 0 | 1 | **2** |
| `serverless` | 1 | 0 | 1 | **2** |
| `ansible` | 1 | 1 | 1 | **3** |
| `packer` | 1 | 0 | 1 | **2** |
| `bicep-arm` | 2 | 1 | 0 | **3** |
| `argocd-flux` | 1 | 1 | 0 | **2** |
| `crossplane` | 1 | 0 | 1 | **2** |
| **Total** | **32** | **29** | **28** | **89** |

---

## 5. How to Run Scanners and Score Results

### Step 1: Execute Scanner

Use `scripts/run_scan.sh` to run either a target scanner or local open-source baselines (Checkov, Trivy):

```bash
# Run baseline Checkov scan over iac-tests
./scripts/run_scan.sh reports/checkov_scan.json

# Run baseline Trivy scan over iac-tests
SCANNER_TYPE=trivy ./scripts/run_scan.sh reports/trivy_scan.json

# Run custom scanner via SCANNER_CMD
SCANNER_CMD="my-iac-scanner --dir iac-tests --format json" ./scripts/run_scan.sh reports/my_scanner.json
```

### Step 2: Score Against Ground Truth

Use `scripts/score.py` to compare scanner findings with `iac-tests/GROUND_TRUTH.csv`:

```bash
python3 scripts/score.py reports/checkov_scan.json
```

The scoring harness will:
1. Attribute findings to each test case.
2. Calculate True Positives, False Positives, False Negatives, and True Negatives.
3. Compute Precision, Recall, and F1-score across every IaC type and category.
4. Output a summary table in the terminal.
5. Generate a comprehensive Markdown audit report at `reports/gap-report.md`.


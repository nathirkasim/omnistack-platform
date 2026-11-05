# Repository Inventory: `omnistack-platform`

## 1. Executive Summary

`omnistack-platform` originated as a multi-domain code security benchmark (`codesec-benchmark`) encompassing Static Application Security Testing (SAST), Software Composition Analysis (SCA), Secrets Detection, and initial Infrastructure-as-Code (IaC) probes.

This inventory provides an audit of all existing directory structures, file assets, IaC resource types, and existing ground truth definitions in preparation for extending the repository into a ground-truth IaC test corpus for evaluating IaC security scanners.

---

## 2. Directory Hierarchy

```
omnistack-platform/
├── basic/                                # Baseline test fixtures
│   ├── iac/                              # Direct IaC manifests
│   │   ├── compose/                      # Docker Compose definitions (docker-compose.yml)
│   │   ├── docker/                       # Container build recipes (Dockerfile)
│   │   ├── k8s/                          # Native Kubernetes manifests (deployment.yaml)
│   │   └── terraform/                    # HashiCorp Terraform configuration (main.tf)
│   ├── sast/                             # Polyglot SAST samples (go, java, node, python)
│   ├── sca/                              # Direct dependency manifests (pip, maven, npm, go.mod)
│   └── secrets/                          # Secret leak patterns (PEM, API keys, JWT, env)
├── advanced/                             # Advanced & evasive test fixtures
│   ├── evasion/                          # Twin pairs and semantic obfuscation (SAST, secrets)
│   ├── harness/                          # Mutation generators and scale utilities
│   ├── iac/                              # Advanced IaC constructs
│   │   ├── helm/                         # Templated Helm chart (templates, dev/prod values)
│   │   ├── kustomize/                    # Kustomize base and overlay patches (dev/prod)
│   │   ├── rendered/                     # Pre-rendered YAML/TF outputs
│   │   └── terraform/                    # Dynamic blocks, locals, counts, module calls
│   ├── mutants/                          # Syntax mutants
│   ├── sca/                              # Deep reachability & transitive dependencies
│   ├── secrets-history/                  # Git commit history and format traps
│   └── taint/                            # Inter-procedural multi-hop taint flows
├── reports/                              # Historical evaluation runs & reports
├── docs/                                 # Documentation & architecture specifications
├── ground_truth.csv                      # Legacy benchmark ground truth catalog (556 entries)
├── ground_truth.json                     # JSON format of benchmark catalog
├── build_all_gt.py                       # Ground truth builder script
├── check_builds.sh                       # Build verification script
├── score.py                              # Legacy benchmark scoring harness
├── validate_gt.py                        # Ground truth schema validator
└── README.md                             # Repository overview and setup instructions
```

---

## 3. Existing IaC Assets & Declared Resources

### 3.1. Basic IaC Manifests (`basic/iac/`)

| File Path | IaC Technology | Declared Resources / Directives | Embedded Test Cases |
| :--- | :--- | :--- | :--- |
| `basic/iac/terraform/main.tf` | Terraform (AWS Provider) | - `aws_s3_bucket.insecure_data_bucket`<br>- `aws_s3_bucket.static_site_bucket`<br>- `aws_security_group.ssh_bastion`<br>- `aws_security_group.public_alb`<br>- `aws_db_instance.insecure_db`<br>- `aws_db_instance.secure_kms_db`<br>- `aws_iam_policy.wildcard_admin`<br>- `aws_iam_policy.scoped_wildcard`<br>- `aws_cloudtrail.insecure_trail` | `IAC-TF-001` (TP: Public S3 ACL)<br>`IAC-TF-002` (TP: Open SSH 0.0.0.0/0)<br>`IAC-TF-003` (TP: Unencrypted RDS storage)<br>`IAC-TF-004` (TP: IAM `*` wildcard)<br>`IAC-TF-005` (TP: CloudTrail logging disabled)<br>`IAC-TF-006` (FP: ALB port 443 0.0.0.0/0)<br>`IAC-TF-007` (FP: Static site public bucket)<br>`IAC-TF-008` (FP: Encrypted RDS with KMS)<br>`IAC-TF-009` (FP: Scoped S3 IAM action) |
| `basic/iac/k8s/deployment.yaml` | Kubernetes Manifest | - `Deployment/workload-processor` (Namespace: production)<br>- Container: `app-service:1.2.0`<br>- Volume: `dockersock` (`/var/run/docker.sock`) | `IAC-K8S-001` (TP: Privileged container)<br>`IAC-K8S-002` (TP: `hostNetwork: true`)<br>`IAC-K8S-003` (TP: `runAsNonRoot: false`)<br>`IAC-K8S-004` (TP: `hostPath` Docker socket)<br>`IAC-K8S-005` (FP: `readOnlyRootFilesystem: true`)<br>`IAC-K8S-006` (FP: `capabilities.drop: [ALL]`) |
| `basic/iac/compose/docker-compose.yml` | Docker Compose (v3.8) | - Service: `database` (`postgres:15-alpine`)<br>- Service: `system-agent` (`agent:latest`)<br>- Service: `internal-worker` (`worker:1.0.0`)<br>- Network: `internal_net` (internal: true) | `IAC-COMPOSE-001` (TP: Privileged service)<br>`IAC-COMPOSE-002` (TP: Mounted `/var/run/docker.sock`)<br>`IAC-COMPOSE-003` (TP: Exposed DB port 5432 to 0.0.0.0)<br>`IAC-COMPOSE-004` (FP: Isolated internal network)<br>`IAC-COMPOSE-005` (FP: Read-only volume mount `:ro`) |
| `basic/iac/docker/Dockerfile` | Dockerfile | - Multi-stage: `builder` (`golang:1.20-alpine`) & `runtime` (`ubuntu:latest`)<br>- Root commands, curl pipe to sh, ARG token | `IAC-DOCKER-001` (TP: Run as root)<br>`IAC-DOCKER-002` (TP: Unpinned `:latest` tag)<br>`IAC-DOCKER-003` (TP: `ADD` from remote URL)<br>`IAC-DOCKER-004` (TP: Secret in `ARG`)<br>`IAC-DOCKER-005` (TP: `curl \| sh` execution)<br>`IAC-DOCKER-006` (FP: Builder stage root permitted)<br>`IAC-DOCKER-007` (FP: Non-root user in runtime stage)<br>`IAC-DOCKER-008` (FP: "latest" keyword in comment) |

---

### 3.2. Advanced IaC Manifests (`advanced/iac/`)

| File Path | IaC Technology | Declared Constructs | Embedded Test Cases |
| :--- | :--- | :--- | :--- |
| `advanced/iac/terraform/main.tf` | Terraform (Dynamic / Modules) | - Dynamic `ingress` blocks via `for_each`<br>- Local ternary variables (`var.environment == "prod" ? "public-read" : "private"`)<br>- Count conditions (`count = var.create_insecure_bucket ? 1 : 0`, `count = 0`)<br>- Subnet/EC2/SG cross-resource correlation<br>- Local module calls (`./modules/rds`) | `IAC-TF-1001` (TP: Local ternary S3 public-read)<br>`IAC-TF-1002` (TP: Dynamic block SSH 0.0.0.0/0)<br>`IAC-TF-1003` (TP: Module parameter unencrypted)<br>`IAC-TF-1004` (TP: Public IP + Subnet + Open SG trio)<br>`IAC-TF-1005` (TP: Count 1 insecure bucket)<br>`IAC-TF-1006` (TP: Dynamic block wildcard IAM)<br>`IAC-TF-1007` (FP: Dev env private ACL ternary)<br>`IAC-TF-1008` (FP: Dynamic block HTTPS 443)<br>`IAC-TF-1009` (FP: Module parameter encrypted)<br>`IAC-TF-1010` (FP: Isolated unattached SG)<br>`IAC-TF-1011` (FP: Private subnet no public IP)<br>`IAC-TF-1012` (FP: `count = 0` inactive bucket)<br>`IAC-TF-1013` (FP: Dynamic scoped ARN IAM) |
| `advanced/iac/helm/templates/deployment.yaml` | Helm Chart | - Parametric `securityContext.privileged` based on `.Values.debug.enabled`<br>- Parametric `securityContext.readOnlyRootFilesystem`<br>- Conditional `hostPath` mount for `/var/run/docker.sock`<br>- Conditional TLS ingress block based on `.Values.tls.enabled` | `IAC-HELM-0001` (TP: Debug enabled adds privileged)<br>`IAC-HELM-0002` (TP: Host mount docker socket)<br>`IAC-HELM-0003` (TP: TLS block omitted in Ingress)<br>`IAC-HELM-0004` (FP: Default readonly rootfs)<br>`IAC-HELM-0005` (FP: TLS block present in dev/safe) |
| `advanced/iac/kustomize/base/deployment.yaml`<br>`advanced/iac/kustomize/overlays/dev/patch.yaml`<br>`advanced/iac/kustomize/overlays/prod/patch.yaml` | Kustomize Overlays | - Base workload: safe/minimal<br>- Dev overlay: enforces `runAsNonRoot: true`, drops `ALL` capabilities, mounts ConfigMap<br>- Prod overlay: enables `hostNetwork: true`, `privileged: true`, mounts `/etc/shadow` | `IAC-KUST-0001` (TP: Prod overlay adds privileged)<br>`IAC-KUST-0002` (TP: Prod overlay enables hostNetwork)<br>`IAC-KUST-0003` (TP: Prod overlay mounts /etc/shadow)<br>`IAC-KUST-0004` (FP: Dev overlay hardens base)<br>`IAC-KUST-0005` (FP: Dev overlay drops all capabilities)<br>`IAC-KUST-0006` (FP: Dev overlay mounts safe ConfigMap) |
| `advanced/iac/rendered/*` | Pre-rendered IaC Artifacts | - Fully synthesized YAML and Terraform outputs for dev/prod states | Mirrors resolved states for AST scanner comparison |

---

## 4. Gap Analysis: Target IaC Corpus Requirements

While the existing repository contains foundational IaC test cases in basic and advanced folders, it lacks systematic coverage across modern infrastructure platforms, multi-cloud architectures, CI/CD pipelines, container orchestration frameworks, and advanced evasion techniques.

### IaC Framework Support Comparison

| IaC Technology / Platform | Status in Repo | Target Corpus Requirement |
| :--- | :--- | :--- |
| **Terraform / OpenTofu** (.tf, .tf.json, .tfvars) | Partial (2 monolithic files) | Modular test suite under `iac-tests/terraform/` covering all 17 scenario classes |
| **Terragrunt** | Missing | Dedicated cases in `iac-tests/terragrunt/` (inputs, includes, mock outputs) |
| **AWS CloudFormation** (YAML/JSON, SAM, Nested) | Missing | Dedicated cases in `iac-tests/cloudformation/` (SAM, nested, intrinsic functions) |
| **AWS CDK / CDKTF / Pulumi** | Missing | Dedicated cases in `iac-tests/cdk/` (source + synthesized CFN/TF) |
| **Kubernetes Manifests** | Partial (1 deployment) | Full suite in `iac-tests/kubernetes/` (RBAC, PSA, DaemonSets, NetworkPolicies) |
| **Helm Charts** (Templated) | Partial (1 chart) | Parametric test fixtures in `iac-tests/helm/` (subcharts, conditionals, tpl) |
| **Kustomize Overlays** | Partial (1 overlay pair) | Advanced patches in `iac-tests/kustomize/` (strategic merge, JSON 6902, components) |
| **ArgoCD & Flux** | Missing | GitOps CRDs in `iac-tests/argocd-flux/` (Application, HelmRelease, Kustomization) |
| **Dockerfile** | Partial (1 file) | Dedicated cases in `iac-tests/dockerfile/` (multi-stage, secret leak, base image) |
| **Docker Compose** | Partial (1 file) | Dedicated cases in `iac-tests/docker-compose/` (capabilities, sockets, ports) |
| **Ansible Playbooks** | Missing | Dedicated cases in `iac-tests/ansible/` (no_log, validate_certs, command creds) |
| **Packer Templates** | Missing | Dedicated cases in `iac-tests/packer/` (HCL2, JSON, provisioner secrets) |
| **Azure Bicep / ARM** | Missing | Dedicated cases in `iac-tests/bicep-arm/` (NSG rules, KeyVault, public storage) |
| **Serverless Framework** | Missing | Serverless YAML in `iac-tests/serverless/` (IAM roles, API Gateway, open endpoints) |
| **GitHub Actions** | Missing (in IaC context) | Workflows in `iac-tests/github-actions/` (pull_request_target, unpinned actions, script injection) |
| **GitLab CI** | Missing | Workflows in `iac-tests/gitlab-ci/` (insecure runners, debug exposed tokens) |
| **Azure Pipelines** | Missing | Pipelines in `iac-tests/azure-pipelines/` (untrusted checkout, over-privileged tokens) |
| **Google Cloud Build** | Missing | Pipelines in `iac-tests/cloudbuild/` (unpinned builders, root execution) |
| **Crossplane / Custom CRDs** | Missing | Compositions & Managed Resources in `iac-tests/crossplane/` (XRD, RDSInstance) |

---

## 5. Local Tooling & Scanner Execution Environment

The evaluation environment provides the following linters and security scanners natively installed:

- **Terraform**: `/usr/bin/terraform` (v1.5+)
- **Trivy**: `/usr/bin/trivy` (v0.76.1 with misconfiguration / config check bundle)
- **Checkov**: `checkov` (v3.4.3 with AWS, K8s, Docker, CloudFormation, Helm parsers)
- **cfn-lint**: `cfn-lint` (v1.59.0 for AWS CloudFormation schema validation)
- **Helm**: `/usr/local/bin/helm` (v3.x for template validation)
- **Kubectl**: `/usr/local/bin/kubectl` (for dry-run schema validation)
- **Python 3**: `/usr/bin/python3` (v3.12 with PyYAML, pytest, and analysis tools)
- **Docker**: `/usr/bin/docker`

---

## 6. Extension Plan

1. Preserve all existing `basic/`, `advanced/`, `reports/`, and legacy scripts unchanged to ensure backward compatibility with the existing benchmark.
2. Build the self-contained ground-truth test corpus under `iac-tests/<iac-type>/<category>/<case-id>/`.
3. Provide metadata `case.yaml` for each test case documenting its label (`TRUE_POSITIVE`, `EVASIVE_MISCONFIG`, `SAFE_LOOKALIKE`), category, description, failure mechanics, expected findings, and compliance frameworks.
4. Generate the master `iac-tests/GROUND_TRUTH.csv` catalog.
5. Create automated test runners and evaluators in `scripts/run_scan.sh` and `scripts/score.py` to benchmark scanners like Checkov and Trivy and generate `reports/gap-report.md`.


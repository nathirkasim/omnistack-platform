# IaC Security Scanner Evaluation & Gap Analysis Report

**Scanner Output File**: `reports/checkov_scan.json`  
**Ground Truth Corpus Size**: 89 test cases across 19 IaC types  

## 1. Executive Summary

| Metric | Value | Description |
| :--- | :--- | :--- |
| **True Positives (TP)** | `46` | Correctly identified misconfigurations & evasions |
| **False Positives (FP)** | `17` | Benign / mitigated safe lookalikes wrongly flagged |
| **False Negatives (FN)** | `15` | Missed vulnerabilities & evasion bypasses |
| **True Negatives (TN)** | `11` | Benign patterns correctly passed without alarms |
| **Precision** | `73.02%` | Proportion of alerted issues that were real risks |
| **Recall (Coverage)** | `75.41%` | Proportion of real misconfigurations detected |
| **F1 Score** | `74.19%` | Harmonic balance between Precision and Recall |

## 2. Performance by Infrastructure-as-Code (IaC) Type

| IaC Type | TP | FP | FN | TN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `ansible` | 1 | 0 | 1 | 1 | 100.0% | 50.0% | 66.7% |
| `argocd-flux` | 0 | 0 | 2 | 0 | 0.0% | 0.0% | 0.0% |
| `azure-pipelines` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `bicep-arm` | 2 | 0 | 1 | 0 | 100.0% | 66.7% | 80.0% |
| `cdk` | 1 | 1 | 0 | 0 | 50.0% | 100.0% | 66.7% |
| `cloudbuild` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `cloudformation` | 5 | 1 | 0 | 0 | 83.3% | 100.0% | 90.9% |
| `crossplane` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `docker-compose` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |
| `dockerfile` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `github-actions` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |
| `gitlab-ci` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `helm` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `kubernetes` | 5 | 1 | 1 | 1 | 83.3% | 83.3% | 83.3% |
| `kustomize` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `packer` | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |
| `serverless` | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |
| `terraform` | 24 | 11 | 0 | 0 | 68.6% | 100.0% | 81.4% |
| `terragrunt` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |

## 3. Performance by Scenario Category

| Category | TP | FP | FN | TN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `ci-cd` | 0 | 0 | 5 | 4 | 0.0% | 0.0% | 0.0% |
| `configuration-management` | 1 | 0 | 1 | 2 | 100.0% | 50.0% | 66.7% |
| `container-images` | 2 | 1 | 2 | 1 | 66.7% | 50.0% | 57.1% |
| `datastores` | 4 | 3 | 2 | 2 | 57.1% | 66.7% | 61.5% |
| `dynamic-constructs` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `helm-kustomize` | 4 | 2 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `kubernetes-security` | 5 | 1 | 3 | 1 | 83.3% | 62.5% | 71.4% |
| `modules` | 3 | 1 | 0 | 0 | 75.0% | 100.0% | 85.7% |
| `multicloud-azure-gcp` | 4 | 1 | 1 | 0 | 80.0% | 80.0% | 80.0% |
| `network` | 4 | 1 | 0 | 1 | 80.0% | 100.0% | 88.9% |
| `parser-evasion` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `policy-encoding` | 6 | 1 | 0 | 0 | 85.7% | 100.0% | 92.3% |
| `runtime-drift` | 1 | 1 | 0 | 0 | 50.0% | 100.0% | 66.7% |
| `secrets` | 4 | 1 | 0 | 0 | 80.0% | 100.0% | 88.9% |
| `split-resources` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `variables-indirection` | 2 | 1 | 1 | 0 | 66.7% | 66.7% | 66.7% |

## 4. Missed Vulnerabilities & Scanner Blind Spots (False Negatives)

These test cases represent genuine security vulnerabilities that the scanner failed to detect.

| Case ID | IaC Type | Category | Severity | Description | Why Scanner Failed |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `K8S-RBAC-002` | `kubernetes` | `kubernetes-security` | **HIGH** | ClusterRole disguised as monitoring agent granting create on pods/exec and get/list on secrets (stealthy privilege escalation) | Scanners searching exclusively for wildcard verbs ['*'] miss specific high-risk RBAC capabilities like pods/exec and secrets extraction. |
| `COMPOSE-001` | `docker-compose` | `container-images` | **CRITICAL** | docker-compose service configured with privileged: true and docker socket mount | Baseline docker-compose security test case. |
| `COMPOSE-002` | `docker-compose` | `container-images` | **HIGH** | docker-compose service escapes isolation via network_mode: host and pid: host without using 'privileged: true' | Scanners that look exclusively for privileged: true fail to detect host network and process namespace sharing. |
| `GHA-001` | `github-actions` | `ci-cd` | **CRITICAL** | GitHub Actions workflow triggers on pull_request_target and checks out untrusted PR head commit (critical RCE / token theft) | Baseline GitHub Actions vulnerability; pull_request_target with checkout of fork code runs with target repo secrets. |
| `GHA-002` | `github-actions` | `ci-cd` | **CRITICAL** | Script injection via ${{ github.event.issue.title }} embedded directly in bash run block | Scanners that do not parse bash syntax inside run blocks fail to recognize that user-controlled GitHub context strings result in command injection. |
| `GL-CI-001` | `gitlab-ci` | `ci-cd` | **CRITICAL** | GitLab CI pipeline executing Docker-in-Docker with privileged flag and logging CI tokens | Baseline GitLab CI misconfiguration. |
| `AZ-PIP-001` | `azure-pipelines` | `ci-cd` | **HIGH** | Azure DevOps pipeline disables workspace clean and executes arbitrary command from unvalidated parameter | Baseline Azure Pipelines security test case. |
| `CLOUDBUILD-001` | `cloudbuild` | `ci-cd` | **HIGH** | Google Cloud Build running unpinned third-party builder with root privileges and token exposure | Baseline Cloud Build misconfiguration. |
| `TG-001` | `terragrunt` | `datastores` | **HIGH** | Terragrunt configuration explicitly passing storage_encrypted = false to remote RDS module | Baseline Terragrunt test case; scanner must parse terragrunt.hcl inputs. |
| `TG-002` | `terragrunt` | `variables-indirection` | **HIGH** | Terragrunt child configuration inherits from parent root.hcl but overrides safe bucket ACL with public-read | Scanners that do not follow include { path = find_in_parent_folders() } fail to resolve the merged inputs between parent and child configs. |
| `ANS-001` | `ansible` | `configuration-management` | **CRITICAL** | Ansible playbook executes shell command with plaintext password | Baseline Ansible misconfiguration; hardcoded credentials in command task. |
| `AZ-ARM-001` | `bicep-arm` | `multicloud-azure-gcp` | **HIGH** | Azure Resource Manager (ARM) JSON template creating SQL server firewall rule opening access to 0.0.0.0 | Baseline ARM JSON firewall rule test case. |
| `ARGO-001` | `argocd-flux` | `kubernetes-security` | **HIGH** | ArgoCD Application CRD syncing unpinned HEAD from public repo with automated selfHeal | Baseline GitOps ArgoCD misconfiguration; targetRevision HEAD allows untrusted mutable commits to be deployed automatically. |
| `FLUX-001` | `argocd-flux` | `kubernetes-security` | **CRITICAL** | Flux Kustomization CRD impersonating a privileged cluster-admin service account | Scanners inspecting Flux CRDs fail to verify serviceAccountName bindings against cluster RBAC permissions. |
| `XP-001` | `crossplane` | `datastores` | **HIGH** | Crossplane AWS S3 Bucket custom resource defining public-read ACL and deletionPolicy: Delete | Baseline Crossplane custom resource definition misconfiguration. |

## 5. False Alarms & Benign Idioms Flagged (False Positives)

These cases represent secure architectures, mitigated risks, or legitimate skips wrongly flagged by the scanner.

| Case ID | IaC Type | Category | Description | Triggered Rules |
| :--- | :--- | :--- | :--- | :--- |
| `TF-VAR-003` | `terraform` | `variables-indirection` | Variable default contains 'public-read' but ternary expression resolves to 'private' when is_prod is true | `CKV_AWS_144`, `CKV_AWS_21`, `CKV2_AWS_62`, `CKV2_AWS_61`, `CKV_AWS_18`, `CKV2_AWS_6`, `CKV_AWS_145` |
| `TF-DYN-003` | `terraform` | `dynamic-constructs` | Insecure resource defined with count = 0 (never deployed) | `CKV_AWS_144`, `CKV_AWS_20`, `CKV2_AWS_62`, `CKV_AWS_21`, `CKV2_AWS_61`, `CKV_AWS_18`, `CKV2_AWS_6`, `CKV_AWS_145` |
| `TF-MOD-003` | `terraform` | `modules` | Module definition defaults to storage_encrypted = false but root caller overrides it to true | `CKV_AWS_293`, `CKV_AWS_129`, `CKV_AWS_226`, `CKV2_AWS_60`, `CKV_AWS_353`, `CKV_AWS_118`, `CKV_AWS_161`, `CKV2_AWS_30`, `CKV_AWS_157` |
| `TF-SPLIT-003` | `terraform` | `split-resources` | S3 bucket declared in s3.tf without inline encryption block, but server-side encryption is attached in encryption.tf and public access block is attached in access.tf (AWS Provider v4+ standard architecture) | `CKV_AWS_144`, `CKV_AWS_21`, `CKV2_AWS_62`, `CKV2_AWS_61`, `CKV_AWS_18`, `CKV_AWS_145` |
| `TF-POL-003` | `terraform` | `policy-encoding` | S3 bucket policy uses Action = 's3:*' and Resource = '*' but contains Condition key aws:PrincipalOrgID and aws:SecureTransport neutralizing public risk | `CKV_AWS_144`, `CKV_AWS_21`, `CKV2_AWS_62`, `CKV2_AWS_61`, `CKV_AWS_18`, `CKV2_AWS_6`, `CKV_AWS_145` |
| `TF-NET-003` | `terraform` | `network` | Security group ingress allows 0.0.0.0/0 on port 443 for public ALB with modern TLS 1.3 policy | `CKV_AWS_23`, `CKV2_AWS_5` |
| `TF-DATA-003` | `terraform` | `datastores` | DynamoDB table without explicit server_side_encryption block (AWS encrypts DynamoDB by default with AWS KMS owned key) | `CKV_AWS_28`, `CKV_AWS_119` |
| `TF-SEC-003` | `terraform` | `secrets` | High-entropy SHA-256 hash and non-secret placeholder token | `CKV2_AWS_34` |
| `TF-PARSE-003` | `terraform` | `parser-evasion` | Legitimate, properly documented Checkov suppression for intentional public static website bucket | `CKV_AWS_144`, `CKV_AWS_20`, `CKV2_AWS_62`, `CKV_AWS_21`, `CKV2_AWS_61`, `CKV_AWS_18`, `CKV2_AWS_6`, `CKV_AWS_145` |
| `TF-DRIFT-002` | `terraform` | `runtime-drift` | Security group referencing computed output from external workspace data.terraform_remote_state | `CKV_AWS_23`, `CKV2_AWS_5` |
| `GCP-TF-003` | `terraform` | `multicloud-azure-gcp` | GCP Storage bucket with uniform_bucket_level_access enabled and IAM binding restricted to authorized service account | `CKV_GCP_114`, `CKV_GCP_62`, `CKV_GCP_78` |
| `K8S-SEC-003` | `kubernetes` | `kubernetes-security` | Fully hardened Pod with readOnlyRootFilesystem, dropped capabilities, no privilege escalation, and non-root execution | `CKV_K8S_8`, `CKV_K8S_9`, `CKV2_K8S_6` |
| `CFN-YAML-003` | `cloudformation` | `datastores` | CloudFormation S3 Bucket fully hardened with ServerSideEncryptionRule and PublicAccessBlockConfiguration | `CKV_AWS_21`, `CKV_AWS_18` |
| `DOCKER-003` | `dockerfile` | `container-images` | Fully hardened Dockerfile with pinned SHA256 digest, non-root user UID 65532, and COPY --chown | `CKV_DOCKER_2` |
| `HELM-003` | `helm` | `helm-kustomize` | Helm chart delegates container securityContext to a shared named template helper in _helpers.tpl that enforces full hardening | `CKV_K8S_10`, `CKV_K8S_31`, `CKV_K8S_15`, `CKV_K8S_8`, `CKV_K8S_13`, `CKV_K8S_21`, `CKV_K8S_9`, `CKV_K8S_12`, `CKV_K8S_43`, `CKV2_K8S_6`, `CKV_K8S_29`, `CKV_K8S_11`, `CKV_K8S_38` |
| `KUST-003` | `kustomize` | `helm-kustomize` | Base deployment is missing securityContext, but dev overlay strategic merge patch injects complete hardening | `CKV_K8S_31`, `CKV_K8S_8`, `CKV_K8S_28`, `CKV2_K8S_6`, `CKV_K8S_43`, `CKV_K8S_14`, `CKV_K8S_22`, `CKV_K8S_38`, `CKV_K8S_29`, `CKV_K8S_37`, `CKV_K8S_10`, `CKV_K8S_13`, `CKV_K8S_21`, `CKV_K8S_23`, `CKV_K8S_20`, `CKV_K8S_40`, `CKV_K8S_11`, `CKV_K8S_15`, `CKV_K8S_9`, `CKV_K8S_12`, `CKV_K8S_30` |
| `CDK-002` | `cdk` | `datastores` | AWS CDK synthesized stack with KMS managed server-side encryption and strict block public access | `CKV_AWS_21`, `CKV_AWS_18` |

## 6. Recommendations for Scanner Improvement

1. **Implement Inter-File Context & Variable Resolution**: Resolve `.tfvars`, `locals`, and input variables rather than relying solely on default values or single-file scopes.
2. **Evaluate Intrinsic & Built-in Functions**: Expand CloudFormation `Fn::Sub`, `Fn::FindInMap`, and Terraform functions (`lookup`, `cidrsubnet`, `merge`, `coalesce`).
3. **Context-Aware Policy Checking**: Inspect IAM Condition keys (`aws:PrincipalOrgID`, `aws:SecureTransport`) before raising alerts on wildcard actions.
4. **Multi-Document & Deep Hierarchy Support**: Ensure parsers do not terminate on the first YAML document in multi-doc streams, and trace nested module calls 3+ levels deep.
5. **Understand Provider Evolution**: Support separate split resources (`aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`) in AWS Provider v4+ to prevent false positives.
# IaC Security Scanner Evaluation & Gap Analysis Report

**Scanner Output File**: `reports/trivy_scan.json`  
**Ground Truth Corpus Size**: 89 test cases across 19 IaC types  

## 1. Executive Summary

| Metric | Value | Description |
| :--- | :--- | :--- |
| **True Positives (TP)** | `37` | Correctly identified misconfigurations & evasions |
| **False Positives (FP)** | `15` | Benign / mitigated safe lookalikes wrongly flagged |
| **False Negatives (FN)** | `24` | Missed vulnerabilities & evasion bypasses |
| **True Negatives (TN)** | `13` | Benign patterns correctly passed without alarms |
| **Precision** | `71.15%` | Proportion of alerted issues that were real risks |
| **Recall (Coverage)** | `60.66%` | Proportion of real misconfigurations detected |
| **F1 Score** | `65.49%` | Harmonic balance between Precision and Recall |

## 2. Performance by Infrastructure-as-Code (IaC) Type

| IaC Type | TP | FP | FN | TN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `ansible` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |
| `argocd-flux` | 0 | 0 | 2 | 0 | 0.0% | 0.0% | 0.0% |
| `azure-pipelines` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `bicep-arm` | 0 | 0 | 3 | 0 | 0.0% | 0.0% | 0.0% |
| `cdk` | 1 | 1 | 0 | 0 | 50.0% | 100.0% | 66.7% |
| `cloudbuild` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `cloudformation` | 4 | 1 | 1 | 0 | 80.0% | 80.0% | 80.0% |
| `crossplane` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `docker-compose` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |
| `dockerfile` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `github-actions` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |
| `gitlab-ci` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `helm` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `kubernetes` | 5 | 1 | 1 | 1 | 83.3% | 83.3% | 83.3% |
| `kustomize` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `packer` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `serverless` | 0 | 0 | 1 | 1 | 0.0% | 0.0% | 0.0% |
| `terraform` | 21 | 9 | 3 | 2 | 70.0% | 87.5% | 77.8% |
| `terragrunt` | 0 | 0 | 2 | 1 | 0.0% | 0.0% | 0.0% |

## 3. Performance by Scenario Category

| Category | TP | FP | FN | TN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `ci-cd` | 0 | 0 | 5 | 4 | 0.0% | 0.0% | 0.0% |
| `configuration-management` | 0 | 0 | 2 | 2 | 0.0% | 0.0% | 0.0% |
| `container-images` | 2 | 1 | 2 | 1 | 66.7% | 50.0% | 57.1% |
| `datastores` | 4 | 3 | 2 | 2 | 57.1% | 66.7% | 61.5% |
| `dynamic-constructs` | 2 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |
| `helm-kustomize` | 4 | 2 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `kubernetes-security` | 5 | 1 | 3 | 1 | 83.3% | 62.5% | 71.4% |
| `modules` | 3 | 1 | 0 | 0 | 75.0% | 100.0% | 85.7% |
| `multicloud-azure-gcp` | 2 | 1 | 3 | 0 | 66.7% | 40.0% | 50.0% |
| `network` | 4 | 1 | 0 | 1 | 80.0% | 100.0% | 88.9% |
| `parser-evasion` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `policy-encoding` | 2 | 1 | 4 | 0 | 66.7% | 33.3% | 44.4% |
| `runtime-drift` | 1 | 1 | 0 | 0 | 50.0% | 100.0% | 66.7% |
| `secrets` | 2 | 0 | 2 | 1 | 100.0% | 50.0% | 66.7% |
| `split-resources` | 2 | 1 | 0 | 0 | 66.7% | 100.0% | 80.0% |
| `variables-indirection` | 2 | 1 | 1 | 0 | 66.7% | 66.7% | 66.7% |

## 4. Missed Vulnerabilities & Scanner Blind Spots (False Negatives)

These test cases represent genuine security vulnerabilities that the scanner failed to detect.

| Case ID | IaC Type | Category | Severity | Description | Why Scanner Failed |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `TF-POL-001` | `terraform` | `policy-encoding` | **CRITICAL** | IAM policy granting Action = '*' and Resource = '*' using jsonencode | Baseline IAM wildcard detection; all policy checkers should detect star permissions. |
| `TF-SEC-002` | `terraform` | `secrets` | **CRITICAL** | AWS access key split into concatenated locals to evade regex token scanners | Regex scanners matching 'AKIA[0-9A-Z]{16}' fail to detect tokens split into smaller string fragments concatenated via HCL interpolation. |
| `TF-POL-004` | `terraform` | `policy-encoding` | **CRITICAL** | IAM AssumeRole trust policy granting sts:AssumeRole to Principal '*' without ExternalId (confused deputy vulnerability) | Scanners that only check aws_iam_policy and ignore assume_role_policy inside aws_iam_role fail to detect world-assumable roles. |
| `K8S-SEC-005` | `kubernetes` | `kubernetes-security` | **CRITICAL** | YAML anchor definition (&base_sec) has safe settings but subsequent key override sets privileged: true after the alias | Scanners that parse YAML anchors with simple shallow replacement may only inspect the anchor definition and miss the overridden property. |
| `CFN-JSON-001` | `cloudformation` | `policy-encoding` | **CRITICAL** | CloudFormation JSON template creating IAM Policy with Action = '*' and Resource = '*' | Baseline CloudFormation JSON syntax test case. |
| `COMPOSE-001` | `docker-compose` | `container-images` | **CRITICAL** | docker-compose service configured with privileged: true and docker socket mount | Baseline docker-compose security test case. |
| `COMPOSE-002` | `docker-compose` | `container-images` | **HIGH** | docker-compose service escapes isolation via network_mode: host and pid: host without using 'privileged: true' | Scanners that look exclusively for privileged: true fail to detect host network and process namespace sharing. |
| `GHA-001` | `github-actions` | `ci-cd` | **CRITICAL** | GitHub Actions workflow triggers on pull_request_target and checks out untrusted PR head commit (critical RCE / token theft) | Baseline GitHub Actions vulnerability; pull_request_target with checkout of fork code runs with target repo secrets. |
| `GHA-002` | `github-actions` | `ci-cd` | **CRITICAL** | Script injection via ${{ github.event.issue.title }} embedded directly in bash run block | Scanners that do not parse bash syntax inside run blocks fail to recognize that user-controlled GitHub context strings result in command injection. |
| `GL-CI-001` | `gitlab-ci` | `ci-cd` | **CRITICAL** | GitLab CI pipeline executing Docker-in-Docker with privileged flag and logging CI tokens | Baseline GitLab CI misconfiguration. |
| `AZ-PIP-001` | `azure-pipelines` | `ci-cd` | **HIGH** | Azure DevOps pipeline disables workspace clean and executes arbitrary command from unvalidated parameter | Baseline Azure Pipelines security test case. |
| `CLOUDBUILD-001` | `cloudbuild` | `ci-cd` | **HIGH** | Google Cloud Build running unpinned third-party builder with root privileges and token exposure | Baseline Cloud Build misconfiguration. |
| `TG-001` | `terragrunt` | `datastores` | **HIGH** | Terragrunt configuration explicitly passing storage_encrypted = false to remote RDS module | Baseline Terragrunt test case; scanner must parse terragrunt.hcl inputs. |
| `TG-002` | `terragrunt` | `variables-indirection` | **HIGH** | Terragrunt child configuration inherits from parent root.hcl but overrides safe bucket ACL with public-read | Scanners that do not follow include { path = find_in_parent_folders() } fail to resolve the merged inputs between parent and child configs. |
| `SLS-001` | `serverless` | `policy-encoding` | **CRITICAL** | Serverless Framework serverless.yml granting wildcard IAM permissions Action = '*' and Resource = '*' | Baseline Serverless Framework security check. |
| `ANS-001` | `ansible` | `configuration-management` | **CRITICAL** | Ansible playbook executes shell command with plaintext password | Baseline Ansible misconfiguration; hardcoded credentials in command task. |
| `ANS-002` | `ansible` | `configuration-management` | **HIGH** | Ansible uri task disables TLS certificate validation with validate_certs: false | Scanners that do not inspect task parameters like validate_certs miss MITM vulnerability. |
| `PACKER-001` | `packer` | `secrets` | **CRITICAL** | Packer HCL2 template containing hardcoded synthetic AWS secret key | Baseline Packer credential detection. |
| `AZ-BICEP-001` | `bicep-arm` | `multicloud-azure-gcp` | **HIGH** | Azure Bicep template creating Storage Account with allowBlobPublicAccess: true and minimumTlsVersion: TLS1_0 | Baseline Azure Bicep security test case. |
| `AZ-BICEP-002` | `bicep-arm` | `multicloud-azure-gcp` | **CRITICAL** | Azure Bicep Network Security Group rule allowing all inbound traffic from source wildcard '*' to port range '*' | Scanners that do not parse Bicep child securityRules sub-properties miss unrestricted internet access. |
| `AZ-ARM-001` | `bicep-arm` | `multicloud-azure-gcp` | **HIGH** | Azure Resource Manager (ARM) JSON template creating SQL server firewall rule opening access to 0.0.0.0 | Baseline ARM JSON firewall rule test case. |
| `ARGO-001` | `argocd-flux` | `kubernetes-security` | **HIGH** | ArgoCD Application CRD syncing unpinned HEAD from public repo with automated selfHeal | Baseline GitOps ArgoCD misconfiguration; targetRevision HEAD allows untrusted mutable commits to be deployed automatically. |
| `FLUX-001` | `argocd-flux` | `kubernetes-security` | **CRITICAL** | Flux Kustomization CRD impersonating a privileged cluster-admin service account | Scanners inspecting Flux CRDs fail to verify serviceAccountName bindings against cluster RBAC permissions. |
| `XP-001` | `crossplane` | `datastores` | **HIGH** | Crossplane AWS S3 Bucket custom resource defining public-read ACL and deletionPolicy: Delete | Baseline Crossplane custom resource definition misconfiguration. |

## 5. False Alarms & Benign Idioms Flagged (False Positives)

These cases represent secure architectures, mitigated risks, or legitimate skips wrongly flagged by the scanner.

| Case ID | IaC Type | Category | Description | Triggered Rules |
| :--- | :--- | :--- | :--- | :--- |
| `TF-VAR-003` | `terraform` | `variables-indirection` | Variable default contains 'public-read' but ternary expression resolves to 'private' when is_prod is true | `AWS-0132`, `AWS-0089`, `AWS-0090`, `AWS-0093`, `AWS-0087`, `AWS-0086`, `AWS-0091`, `AWS-0094` |
| `TF-MOD-003` | `terraform` | `modules` | Module definition defaults to storage_encrypted = false but root caller overrides it to true | `AWS-0176`, `AWS-0177`, `AWS-0133`, `AWS-0077` |
| `TF-SPLIT-003` | `terraform` | `split-resources` | S3 bucket declared in s3.tf without inline encryption block, but server-side encryption is attached in encryption.tf and public access block is attached in access.tf (AWS Provider v4+ standard architecture) | `AWS-0132`, `AWS-0090`, `AWS-0089` |
| `TF-POL-003` | `terraform` | `policy-encoding` | S3 bucket policy uses Action = 's3:*' and Resource = '*' but contains Condition key aws:PrincipalOrgID and aws:SecureTransport neutralizing public risk | `AWS-0132`, `AWS-0089`, `AWS-0090`, `AWS-0093`, `AWS-0087`, `AWS-0086`, `AWS-0091`, `AWS-0094` |
| `TF-NET-003` | `terraform` | `network` | Security group ingress allows 0.0.0.0/0 on port 443 for public ALB with modern TLS 1.3 policy | `AWS-0124` |
| `TF-DATA-003` | `terraform` | `datastores` | DynamoDB table without explicit server_side_encryption block (AWS encrypts DynamoDB by default with AWS KMS owned key) | `AWS-0025`, `AWS-0024` |
| `TF-PARSE-003` | `terraform` | `parser-evasion` | Legitimate, properly documented Checkov suppression for intentional public static website bucket | `AWS-0132`, `AWS-0092`, `AWS-0089`, `AWS-0090`, `AWS-0093`, `AWS-0087`, `AWS-0086`, `AWS-0091`, `AWS-0094` |
| `TF-DRIFT-002` | `terraform` | `runtime-drift` | Security group referencing computed output from external workspace data.terraform_remote_state | `AWS-0124` |
| `GCP-TF-003` | `terraform` | `multicloud-azure-gcp` | GCP Storage bucket with uniform_bucket_level_access enabled and IAM binding restricted to authorized service account | `GCP-0066`, `GCP-0078`, `GCP-0077` |
| `K8S-SEC-003` | `kubernetes` | `kubernetes-security` | Fully hardened Pod with readOnlyRootFilesystem, dropped capabilities, no privilege escalation, and non-root execution | `KSV-0125` |
| `CFN-YAML-003` | `cloudformation` | `datastores` | CloudFormation S3 Bucket fully hardened with ServerSideEncryptionRule and PublicAccessBlockConfiguration | `AWS-0090`, `AWS-0132`, `AWS-0089` |
| `DOCKER-003` | `dockerfile` | `container-images` | Fully hardened Dockerfile with pinned SHA256 digest, non-root user UID 65532, and COPY --chown | `DS-0026` |
| `HELM-003` | `helm` | `helm-kustomize` | Helm chart delegates container securityContext to a shared named template helper in _helpers.tpl that enforces full hardening | `KSV-0015`, `KSV-0104`, `KSV-0018`, `KSV-0030`, `KSV-0110`, `KSV-0021`, `KSV-0011`, `KSV-0118`, `KSV-0016` |
| `KUST-003` | `kustomize` | `helm-kustomize` | Base deployment is missing securityContext, but dev overlay strategic merge patch injects complete hardening | `KSV-0015`, `KSV-0106`, `KSV-0001`, `KSV-0014`, `KSV-0018`, `KSV-0030`, `KSV-0104`, `KSV-0003`, `KSV-0110`, `KSV-0011`, `KSV-0004`, `KSV-0021`, `KSV-0118`, `KSV-0016`, `KSV-0020`, `KSV-0012` |
| `CDK-002` | `cdk` | `datastores` | AWS CDK synthesized stack with KMS managed server-side encryption and strict block public access | `AWS-0090`, `AWS-0132`, `AWS-0089` |

## 6. Recommendations for Scanner Improvement

1. **Implement Inter-File Context & Variable Resolution**: Resolve `.tfvars`, `locals`, and input variables rather than relying solely on default values or single-file scopes.
2. **Evaluate Intrinsic & Built-in Functions**: Expand CloudFormation `Fn::Sub`, `Fn::FindInMap`, and Terraform functions (`lookup`, `cidrsubnet`, `merge`, `coalesce`).
3. **Context-Aware Policy Checking**: Inspect IAM Condition keys (`aws:PrincipalOrgID`, `aws:SecureTransport`) before raising alerts on wildcard actions.
4. **Multi-Document & Deep Hierarchy Support**: Ensure parsers do not terminate on the first YAML document in multi-doc streams, and trace nested module calls 3+ levels deep.
5. **Understand Provider Evolution**: Support separate split resources (`aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`) in AWS Provider v4+ to prevent false positives.
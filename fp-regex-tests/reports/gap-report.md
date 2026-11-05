# Regex & Pattern Security Scanner Benchmark Report

- **Evaluated Report**: `checkov_results.json`
- **Total Target Scenarios**: 409
- **Total Scanner Findings**: 647

## 1. Executive Summary

| Metric | Count | Ratio |
| :--- | :--- | :--- |
| **True Positives (Caught Issues)** | 21 | Recall: 13.9% |
| **False Negatives (Missed Vulnerabilities)** | 130 | Miss Rate: 86.1% |
| **True Negatives (Correctly Ignored Lookalikes)** | 229 | Specificity: 95.0% |
| **False Positive Candidates (Flagged Lookalikes)** | 12 | Precision: 63.6% |
| **Debatable Hits (Policy / Sample Keys)** | 1 | (Isolated from FP/FN) |
| **Unexpected Other Findings** | 605 | (Requires manual triage) |

## 2. Accuracy by Complexity Level

| Level | Targets | TP | FN | TN | FP | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `L1_BASIC` | 174 | 12 | 67 | 91 | 4 | 75.0% | 15.2% |
| `L2_INTERMEDIATE` | 112 | 4 | 28 | 77 | 3 | 57.1% | 12.5% |
| `L3_ADVANCED` | 106 | 5 | 35 | 61 | 5 | 50.0% | 12.5% |

## 3. Accuracy by Scenario Family

| Family | Targets | TP | FN | TN | FP | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CFN` | 23 | 0 | 8 | 14 | 1 | 0.0% | 0.0% |
| `CI` | 32 | 6 | 6 | 19 | 1 | 85.7% | 50.0% |
| `DOCKER` | 35 | 10 | 6 | 12 | 7 | 58.8% | 62.5% |
| `K8S` | 49 | 0 | 20 | 29 | 0 | 0.0% | 0.0% |
| `ROBUSTNESS` | 36 | 1 | 9 | 26 | 0 | 100.0% | 10.0% |
| `SAST` | 77 | 0 | 36 | 41 | 0 | 0.0% | 0.0% |
| `SECRETS` | 91 | 2 | 27 | 60 | 2 | 50.0% | 6.9% |
| `TERRAFORM` | 49 | 2 | 18 | 28 | 1 | 66.7% | 10.0% |

## 4. Accuracy by Language / File Format

| Extension / Format | Targets | TP | FN | TN | FP | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `.Dockerfile` | 17 | 6 | 1 | 5 | 5 | 54.5% | 85.7% |
| `.conf` | 2 | 0 | 1 | 1 | 0 | 0.0% | 0.0% |
| `.env` | 8 | 0 | 2 | 6 | 0 | 0.0% | 0.0% |
| `.env.local` | 1 | 0 | 1 | 0 | 0 | 0.0% | 0.0% |
| `.go` | 11 | 0 | 6 | 5 | 0 | 0.0% | 0.0% |
| `.java` | 4 | 0 | 2 | 2 | 0 | 0.0% | 0.0% |
| `.js` | 30 | 0 | 13 | 17 | 0 | 0.0% | 0.0% |
| `.json` | 2 | 0 | 1 | 1 | 0 | 0.0% | 0.0% |
| `.md` | 3 | 0 | 1 | 2 | 0 | 0.0% | 0.0% |
| `.pem` | 2 | 0 | 1 | 1 | 0 | 0.0% | 0.0% |
| `.php` | 4 | 0 | 2 | 2 | 0 | 0.0% | 0.0% |
| `.py` | 110 | 0 | 33 | 77 | 0 | 0.0% | 0.0% |
| `.sh` | 8 | 0 | 5 | 3 | 0 | 0.0% | 0.0% |
| `.tf` | 49 | 2 | 18 | 28 | 1 | 66.7% | 10.0% |
| `.tf.json` | 3 | 0 | 1 | 2 | 0 | 0.0% | 0.0% |
| `.xml` | 1 | 0 | 0 | 1 | 0 | 0.0% | 0.0% |
| `.yaml` | 79 | 3 | 28 | 45 | 3 | 50.0% | 9.7% |
| `.yml` | 44 | 9 | 10 | 24 | 1 | 90.0% | 47.4% |
| `Dockerfile` | 6 | 1 | 1 | 2 | 2 | 33.3% | 50.0% |
| `other` | 8 | 0 | 3 | 5 | 0 | 0.0% | 0.0% |

## 5. Top 20 FP-Prone Rules

| Rule ID | False Positive Hits |
| :--- | :--- |
| `CKV_DOCKER_1` | 4 |
| `CKV_DOCKER_3` | 3 |
| `CKV_DOCKER_2` | 3 |
| `CKV_SECRET_6` | 2 |
| `CKV_AWS_23` | 1 |
| `CKV_AWS_56` | 1 |
| `CKV_AWS_18` | 1 |
| `CKV_AWS_21` | 1 |
| `CKV_AWS_55` | 1 |
| `CKV_AWS_53` | 1 |
| `CKV_AWS_54` | 1 |
| `CKV_SECRET_4` | 1 |

## 6. Format-Robustness Verification

Testing parser invariance across syntax formatting, casing, line-endings, and comments.

| Test File | Target Scenario | Expect | Flagged | Status |
| :--- | :--- | :--- | :--- | :--- |
| `l2_intermediate/secrets/format_robustness.py:2` | `SEC-L2-018` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:3` | `SEC-L2-019` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:4` | `SEC-L2-020` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:5` | `SEC-L2-021` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:6` | `SEC-L2-022` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:7` | `SEC-L2-023` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/secrets/format_robustness.py:8` | `SEC-L2-024` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_secret_in_comment_debatable.py:2` | `ROB-001` | DEBATABLE | N | DEBATABLE_IGNORED |
| `l1_basic/robustness/rob_keyword_in_string_noflag.py:3` | `ROB-002` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_partial_match_noflag.py:1` | `ROB-003` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_partial_match_noflag.py:2` | `ROB-004` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_partial_match_noflag.py:3` | `ROB-005` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_mixed_crlf.py:2` | `ROB-006` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_utf8_neighbors.py:3` | `ROB-007` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_utf8_neighbors.py:4` | `ROB-008` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_bom_header.py:2` | `ROB-009` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_unusual_ext.env.local:2` | `ROB-010` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_service.conf:2` | `ROB-011` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_service.conf:3` | `ROB-012` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_markdown_docs.md:4` | `ROB-013` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_markdown_docs.md:5` | `ROB-014` | DEBATABLE | N | DEBATABLE_IGNORED |
| `l1_basic/robustness/rob_minified_bundle.js:1` | `ROB-015` | FLAG | N | FALSE_NEGATIVE |
| `l1_basic/robustness/rob_windows_paths.py:2` | `ROB-016` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_windows_paths.py:3` | `ROB-017` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_yaml_block_scalar.yaml:3` | `ROB-018` | NO_FLAG | N | TRUE_NEGATIVE |
| `l1_basic/robustness/rob_yaml_block_scalar.yaml:5` | `ROB-019` | FLAG | Y | TRUE_POSITIVE |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:4` | `ROB-L2-001` | DEBATABLE | N | DEBATABLE_IGNORED |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:5` | `ROB-L2-002` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:6` | `ROB-L2-003` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:7` | `ROB-L2-004` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:8` | `ROB-L2-005` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/robustness/multilingual_comments_and_strings.py:10` | `ROB-L2-006` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/unusual_formats.tf.json:10` | `ROB-L2-007` | FLAG | N | FALSE_NEGATIVE |
| `l2_intermediate/robustness/unusual_formats.tf.json:18` | `ROB-L2-008` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/unusual_formats.tf.json:25` | `ROB-L2-009` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:3` | `ROB-REP-001` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:4` | `ROB-REP-002` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:5` | `ROB-REP-003` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:6` | `ROB-REP-004` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:7` | `ROB-REP-005` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:8` | `ROB-REP-006` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:9` | `ROB-REP-007` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:10` | `ROB-REP-008` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:11` | `ROB-REP-009` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:12` | `ROB-REP-010` | NO_FLAG | N | TRUE_NEGATIVE |
| `l2_intermediate/robustness/repetition_stress.py:13` | `ROB-REP-099` | FLAG | N | FALSE_NEGATIVE |

## 7. Unexpected Other Findings (Manual Review Needed)

| File | Line | Rule ID | Message |
| :--- | :--- | :--- | :--- |
| `l1_basic/docker/docker_nonroot_user_noflag.Dockerfile` | 1 | `CKV_DOCKER_2` | Ensure that HEALTHCHECK instructions have been added to container images |
| `l2_intermediate/docker/backend.Dockerfile` | 1 | `CKV_DOCKER_2` | Ensure that HEALTHCHECK instructions have been added to container images |
| `l3_advanced/docker_build/Dockerfile` | 1 | `CKV_DOCKER_2` | Ensure that HEALTHCHECK instructions have been added to container images |
| `l1_basic/docker/docker_multistage_builder_root_noflag.Dockerfile` | 1 | `CKV_DOCKER_2` | Ensure that HEALTHCHECK instructions have been added to container images |
| `l1_basic/docker/docker_user_root_flag.Dockerfile` | 1 | `CKV_DOCKER_2` | Ensure that HEALTHCHECK instructions have been added to container images |
| `l2_intermediate/robustness/unusual_formats.tf.json` | 4 | `CKV_AWS_23` | Ensure every security group and rule has a description |
| `l2_intermediate/robustness/unusual_formats.tf.json` | 4 | `CKV_AWS_24` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |
| `l2_intermediate/robustness/unusual_formats.tf.json` | 12 | `CKV_AWS_23` | Ensure every security group and rule has a description |
| `l2_intermediate/robustness/unusual_formats.tf.json` | 22 | `CKV_AWS_189` | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_15` | Image Pull Policy should be Always |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_21` | The default namespace should not be used |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_12` | Memory requests should be set |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_23` | Minimize the admission of root containers |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_43` | Image should use digest |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_10` | CPU requests should be set |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_28` | Minimize the admission of containers with the NET_RAW capability |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_8` | Liveness Probe Should be Configured |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_9` | Readiness Probe Should be Configured |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_20` | Containers should not run with allowPrivilegeEscalation |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_22` | Use read-only filesystem for containers where possible |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_31` | Ensure that the seccomp profile is set to docker/default or runtime/default |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_40` | Containers should run as a high UID to avoid host conflict |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_38` | Ensure that Service Account Tokens are only mounted where necessary |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_29` | Apply security context to your pods and containers |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_11` | CPU limits should be set |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_16` | Container should not be privileged |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_14` | Image Tag should be fixed - not latest or blank |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_37` | Minimize the admission of containers with capabilities assigned |
| `l3_advanced/k8s_workload/deployment.yaml` | 1 | `CKV_K8S_13` | Memory limits should be set |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_30` | Apply security context to your containers |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_15` | Image Pull Policy should be Always |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_21` | The default namespace should not be used |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_12` | Memory requests should be set |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_35` | Prefer using secrets as files over secrets as environment variables |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_23` | Minimize the admission of root containers |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_43` | Image should use digest |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_10` | CPU requests should be set |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_28` | Minimize the admission of containers with the NET_RAW capability |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_8` | Liveness Probe Should be Configured |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_9` | Readiness Probe Should be Configured |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_20` | Containers should not run with allowPrivilegeEscalation |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_22` | Use read-only filesystem for containers where possible |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_31` | Ensure that the seccomp profile is set to docker/default or runtime/default |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_40` | Containers should run as a high UID to avoid host conflict |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_38` | Ensure that Service Account Tokens are only mounted where necessary |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_29` | Apply security context to your pods and containers |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_11` | CPU limits should be set |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_37` | Minimize the admission of containers with capabilities assigned |
| `l1_basic/k8s/k8s_secret_ref_noflag.yaml` | 1 | `CKV_K8S_13` | Memory limits should be set |
| `l1_basic/k8s/k8s_caps_flag.yaml` | 1 | `CKV_K8S_15` | Image Pull Policy should be Always |


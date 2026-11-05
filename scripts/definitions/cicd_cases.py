"""CI/CD pipelines test cases (GitHub Actions, GitLab CI, Azure Pipelines, Cloud Build)."""

CICD_CASES = [
    # ---------------------------------------------------------
    # GitHub Actions
    # ---------------------------------------------------------
    {
        "id": "GHA-001",
        "iac_type": "github-actions",
        "category": "ci-cd",
        "label": "TRUE_POSITIVE",
        "description": "GitHub Actions workflow triggers on pull_request_target and checks out untrusted PR head commit (critical RCE / token theft)",
        "why_scanner_may_fail": "Baseline GitHub Actions vulnerability; pull_request_target with checkout of fork code runs with target repo secrets.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_GHA_1",
                "cwe": "CWE-829",
                "cis": "CIS Software Supply Chain 1.0 - 2.1",
                "nist": "SA-11",
                "resource": "job.test",
                "file": "workflow.yml",
                "line": 8,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"],
        "undeliverable_static": False,
        "files": {
            "workflow.yml": """name: Untrusted PR Checkout
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR Head
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Run Build Script
        run: |
          npm install
          npm test
"""
        }
    },
    {
        "id": "GHA-002",
        "iac_type": "github-actions",
        "category": "ci-cd",
        "label": "EVASIVE_MISCONFIG",
        "description": "Script injection via ${{ github.event.issue.title }} embedded directly in bash run block",
        "why_scanner_may_fail": "Scanners that do not parse bash syntax inside run blocks fail to recognize that user-controlled GitHub context strings result in command injection.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_GHA_2",
                "cwe": "CWE-78",
                "cis": "CIS Software Supply Chain 1.0 - 2.2",
                "nist": "SI-10",
                "resource": "job.triage.step.echo",
                "file": "workflow.yml",
                "line": 12,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.2", "nist_800_53": "SI-10", "pci_dss": "6.5.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"],
        "undeliverable_static": False,
        "files": {
            "workflow.yml": """name: Issue Triage
on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Log Issue Title
        run: |
          echo "Processing issue: ${{ github.event.issue.title }}"
"""
        }
    },
    {
        "id": "GHA-003",
        "iac_type": "github-actions",
        "category": "ci-cd",
        "label": "SAFE_LOOKALIKE",
        "description": "GitHub context safely mapped to environment variable before usage in bash run script (safe idiom)",
        "why_scanner_may_fail": "Naive regex scanners matching '${{ github.event.* }}' without checking whether it is safely passed through an env: block trigger False Positives.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_GHA_2"],
        "compliance": {"cis": "2.2", "nist_800_53": "SI-10", "pci_dss": "6.5.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable"],
        "undeliverable_static": False,
        "files": {
            "workflow.yml": """name: Safe Issue Triage
on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Log Issue Safely
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: |
          echo "Processing issue safely: $ISSUE_TITLE"
"""
        }
    },

    # ---------------------------------------------------------
    # GitLab CI
    # ---------------------------------------------------------
    {
        "id": "GL-CI-001",
        "iac_type": "gitlab-ci",
        "category": "ci-cd",
        "label": "TRUE_POSITIVE",
        "description": "GitLab CI pipeline executing Docker-in-Docker with privileged flag and logging CI tokens",
        "why_scanner_may_fail": "Baseline GitLab CI misconfiguration.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_GL_1",
                "cwe": "CWE-250",
                "cis": "CIS Software Supply Chain 1.0 - 3.1",
                "nist": "AC-6",
                "resource": "job.build-job",
                "file": ".gitlab-ci.yml",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "3.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://docs.gitlab.com/ee/ci/docker/using_docker_build.html"],
        "undeliverable_static": False,
        "files": {
            ".gitlab-ci.yml": """image: docker:24.0.5

services:
  - name: docker:24.0.5-dind
    command: ["--privileged"]

build-job:
  stage: build
  script:
    - echo "Token: $CI_JOB_TOKEN"
    - docker build -t myapp .
"""
        }
    },
    {
        "id": "GL-CI-002",
        "iac_type": "gitlab-ci",
        "category": "ci-cd",
        "label": "SAFE_LOOKALIKE",
        "description": "GitLab CI pipeline using non-privileged runner with kaniko container build and scoped secrets",
        "why_scanner_may_fail": "Hardened GitLab CI build baseline; no findings should fire.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_GL_1"],
        "compliance": {"cis": "3.1", "nist_800_53": "AC-6", "pci_dss": "2.2.4", "soc2": "CC6.3"},
        "source_refs": ["https://docs.gitlab.com/ee/ci/docker/using_kaniko.html"],
        "undeliverable_static": False,
        "files": {
            ".gitlab-ci.yml": """build-kaniko:
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:v1.14.0-debug
    entrypoint: [""]
  script:
    - /kaniko/executor --context "${CI_PROJECT_DIR}" --dockerfile "${CI_PROJECT_DIR}/Dockerfile" --no-push
"""
        }
    },

    # ---------------------------------------------------------
    # Azure Pipelines
    # ---------------------------------------------------------
    {
        "id": "AZ-PIP-001",
        "iac_type": "azure-pipelines",
        "category": "ci-cd",
        "label": "TRUE_POSITIVE",
        "description": "Azure DevOps pipeline disables workspace clean and executes arbitrary command from unvalidated parameter",
        "why_scanner_may_fail": "Baseline Azure Pipelines security test case.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AZP_1",
                "cwe": "CWE-78",
                "cis": "CIS Software Supply Chain 1.0 - 4.1",
                "nist": "SA-11",
                "resource": "steps.bash",
                "file": "azure-pipelines.yml",
                "line": 8,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "4.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview"],
        "undeliverable_static": False,
        "files": {
            "azure-pipelines.yml": """trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - checkout: self
    clean: false
  - bash: |
      eval "$(Build.SourceVersionMessage)"
    displayName: 'Execute Commit Hook'
"""
        }
    },
    {
        "id": "AZ-PIP-002",
        "iac_type": "azure-pipelines",
        "category": "ci-cd",
        "label": "SAFE_LOOKALIKE",
        "description": "Hardened Azure DevOps pipeline with clean workspace and parameterized task execution",
        "why_scanner_may_fail": "Baseline safe Azure Pipelines definition.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AZP_1"],
        "compliance": {"cis": "4.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview"],
        "undeliverable_static": False,
        "files": {
            "azure-pipelines.yml": """trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - checkout: self
    clean: true
  - script: echo "Build starting..."
    displayName: 'Safe Build'
"""
        }
    },

    # ---------------------------------------------------------
    # Cloud Build
    # ---------------------------------------------------------
    {
        "id": "CLOUDBUILD-001",
        "iac_type": "cloudbuild",
        "category": "ci-cd",
        "label": "TRUE_POSITIVE",
        "description": "Google Cloud Build running unpinned third-party builder with root privileges and token exposure",
        "why_scanner_may_fail": "Baseline Cloud Build misconfiguration.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_GCB_1",
                "cwe": "CWE-829",
                "cis": "CIS GCP 1.3 - 5.1",
                "nist": "SA-11",
                "resource": "steps.unpinned-step",
                "file": "cloudbuild.yaml",
                "line": 1,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://cloud.google.com/build/docs/securing-builds/overview"],
        "undeliverable_static": False,
        "files": {
            "cloudbuild.yaml": """steps:
  - name: 'gcr.io/cloud-builders/npm:latest'
    entrypoint: 'bash'
    args:
      - '-c'
      - 'npm test'
"""
        }
    },
    {
        "id": "CLOUDBUILD-002",
        "iac_type": "cloudbuild",
        "category": "ci-cd",
        "label": "SAFE_LOOKALIKE",
        "description": "Hardened Google Cloud Build pipeline with sha256 pinned container image and non-root execution",
        "why_scanner_may_fail": "Hardened Google Cloud Build pipeline.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_GCB_1"],
        "compliance": {"cis": "5.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://cloud.google.com/build/docs/securing-builds/overview"],
        "undeliverable_static": False,
        "files": {
            "cloudbuild.yaml": """steps:
  - name: 'gcr.io/cloud-builders/npm@sha256:d8bb6aa16709a3dc5877f24032d84db8cc3bc5ab6ce6e5c8e235804aa3d56fcf'
    args: ['ci']
"""
        }
    }
]


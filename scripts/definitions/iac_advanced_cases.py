"""Advanced and specialized IaC test cases:
Terragrunt, CDK, Serverless, Ansible, Packer, Bicep/ARM, ArgoCD/Flux, Crossplane.
"""

IAC_ADVANCED_CASES = [
    # ---------------------------------------------------------
    # Terragrunt
    # ---------------------------------------------------------
    {
        "id": "TG-001",
        "iac_type": "terragrunt",
        "category": "datastores",
        "label": "TRUE_POSITIVE",
        "description": "Terragrunt configuration explicitly passing storage_encrypted = false to remote RDS module",
        "why_scanner_may_fail": "Baseline Terragrunt test case; scanner must parse terragrunt.hcl inputs.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_16",
                "cwe": "CWE-311",
                "cis": "CIS AWS 1.4 - 2.3.1",
                "nist": "SC-28",
                "resource": "inputs.storage_encrypted",
                "file": "terragrunt.hcl",
                "line": 5,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://terragrunt.gruntwork.io/docs/reference/config-blocks-and-attributes/#inputs"],
        "undeliverable_static": False,
        "files": {
            "terragrunt.hcl": """terraform {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-rds.git?ref=v6.0.0"
}

inputs = {
  identifier        = "corp-analytics-db"
  allocated_storage = 50
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = false
}
"""
        }
    },
    {
        "id": "TG-002",
        "iac_type": "terragrunt",
        "category": "variables-indirection",
        "label": "EVASIVE_MISCONFIG",
        "description": "Terragrunt child configuration inherits from parent root.hcl but overrides safe bucket ACL with public-read",
        "why_scanner_may_fail": "Scanners that do not follow include { path = find_in_parent_folders() } fail to resolve the merged inputs between parent and child configs.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_20",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3",
                "resource": "inputs.bucket_acl",
                "file": "app/terragrunt.hcl",
                "line": 5,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://terragrunt.gruntwork.io/docs/reference/config-blocks-and-attributes/#include"],
        "undeliverable_static": False,
        "files": {
            "root.hcl": """inputs = {
  bucket_acl = "private"
  tags = {
    ManagedBy = "Terragrunt"
  }
}
""",
            "app/terragrunt.hcl": """include "root" {
  path = find_in_parent_folders("root.hcl")
}

inputs = {
  bucket_name = "corp-public-assets"
  bucket_acl  = "public-read"
}
"""
        }
    },
    {
        "id": "TG-003",
        "iac_type": "terragrunt",
        "category": "datastores",
        "label": "SAFE_LOOKALIKE",
        "description": "Hardened Terragrunt configuration enforcing encryption and termination protection",
        "why_scanner_may_fail": "Baseline safe Terragrunt configuration.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_16"],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://terragrunt.gruntwork.io/"],
        "undeliverable_static": False,
        "files": {
            "terragrunt.hcl": """inputs = {
  identifier          = "corp-secure-db"
  allocated_storage   = 100
  storage_encrypted   = true
  deletion_protection = true
}
"""
        }
    },

    # ---------------------------------------------------------
    # AWS CDK / CDKTF / Pulumi
    # ---------------------------------------------------------
    {
        "id": "CDK-001",
        "iac_type": "cdk",
        "category": "datastores",
        "label": "TRUE_POSITIVE",
        "description": "AWS CDK synthesized CloudFormation template containing unencrypted S3 bucket with PublicRead access",
        "why_scanner_may_fail": "Baseline synthesized CDK CloudFormation artifact.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_20",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3",
                "resource": "AWS::S3::Bucket.CdkDataBucket",
                "file": "cdk.out/Stack.template.json",
                "line": 6,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.aws.amazon.com/cdk/v2/guide/home.html"],
        "undeliverable_static": False,
        "files": {
            "index.ts": """import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';

export class InsecureCdkStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    new s3.Bucket(this, 'CdkDataBucket', {
      accessControl: s3.BucketAccessControl.PUBLIC_READ,
    });
  }
}
""",
            "cdk.out/Stack.template.json": """{
  "Resources": {
    "CdkDataBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead"
      }
    }
  }
}
"""
        }
    },
    {
        "id": "CDK-002",
        "iac_type": "cdk",
        "category": "datastores",
        "label": "SAFE_LOOKALIKE",
        "description": "AWS CDK synthesized stack with KMS managed server-side encryption and strict block public access",
        "why_scanner_may_fail": "Safe CDK synthesized baseline.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_19", "CKV_AWS_20"],
        "compliance": {"cis": "2.1.1", "nist_800_53": "SC-13", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.aws.amazon.com/cdk/v2/guide/home.html"],
        "undeliverable_static": False,
        "files": {
            "cdk.out/Stack.template.json": """{
  "Resources": {
    "SecureCdkBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketEncryption": {
          "ServerSideEncryptionConfiguration": [
            {
              "ServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms"
              }
            }
          ]
        },
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": true,
          "BlockPublicPolicy": true,
          "IgnorePublicAcls": true,
          "RestrictPublicBuckets": true
        }
      }
    }
  }
}
"""
        }
    },

    # ---------------------------------------------------------
    # Serverless Framework
    # ---------------------------------------------------------
    {
        "id": "SLS-001",
        "iac_type": "serverless",
        "category": "policy-encoding",
        "label": "TRUE_POSITIVE",
        "description": "Serverless Framework serverless.yml granting wildcard IAM permissions Action = '*' and Resource = '*'",
        "why_scanner_may_fail": "Baseline Serverless Framework security check.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_1",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-6",
                "resource": "provider.iamRoleStatements",
                "file": "serverless.yml",
                "line": 9,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://www.serverless.com/framework/docs/providers/aws/guide/iam"],
        "undeliverable_static": False,
        "files": {
            "serverless.yml": """service: payment-service

provider:
  name: aws
  runtime: nodejs18.x
  region: us-east-1
  iamRoleStatements:
    - Effect: Allow
      Action: "*"
      Resource: "*"

functions:
  processPayment:
    handler: handler.process
"""
        }
    },
    {
        "id": "SLS-002",
        "iac_type": "serverless",
        "category": "network",
        "label": "SAFE_LOOKALIKE",
        "description": "Serverless Framework service using scoped IAM role and JWT authorizer on HTTP API endpoints",
        "why_scanner_may_fail": "Hardened serverless configuration baseline.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_1"],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://www.serverless.com/framework/docs/providers/aws/guide/http-api"],
        "undeliverable_static": False,
        "files": {
            "serverless.yml": """service: secure-service

provider:
  name: aws
  runtime: nodejs18.x
  region: us-east-1
  iamRoleStatements:
    - Effect: Allow
      Action:
        - dynamodb:GetItem
      Resource: "arn:aws:dynamodb:us-east-1:*:table/Users"

functions:
  getUser:
    handler: handler.get
"""
        }
    },

    # ---------------------------------------------------------
    # Ansible
    # ---------------------------------------------------------
    {
        "id": "ANS-001",
        "iac_type": "ansible",
        "category": "configuration-management",
        "label": "TRUE_POSITIVE",
        "description": "Ansible playbook executes shell command with plaintext password",
        "why_scanner_may_fail": "Baseline Ansible misconfiguration; hardcoded credentials in command task.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_ANSIBLE_1",
                "cwe": "CWE-798",
                "cis": "CIS Benchmark - 5.1",
                "nist": "IA-2",
                "resource": "task.reset_admin_password",
                "file": "playbook.yml",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html"],
        "undeliverable_static": False,
        "files": {
            "playbook.yml": """- name: System Configuration
  hosts: all
  tasks:
    - name: Reset admin user credentials
      ansible.builtin.shell: |
        echo "admin:SuperSecretPassword123!" | chpasswd
"""
        }
    },
    {
        "id": "ANS-002",
        "iac_type": "ansible",
        "category": "configuration-management",
        "label": "EVASIVE_MISCONFIG",
        "description": "Ansible uri task disables TLS certificate validation with validate_certs: false",
        "why_scanner_may_fail": "Scanners that do not inspect task parameters like validate_certs miss MITM vulnerability.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_ANSIBLE_2",
                "cwe": "CWE-295",
                "cis": "CIS Benchmark - 5.2",
                "nist": "SC-8",
                "resource": "task.download_payload",
                "file": "playbook.yml",
                "line": 6,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-8", "pci_dss": "4.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html"],
        "undeliverable_static": False,
        "files": {
            "playbook.yml": """- name: Deploy Secure Package
  hosts: all
  tasks:
    - name: Download configuration artifact
      ansible.builtin.uri:
        url: https://internal-repo.corp/config.tar.gz
        validate_certs: false
        dest: /tmp/config.tar.gz
"""
        }
    },
    {
        "id": "ANS-003",
        "iac_type": "ansible",
        "category": "configuration-management",
        "label": "SAFE_LOOKALIKE",
        "description": "Ansible task using no_log: true and secure file permissions mode: '0600'",
        "why_scanner_may_fail": "Hardened Ansible playbook baseline.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_ANSIBLE_1", "CKV_ANSIBLE_2"],
        "compliance": {"cis": "5.1", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#how-do-i-keep-secret-data-in-my-playbooks"],
        "undeliverable_static": False,
        "files": {
            "playbook.yml": """- name: Deploy Secure Key
  hosts: all
  tasks:
    - name: Deploy private certificate
      ansible.builtin.copy:
        dest: /etc/ssl/certs/service.key
        content: "{{ vault_private_key }}"
        mode: '0600'
        no_log: true
"""
        }
    },

    # ---------------------------------------------------------
    # Packer
    # ---------------------------------------------------------
    {
        "id": "PACKER-001",
        "iac_type": "packer",
        "category": "secrets",
        "label": "TRUE_POSITIVE",
        "description": "Packer HCL2 template containing hardcoded synthetic AWS secret key",
        "why_scanner_may_fail": "Baseline Packer credential detection.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_PACKER_1",
                "cwe": "CWE-798",
                "cis": "CIS Benchmark - 1.14",
                "nist": "IA-2",
                "resource": "source.amazon-ebs.builder",
                "file": "template.pkr.hcl",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://developer.hashicorp.com/packer/docs/templates/hcl_templates"],
        "undeliverable_static": False,
        "files": {
            "template.pkr.hcl": """source "amazon-ebs" "builder" {
  region        = "us-east-1"
  instance_type = "t3.micro"
  access_key    = "AKIAIOSFODNN7EXAMPLE"
  secret_key    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ami_name      = "custom-ubuntu-image"
}

build {
  sources = ["source.amazon-ebs.builder"]
}
"""
        }
    },
    {
        "id": "PACKER-002",
        "iac_type": "packer",
        "category": "configuration-management",
        "label": "SAFE_LOOKALIKE",
        "description": "Hardened Packer template using IAM instance profile instead of embedded credentials",
        "why_scanner_may_fail": "Safe Packer build template.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_PACKER_1"],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://developer.hashicorp.com/packer/docs/templates/hcl_templates"],
        "undeliverable_static": False,
        "files": {
            "template.pkr.hcl": """source "amazon-ebs" "hardened" {
  region               = "us-east-1"
  instance_type        = "t3.micro"
  ami_name             = "hardened-image-{{timestamp}}"
  iam_instance_profile = "PackerBuilderRole"
}

build {
  sources = ["source.amazon-ebs.hardened"]
}
"""
        }
    },

    # ---------------------------------------------------------
    # Azure Bicep & ARM
    # ---------------------------------------------------------
    {
        "id": "AZ-BICEP-001",
        "iac_type": "bicep-arm",
        "category": "multicloud-azure-gcp",
        "label": "TRUE_POSITIVE",
        "description": "Azure Bicep template creating Storage Account with allowBlobPublicAccess: true and minimumTlsVersion: TLS1_0",
        "why_scanner_may_fail": "Baseline Azure Bicep security test case.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AZURE_59",
                "cwe": "CWE-732",
                "cis": "CIS Azure 2.0 - 5.1.3",
                "nist": "AC-3",
                "resource": "Microsoft.Storage/storageAccounts",
                "file": "main.bicep",
                "line": 4,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1.3", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/overview"],
        "undeliverable_static": False,
        "files": {
            "main.bicep": """param location string = 'eastus'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'corpinsecurestorage2026'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}
"""
        }
    },
    {
        "id": "AZ-BICEP-002",
        "iac_type": "bicep-arm",
        "category": "multicloud-azure-gcp",
        "label": "EVASIVE_MISCONFIG",
        "description": "Azure Bicep Network Security Group rule allowing all inbound traffic from source wildcard '*' to port range '*'",
        "why_scanner_may_fail": "Scanners that do not parse Bicep child securityRules sub-properties miss unrestricted internet access.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AZURE_9",
                "cwe": "CWE-284",
                "cis": "CIS Azure 2.0 - 6.1",
                "nist": "SC-7",
                "resource": "Microsoft.Network/networkSecurityGroups",
                "file": "main.bicep",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "6.1", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "undeliverable_static": False,
        "files": {
            "main.bicep": """param location string = 'eastus'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'open-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}
"""
        }
    },
    {
        "id": "AZ-ARM-001",
        "iac_type": "bicep-arm",
        "category": "multicloud-azure-gcp",
        "label": "TRUE_POSITIVE",
        "description": "Azure Resource Manager (ARM) JSON template creating SQL server firewall rule opening access to 0.0.0.0",
        "why_scanner_may_fail": "Baseline ARM JSON firewall rule test case.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AZURE_11",
                "cwe": "CWE-284",
                "cis": "CIS Azure 2.0 - 4.1.1",
                "nist": "SC-7",
                "resource": "Microsoft.Sql/servers/firewallRules",
                "file": "azuredeploy.json",
                "line": 6,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "4.1.1", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview"],
        "undeliverable_static": False,
        "files": {
            "azuredeploy.json": """{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Sql/servers/firewallRules",
      "apiVersion": "2021-11-01-preview",
      "name": "sqlserver/AllowAllAzureIPs",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
      }
    }
  ]
}
"""
        }
    },

    # ---------------------------------------------------------
    # ArgoCD & Flux
    # ---------------------------------------------------------
    {
        "id": "ARGO-001",
        "iac_type": "argocd-flux",
        "category": "kubernetes-security",
        "label": "TRUE_POSITIVE",
        "description": "ArgoCD Application CRD syncing unpinned HEAD from public repo with automated selfHeal",
        "why_scanner_may_fail": "Baseline GitOps ArgoCD misconfiguration; targetRevision HEAD allows untrusted mutable commits to be deployed automatically.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_ARGO_1",
                "cwe": "CWE-829",
                "cis": "CIS GitOps 1.0 - 1.1",
                "nist": "SA-11",
                "resource": "Application.argocd.unpinned-app",
                "file": "application.yaml",
                "line": 4,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.1", "nist_800_53": "SA-11", "pci_dss": "6.4.2", "soc2": "CC7.1"},
        "source_refs": ["https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#applications"],
        "undeliverable_static": False,
        "files": {
            "application.yaml": """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: unpinned-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/example/untrusted-repo.git
    targetRevision: HEAD
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      selfHeal: true
"""
        }
    },
    {
        "id": "FLUX-001",
        "iac_type": "argocd-flux",
        "category": "kubernetes-security",
        "label": "EVASIVE_MISCONFIG",
        "description": "Flux Kustomization CRD impersonating a privileged cluster-admin service account",
        "why_scanner_may_fail": "Scanners inspecting Flux CRDs fail to verify serviceAccountName bindings against cluster RBAC permissions.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_FLUX_1",
                "cwe": "CWE-250",
                "cis": "CIS GitOps 1.0 - 2.1",
                "nist": "AC-6",
                "resource": "Kustomization.flux-system.privileged-sync",
                "file": "flux-kustomization.yaml",
                "line": 4,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://fluxcd.io/flux/components/kustomize/kustomizations/"],
        "undeliverable_static": False,
        "files": {
            "flux-kustomization.yaml": """apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: privileged-sync
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: fleet-infra
  path: ./clusters/production
  prune: true
  serviceAccountName: cluster-admin-sa
"""
        }
    },

    # ---------------------------------------------------------
    # Crossplane
    # ---------------------------------------------------------
    {
        "id": "XP-001",
        "iac_type": "crossplane",
        "category": "datastores",
        "label": "TRUE_POSITIVE",
        "description": "Crossplane AWS S3 Bucket custom resource defining public-read ACL and deletionPolicy: Delete",
        "why_scanner_may_fail": "Baseline Crossplane custom resource definition misconfiguration.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_XP_1",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3",
                "resource": "Bucket.s3.aws.upbound.io.public-crossplane-bucket",
                "file": "bucket.yaml",
                "line": 4,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://marketplace.upbound.io/providers/upbound/provider-aws-s3/"],
        "undeliverable_static": False,
        "files": {
            "bucket.yaml": """apiVersion: s3.aws.upbound.io/v1beta1
kind: Bucket
metadata:
  name: public-crossplane-bucket
spec:
  forProvider:
    acl: public-read
    region: us-east-1
  deletionPolicy: Delete
"""
        }
    },
    {
        "id": "XP-002",
        "iac_type": "crossplane",
        "category": "datastores",
        "label": "SAFE_LOOKALIKE",
        "description": "Crossplane Managed AWS S3 Bucket with SSE enabled and block public access configuration",
        "why_scanner_may_fail": "Hardened Crossplane managed resource baseline.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_XP_1"],
        "compliance": {"cis": "2.1.1", "nist_800_53": "SC-13", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://marketplace.upbound.io/providers/upbound/provider-aws-s3/"],
        "undeliverable_static": False,
        "files": {
            "bucket.yaml": """apiVersion: s3.aws.upbound.io/v1beta1
kind: Bucket
metadata:
  name: secure-crossplane-bucket
spec:
  forProvider:
    acl: private
    region: us-east-1
    serverSideEncryptionConfiguration:
      - rule:
          - applyServerSideEncryptionByDefault:
              - sseAlgorithm: AES256
  deletionPolicy: Orphan
"""
        }
    }
]


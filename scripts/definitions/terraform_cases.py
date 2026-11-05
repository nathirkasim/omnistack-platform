"""Terraform and OpenTofu test cases for IaC security benchmark."""

TERRAFORM_CASES = [
    # ---------------------------------------------------------
    # 1. Variables and Indirection
    # ---------------------------------------------------------
    {
        "id": "TF-VAR-001",
        "iac_type": "terraform",
        "category": "variables-indirection",
        "label": "TRUE_POSITIVE",
        "description": "S3 bucket ACL set to public-read via variable default value",
        "why_scanner_may_fail": "Baseline test case; simple variable resolution should be caught by all AST and graph scanners.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_20",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3, MP-2",
                "resource": "aws_s3_bucket.data_bucket",
                "file": "main.tf",
                "line": 5,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_s3_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "bucket_acl" {
  type        = string
  default     = "public-read"
  description = "Access control list for S3 bucket"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "corp-data-analytics-storage"
  acl    = var.bucket_acl
}
"""
        }
    },
    {
        "id": "TF-VAR-002",
        "iac_type": "terraform",
        "category": "variables-indirection",
        "label": "EVASIVE_MISCONFIG",
        "description": "S3 bucket has safe default 'private' in variables.tf but overridden to 'public-read' in terraform.tfvars",
        "why_scanner_may_fail": "Scanners that analyze only main.tf or ignore .tfvars files will only see the safe default 'private' and fail to flag the real vulnerability (False Negative).",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_20",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3, MP-2",
                "resource": "aws_s3_bucket.app_bucket",
                "file": "main.tf",
                "line": 6,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_s3_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "corp-production-assets"
  acl    = var.bucket_acl
}
""",
            "variables.tf": """variable "bucket_acl" {
  type        = string
  default     = "private"
  description = "Default safe ACL overridden by tfvars"
}
""",
            "terraform.tfvars": """bucket_acl = "public-read"
"""
        }
    },
    {
        "id": "TF-VAR-003",
        "iac_type": "terraform",
        "category": "variables-indirection",
        "label": "SAFE_LOOKALIKE",
        "description": "Variable default contains 'public-read' but ternary expression resolves to 'private' when is_prod is true",
        "why_scanner_may_fail": "Scanners doing simple AST keyword matching or variable default inspection flag the presence of 'public-read' without evaluating the ternary condition (False Positive).",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_20", "AVD-AWS-0086"],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_s3_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

variable "raw_acl" {
  type    = string
  default = "public-read"
}

variable "is_prod" {
  type    = bool
  default = true
}

locals {
  enforced_acl = var.is_prod ? "private" : var.raw_acl
}

resource "aws_s3_bucket" "guarded_bucket" {
  bucket = "corp-hardened-customer-data"
  acl    = local.enforced_acl
}
"""
        }
    },

    # ---------------------------------------------------------
    # 2. Dynamic Constructs
    # ---------------------------------------------------------
    {
        "id": "TF-DYN-001",
        "iac_type": "terraform",
        "category": "dynamic-constructs",
        "label": "TRUE_POSITIVE",
        "description": "Dynamic ingress block iterating over ports allowing open SSH 0.0.0.0/0",
        "why_scanner_may_fail": "Standard baseline; dynamic ingress blocks must be resolved to evaluate port and CIDR.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "AC-4, SC-7",
                "resource": "aws_security_group.dynamic_ssh",
                "file": "main.tf",
                "line": 10,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.bridgecrew.io/docs/networking_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "dynamic_ssh" {
  name        = "bastion-dynamic-sg"
  description = "Dynamic security group"

  dynamic "ingress" {
    for_each = [22]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
"""
        }
    },
    {
        "id": "TF-DYN-002",
        "iac_type": "terraform",
        "category": "dynamic-constructs",
        "label": "EVASIVE_MISCONFIG",
        "description": "Port 22 and 0.0.0.0/0 are resolved via lookup(), coalesce(), and merge() with list comprehension",
        "why_scanner_may_fail": "AST scanners that do not execute HCL built-in functions (lookup, coalesce, merge, for expressions) see complex expressions rather than literal 22 and 0.0.0.0/0, leading to False Negatives.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "AC-4, SC-7",
                "resource": "aws_security_group.evasive_sg",
                "file": "main.tf",
                "line": 18,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.bridgecrew.io/docs/networking_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

locals {
  base_config   = { admin_port = 22, fallback_cidr = "10.0.0.0/8" }
  override_map  = { active_cidr = "0.0.0.0/0" }
  merged_config = merge(local.base_config, local.override_map)
  target_port   = lookup(local.merged_config, "admin_port", 80)
  target_cidr   = coalesce(local.merged_config.active_cidr, local.merged_config.fallback_cidr)
}

resource "aws_security_group" "evasive_sg" {
  name        = "obfuscated-ingress-sg"
  description = "Evasive SSH opening via dynamic functions"

  ingress {
    from_port   = local.target_port
    to_port     = local.target_port
    protocol    = "tcp"
    cidr_blocks = [for c in [local.target_cidr] : c if length(c) > 0]
  }
}
"""
        }
    },
    {
        "id": "TF-DYN-003",
        "iac_type": "terraform",
        "category": "dynamic-constructs",
        "label": "SAFE_LOOKALIKE",
        "description": "Insecure resource defined with count = 0 (never deployed)",
        "why_scanner_may_fail": "Naive scanners that ignore count or fail to resolve count = 0 flag the resource block even though it is never provisioned in the graph (False Positive).",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_20", "CKV_AWS_24"],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_s3_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

variable "enable_legacy_debug_bucket" {
  type    = bool
  default = false
}

resource "aws_s3_bucket" "disabled_bucket" {
  count  = var.enable_legacy_debug_bucket ? 1 : 0
  bucket = "company-disabled-debug-bucket"
  acl    = "public-read"
}
"""
        }
    },

    # ---------------------------------------------------------
    # 3. Modules
    # ---------------------------------------------------------
    {
        "id": "TF-MOD-001",
        "iac_type": "terraform",
        "category": "modules",
        "label": "TRUE_POSITIVE",
        "description": "Module caller explicitly passes storage_encrypted = false to RDS child module",
        "why_scanner_may_fail": "Baseline test case; parameter passing to local child module must be evaluated.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_16",
                "cwe": "CWE-311",
                "cis": "CIS AWS 1.4 - 2.3.1",
                "nist": "SC-13, SC-28",
                "resource": "module.database.aws_db_instance.db",
                "file": "modules/rds/main.tf",
                "line": 1,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.bridgecrew.io/docs/general_6"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

module "database" {
  source            = "./modules/rds"
  storage_encrypted = false
}
""",
            "modules/rds/main.tf": """variable "storage_encrypted" {
  type    = bool
  default = true
}

resource "aws_db_instance" "db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = var.storage_encrypted
}
"""
        }
    },
    {
        "id": "TF-MOD-002",
        "iac_type": "terraform",
        "category": "modules",
        "label": "EVASIVE_MISCONFIG",
        "description": "3-level nested module chain where insecure default propagates through intermediate unmapped variables",
        "why_scanner_may_fail": "Scanners that do not perform recursive module resolution (root -> layer1 -> layer2 -> leaf) fail to trace variable inheritance across nested boundaries.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_16",
                "cwe": "CWE-311",
                "cis": "CIS AWS 1.4 - 2.3.1",
                "nist": "SC-13, SC-28",
                "resource": "module.tier1.module.tier2.module.leaf.aws_db_instance.db",
                "file": "modules/leaf/main.tf",
                "line": 1,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.bridgecrew.io/docs/general_6"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

module "tier1" {
  source = "./modules/tier1"
}
""",
            "modules/tier1/main.tf": """module "tier2" {
  source = "./modules/tier2"
}
""",
            "modules/tier2/main.tf": """module "leaf" {
  source = "./modules/leaf"
}
""",
            "modules/leaf/main.tf": """variable "storage_encrypted" {
  type    = bool
  default = false
}

resource "aws_db_instance" "db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = var.storage_encrypted
}
"""
        }
    },
    {
        "id": "TF-MOD-003",
        "iac_type": "terraform",
        "category": "modules",
        "label": "SAFE_LOOKALIKE",
        "description": "Module definition defaults to storage_encrypted = false but root caller overrides it to true",
        "why_scanner_may_fail": "Scanners evaluating the module directory in isolation without caller context flag the default false as a violation (False Positive).",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_16", "AVD-AWS-0133"],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.bridgecrew.io/docs/general_6"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

module "hardened_db" {
  source            = "./modules/rds"
  storage_encrypted = true
}
""",
            "modules/rds/main.tf": """variable "storage_encrypted" {
  type    = bool
  default = false
}

resource "aws_db_instance" "db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = var.storage_encrypted
}
"""
        }
    },

    # ---------------------------------------------------------
    # 4. Split Resources
    # ---------------------------------------------------------
    {
        "id": "TF-SPLIT-001",
        "iac_type": "terraform",
        "category": "split-resources",
        "label": "TRUE_POSITIVE",
        "description": "aws_security_group has no inline rules but separate aws_security_group_rule allows open RDP 3389",
        "why_scanner_may_fail": "Baseline split-resource test case; requires linking SG rule resource to parent security group.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_25",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.3",
                "nist": "AC-4, SC-7",
                "resource": "aws_security_group_rule.open_rdp",
                "file": "rules.tf",
                "line": 1,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.3", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.bridgecrew.io/docs/networking_2"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "windows_sg" {
  name        = "windows-fleet-sg"
  description = "Windows instances security group"
}
""",
            "rules.tf": """resource "aws_security_group_rule" "open_rdp" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.windows_sg.id
}
"""
        }
    },
    {
        "id": "TF-SPLIT-002",
        "iac_type": "terraform",
        "category": "split-resources",
        "label": "EVASIVE_MISCONFIG",
        "description": "S3 bucket public access block defined in separate security.tf explicitly sets block_public_acls = false",
        "why_scanner_may_fail": "Scanners checking only bucket.tf assume public access block is handled elsewhere or default, failing to cross-reference security.tf which explicitly exposes it.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_53",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 2.1.5",
                "nist": "AC-3",
                "resource": "aws_s3_bucket_public_access_block.pab",
                "file": "security.tf",
                "line": 1,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_s3_19"],
        "undeliverable_static": False,
        "files": {
            "bucket.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "corp_data" {
  bucket = "company-financial-reports-2026"
}
""",
            "security.tf": """resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.corp_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
"""
        }
    },
    {
        "id": "TF-SPLIT-003",
        "iac_type": "terraform",
        "category": "split-resources",
        "label": "SAFE_LOOKALIKE",
        "description": "S3 bucket declared in s3.tf without inline encryption block, but server-side encryption is attached in encryption.tf and public access block is attached in access.tf (AWS Provider v4+ standard architecture)",
        "why_scanner_may_fail": "Legacy scanners built for AWS provider v3 check the aws_s3_bucket block for inline server_side_encryption_configuration or public_access_block and trigger a False Positive when split into separate resources.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_19", "CKV_AWS_144", "AVD-AWS-0087"],
        "compliance": {"cis": "2.1.1", "nist_800_53": "SC-13", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.bridgecrew.io/docs/s3_1"],
        "undeliverable_static": False,
        "files": {
            "s3.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "modern_bucket" {
  bucket = "company-secure-reports"
}
""",
            "encryption.tf": """resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.modern_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
""",
            "access.tf": """resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.modern_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
        }
    },

    # ---------------------------------------------------------
    # 5. Policy Encoding
    # ---------------------------------------------------------
    {
        "id": "TF-POL-001",
        "iac_type": "terraform",
        "category": "policy-encoding",
        "label": "TRUE_POSITIVE",
        "description": "IAM policy granting Action = '*' and Resource = '*' using jsonencode",
        "why_scanner_may_fail": "Baseline IAM wildcard detection; all policy checkers should detect star permissions.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_1",
                "cwe": "CWE-732",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-3, AC-6",
                "resource": "aws_iam_policy.admin_policy",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://docs.bridgecrew.io/docs/iam_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_policy" "admin_policy" {
  name        = "full-admin-access"
  description = "Excessive administrator permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
"""
        }
    },
    {
        "id": "TF-POL-002",
        "iac_type": "terraform",
        "category": "policy-encoding",
        "label": "EVASIVE_MISCONFIG",
        "description": "IAM privilege escalation chain (iam:PassRole + ec2:RunInstances) disguised in aws_iam_policy_document without explicit star actions",
        "why_scanner_may_fail": "Scanners searching exclusively for Action = '*' or broad admin wildcards miss specific privilege escalation pairs (CWE-250: Execution with Unnecessary Privileges) that allow full cloud takeover via IAM PassRole.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_286",
                "cwe": "CWE-250",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-6",
                "resource": "aws_iam_policy.privesc_policy",
                "file": "main.tf",
                "line": 15,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-6", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

data "aws_iam_policy_document" "privesc" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole", "ec2:RunInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "privesc_policy" {
  name   = "ec2-deployment-worker"
  policy = data.aws_iam_policy_document.privesc.json
}
"""
        }
    },
    {
        "id": "TF-POL-003",
        "iac_type": "terraform",
        "category": "policy-encoding",
        "label": "SAFE_LOOKALIKE",
        "description": "S3 bucket policy uses Action = 's3:*' and Resource = '*' but contains Condition key aws:PrincipalOrgID and aws:SecureTransport neutralizing public risk",
        "why_scanner_may_fail": "Scanners that look only at Action and Resource wildcards without evaluating Condition keys produce False Positives because access is restricted solely to the AWS Organization over TLS.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_1", "CKV_AWS_70"],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-3", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "org_shared_bucket" {
  bucket = "company-org-restricted-data"
}

resource "aws_s3_bucket_policy" "org_policy" {
  bucket = aws_s3_bucket.org_shared_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrganizationOnly"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.org_shared_bucket.arn,
          "${aws_s3_bucket.org_shared_bucket.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-synth1234567"
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
}
"""
        }
    },

    # ---------------------------------------------------------
    # 6. Network
    # ---------------------------------------------------------
    {
        "id": "TF-NET-001",
        "iac_type": "terraform",
        "category": "network",
        "label": "TRUE_POSITIVE",
        "description": "Security group ingress allows 0.0.0.0/0 on SSH port 22 directly",
        "why_scanner_may_fail": "Baseline network exposure test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "SC-7",
                "resource": "aws_security_group.open_ssh",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.bridgecrew.io/docs/networking_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "open_ssh" {
  name        = "public-ssh-sg"
  description = "Open SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        }
    },
    {
        "id": "TF-NET-002",
        "iac_type": "terraform",
        "category": "network",
        "label": "EVASIVE_MISCONFIG",
        "description": "Ingress rule opens all traffic to IPv6 ::/0 with protocol = -1 and port 0-65535",
        "why_scanner_may_fail": "Scanners that only inspect ipv4 cidr_blocks or check specifically for '0.0.0.0/0' fail to detect open IPv6 default route (::/0) on all protocols.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_260",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.1",
                "nist": "SC-7",
                "resource": "aws_security_group.ipv6_open",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.bridgecrew.io/docs/networking_29"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "ipv6_open" {
  name        = "ipv6-all-open-sg"
  description = "IPv6 unrestricted ingress"

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
        }
    },
    {
        "id": "TF-NET-003",
        "iac_type": "terraform",
        "category": "network",
        "label": "SAFE_LOOKALIKE",
        "description": "Security group ingress allows 0.0.0.0/0 on port 443 for public ALB with modern TLS 1.3 policy",
        "why_scanner_may_fail": "Scanners that blindly alert on any 0.0.0.0/0 ingress without contextualizing HTTPS port 443 on public load balancers generate False Positives.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_260", "CKV_AWS_24"],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "alb_https" {
  name        = "public-alb-https-sg"
  description = "Permit inbound HTTPS from internet"

  ingress {
    description = "Standard HTTPS internet ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""
        }
    },

    # ---------------------------------------------------------
    # 7. Data Stores
    # ---------------------------------------------------------
    {
        "id": "TF-DATA-001",
        "iac_type": "terraform",
        "category": "datastores",
        "label": "TRUE_POSITIVE",
        "description": "RDS PostgreSQL instance with publicly_accessible = true and storage_encrypted = false",
        "why_scanner_may_fail": "Baseline RDS misconfiguration.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_16",
                "cwe": "CWE-311",
                "cis": "CIS AWS 1.4 - 2.3.1",
                "nist": "SC-28",
                "resource": "aws_db_instance.unprotected_rds",
                "file": "main.tf",
                "line": 5,
                "severity": "HIGH"
            },
            {
                "rule": "CKV_AWS_17",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 2.3.2",
                "nist": "AC-3",
                "resource": "aws_db_instance.unprotected_rds",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.bridgecrew.io/docs/general_6"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "unprotected_rds" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}
"""
        }
    },
    {
        "id": "TF-DATA-002",
        "iac_type": "terraform",
        "category": "datastores",
        "label": "EVASIVE_MISCONFIG",
        "description": "RDS instance has storage encryption enabled but backup_retention_period = 0 and deletion_protection = false",
        "why_scanner_may_fail": "Scanners that only check storage_encrypted miss backup_retention_period = 0 (backups completely disabled) and missing deletion protection, violating disaster recovery compliance.",
        "severity": "MEDIUM",
        "expected_findings": [
            {
                "rule": "CKV_AWS_133",
                "cwe": "CWE-754",
                "cis": "CIS AWS 1.4 - 2.3.3",
                "nist": "CP-9",
                "resource": "aws_db_instance.nobackup_rds",
                "file": "main.tf",
                "line": 5,
                "severity": "MEDIUM"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.3", "nist_800_53": "CP-9", "pci_dss": "10.5.3", "soc2": "A1.2"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_general_133"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "nobackup_rds" {
  allocated_storage       = 50
  engine                  = "postgres"
  instance_class          = "db.t3.small"
  storage_encrypted       = true
  backup_retention_period = 0
  deletion_protection     = false
}
"""
        }
    },
    {
        "id": "TF-DATA-003",
        "iac_type": "terraform",
        "category": "datastores",
        "label": "SAFE_LOOKALIKE",
        "description": "DynamoDB table without explicit server_side_encryption block (AWS encrypts DynamoDB by default with AWS KMS owned key)",
        "why_scanner_may_fail": "Legacy scanners trigger False Positives on aws_dynamodb_table missing an explicit server_side_encryption block, even though AWS has enforced default encryption since 2018.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_28", "AVD-AWS-0024"],
        "compliance": {"cis": "2.2.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_dynamodb_table" "default_encrypted_table" {
  name         = "user-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }
}
"""
        }
    },

    # ---------------------------------------------------------
    # 8. Secrets
    # ---------------------------------------------------------
    {
        "id": "TF-SEC-001",
        "iac_type": "terraform",
        "category": "secrets",
        "label": "TRUE_POSITIVE",
        "description": "Hardcoded synthetic AWS access key and secret key in terraform provider block",
        "why_scanner_may_fail": "Baseline secret detection; regex patterns for AKIA and base64 key should trigger.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_41",
                "cwe": "CWE-798",
                "cis": "CIS AWS 1.4 - 1.14",
                "nist": "IA-2",
                "resource": "provider.aws",
                "file": "main.tf",
                "line": 1,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://docs.bridgecrew.io/docs/bc_aws_secrets_1"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "test" {
  bucket = "synthetic-secrets-test"
}
"""
        }
    },
    {
        "id": "TF-SEC-002",
        "iac_type": "terraform",
        "category": "secrets",
        "label": "EVASIVE_MISCONFIG",
        "description": "AWS access key split into concatenated locals to evade regex token scanners",
        "why_scanner_may_fail": "Regex scanners matching 'AKIA[0-9A-Z]{16}' fail to detect tokens split into smaller string fragments concatenated via HCL interpolation.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_41",
                "cwe": "CWE-798",
                "cis": "CIS AWS 1.4 - 1.14",
                "nist": "IA-2",
                "resource": "local.api_key",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://cwe.mitre.org/data/definitions/798.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

locals {
  k_prefix = "AKIA"
  k_body   = "IOSFODNN7"
  k_suffix = "EXAMPLE"
  api_key  = "${local.k_prefix}${local.k_body}${local.k_suffix}"
}

resource "aws_ssm_parameter" "leaked_key" {
  name  = "/app/credentials/aws_key"
  type  = "String"
  value = local.api_key
}
"""
        }
    },
    {
        "id": "TF-SEC-003",
        "iac_type": "terraform",
        "category": "secrets",
        "label": "SAFE_LOOKALIKE",
        "description": "High-entropy SHA-256 hash and non-secret placeholder token",
        "why_scanner_may_fail": "Pure entropy-based secret scanners flag high Shannon entropy strings (like SHA256 sums or UUIDs) as credentials, producing False Positives.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_41", "generic-secret"],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://en.wikipedia.org/wiki/Shannon_entropy"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_object" "verified_binary" {
  bucket = "company-software-releases"
  key    = "app-v1.0.0.tar.gz"
  # High entropy sha256 checksum (not a secret)
  etag   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

resource "aws_ssm_parameter" "template_placeholder" {
  name  = "/config/db_placeholder"
  type  = "String"
  value = "CHANGEME_ON_FIRST_LOGIN_MOCK_12345"
}
"""
        }
    },

    # ---------------------------------------------------------
    # 15. Parser / Format Evasion
    # ---------------------------------------------------------
    {
        "id": "TF-PARSE-001",
        "iac_type": "terraform",
        "category": "parser-evasion",
        "label": "TRUE_POSITIVE",
        "description": "Terraform configuration expressed entirely in JSON syntax (.tf.json) with open SSH",
        "why_scanner_may_fail": "Many scanners filter strictly on *.tf file extensions and omit *.tf.json entirely, missing genuine security vulnerabilities.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "SC-7",
                "resource": "aws_security_group.json_ssh",
                "file": "main.tf.json",
                "line": 1,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://developer.hashicorp.com/terraform/language/syntax/json"],
        "undeliverable_static": False,
        "files": {
            "main.tf.json": """{
  "provider": {
    "aws": {
      "region": "us-east-1"
    }
  },
  "resource": {
    "aws_security_group": {
      "json_ssh": {
        "name": "json-open-ssh",
        "ingress": [
          {
            "from_port": 22,
            "to_port": 22,
            "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"]
          }
        ]
      }
    }
  }
}
"""
        }
    },
    {
        "id": "TF-PARSE-002",
        "iac_type": "terraform",
        "category": "parser-evasion",
        "label": "EVASIVE_MISCONFIG",
        "description": "Bogus inline suppression comment '# checkov:skip=CKV_AWS_20' placed on an unencrypted RDS instance to trick scanner into suppressing S3 rule on RDS",
        "why_scanner_may_fail": "Faulty suppression parsers that associate comments with adjacent blocks or apply broad rule skipping without verifying resource type compatibility.",
        "severity": "HIGH",
        "expected_findings": [
            {
                "rule": "CKV_AWS_16",
                "cwe": "CWE-311",
                "cis": "CIS AWS 1.4 - 2.3.1",
                "nist": "SC-28",
                "resource": "aws_db_instance.bogus_suppressed",
                "file": "main.tf",
                "line": 5,
                "severity": "HIGH"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "2.3.1", "nist_800_53": "SC-28", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://www.checkov.io/2.Basics/Suppressing%20and%20Skipping%20Policies.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

# checkov:skip=CKV_AWS_20:Misleading suppression for S3 public read applied to RDS
resource "aws_db_instance" "bogus_suppressed" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}
"""
        }
    },
    {
        "id": "TF-PARSE-003",
        "iac_type": "terraform",
        "category": "parser-evasion",
        "label": "SAFE_LOOKALIKE",
        "description": "Legitimate, properly documented Checkov suppression for intentional public static website bucket",
        "why_scanner_may_fail": "Scanners that do not respect valid inline suppression comments '#checkov:skip' will flag this intentional design as a violation (False Positive).",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_20"],
        "compliance": {"cis": "2.1.5", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://www.checkov.io/2.Basics/Suppressing%20and%20Skipping%20Policies.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

# checkov:skip=CKV_AWS_20:Intentional public documentation website bucket
resource "aws_s3_bucket" "public_docs" {
  bucket = "company-public-documentation-static-website"
  acl    = "public-read"
}
"""
        }
    },

    # ---------------------------------------------------------
    # 17. Runtime / Drift (EXPECTED_UNDETECTABLE_STATIC)
    # ---------------------------------------------------------
    {
        "id": "TF-DRIFT-001",
        "iac_type": "terraform",
        "category": "runtime-drift",
        "label": "EVASIVE_MISCONFIG",
        "description": "S3 bucket encryption toggle read dynamically from aws_ssm_parameter data source (only known at apply/plan time)",
        "why_scanner_may_fail": "Static code scanners inspect AST without cloud API resolution; data source values are unresolved computed values. Mark as EXPECTED_UNDETECTABLE_STATIC.",
        "severity": "HIGH",
        "expected_findings": [],
        "expected_no_findings": [],
        "compliance": {"cis": "2.1.1", "nist_800_53": "SC-13", "pci_dss": "3.4", "soc2": "CC6.7"},
        "source_refs": ["https://developer.hashicorp.com/terraform/language/data-sources"],
        "undeliverable_static": True,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

data "aws_ssm_parameter" "encryption_enabled" {
  name = "/infra/s3/encryption_toggle"
}

resource "aws_s3_bucket" "computed_bucket" {
  bucket = "computed-runtime-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "computed_sse" {
  bucket = aws_s3_bucket.computed_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = data.aws_ssm_parameter.encryption_enabled.value == "true" ? "AES256" : "None"
    }
  }
}
"""
        }
    },
    {
        "id": "TF-DRIFT-002",
        "iac_type": "terraform",
        "category": "runtime-drift",
        "label": "SAFE_LOOKALIKE",
        "description": "Security group referencing computed output from external workspace data.terraform_remote_state",
        "why_scanner_may_fail": "Static code scanners inspect AST without backend remote state access. Mark as EXPECTED_UNDETECTABLE_STATIC.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_AWS_24"],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://developer.hashicorp.com/terraform/language/state/remote-state-data"],
        "undeliverable_static": True,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = "corp-terraform-state"
    key    = "network/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_security_group" "remote_state_sg" {
  name        = "remote-state-bastion-sg"
  description = "Ingress restricted to remote bastion CIDR"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [data.terraform_remote_state.network.outputs.bastion_cidr]
  }
}
"""
        }
    },

    # ---------------------------------------------------------
    # 14. Multi-Cloud (Google Cloud Platform via Terraform)
    # ---------------------------------------------------------
    {
        "id": "GCP-TF-001",
        "iac_type": "terraform",
        "category": "multicloud-azure-gcp",
        "label": "TRUE_POSITIVE",
        "description": "Google Cloud Storage bucket with IAM binding granting roles/storage.objectViewer to allUsers",
        "why_scanner_may_fail": "Baseline GCP storage bucket exposure test case.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_GCP_28",
                "cwe": "CWE-732",
                "cis": "CIS GCP 1.3 - 5.1",
                "nist": "AC-3",
                "resource": "google_storage_bucket_iam_binding.public_rule",
                "file": "main.tf",
                "line": 9,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.1", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://cloud.google.com/storage/docs/access-control/iam"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "public_bucket" {
  name     = "synth-eval-open-bucket-2026"
  location = "US"
}

resource "google_storage_bucket_iam_binding" "public_rule" {
  bucket  = google_storage_bucket.public_bucket.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
"""
        }
    },
    {
        "id": "GCP-TF-002",
        "iac_type": "terraform",
        "category": "multicloud-azure-gcp",
        "label": "EVASIVE_MISCONFIG",
        "description": "GCP compute firewall rule opens all ports (0-65535) to 0.0.0.0/0 with target_tags omitted (applies to all VPC instances)",
        "why_scanner_may_fail": "Scanners checking only port 22 or rules with explicit target tags miss firewall rules with empty target_tags that broad-sweep the entire network.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_GCP_2",
                "cwe": "CWE-284",
                "cis": "CIS GCP 1.3 - 3.6",
                "nist": "SC-7",
                "resource": "google_compute_firewall.open_all",
                "file": "main.tf",
                "line": 6,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "3.6", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://cloud.google.com/firewall/docs/firewalls-overview"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_compute_firewall" "open_all" {
  name    = "allow-all-ingress"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}
"""
        }
    },
    {
        "id": "GCP-TF-003",
        "iac_type": "terraform",
        "category": "multicloud-azure-gcp",
        "label": "SAFE_LOOKALIKE",
        "description": "GCP Storage bucket with uniform_bucket_level_access enabled and IAM binding restricted to authorized service account",
        "why_scanner_may_fail": "Baseline safe GCP Storage configuration.",
        "severity": "LOW",
        "expected_findings": [],
        "expected_no_findings": ["CKV_GCP_28"],
        "compliance": {"cis": "5.1", "nist_800_53": "AC-3", "pci_dss": "1.3", "soc2": "CC6.1"},
        "source_refs": ["https://cloud.google.com/storage/docs/uniform-bucket-level-access"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "google" {
  project = "synth-eval-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "hardened_bucket" {
  name                        = "synth-eval-hardened-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_binding" "service_account_access" {
  bucket  = google_storage_bucket.hardened_bucket.name
  role    = "roles/storage.objectViewer"
  members = ["serviceAccount:app-worker@synth-eval-project.iam.gserviceaccount.com"]
}
"""
        }
    },

    # ---------------------------------------------------------
    # Additional Policy & Network & Secret Depth
    # ---------------------------------------------------------
    {
        "id": "TF-POL-004",
        "iac_type": "terraform",
        "category": "policy-encoding",
        "label": "EVASIVE_MISCONFIG",
        "description": "IAM AssumeRole trust policy granting sts:AssumeRole to Principal '*' without ExternalId (confused deputy vulnerability)",
        "why_scanner_may_fail": "Scanners that only check aws_iam_policy and ignore assume_role_policy inside aws_iam_role fail to detect world-assumable roles.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_60",
                "cwe": "CWE-287",
                "cis": "CIS AWS 1.4 - 1.16",
                "nist": "AC-3",
                "resource": "aws_iam_role.confused_deputy_role",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.16", "nist_800_53": "AC-3", "pci_dss": "7.1.2", "soc2": "CC6.3"},
        "source_refs": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "confused_deputy_role" {
  name = "public-vendor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}
"""
        }
    },
    {
        "id": "TF-NET-004",
        "iac_type": "terraform",
        "category": "network",
        "label": "EVASIVE_MISCONFIG",
        "description": "Ingress CIDR constructed dynamically via cidrsubnet('0.0.0.0/0', 0, 0)",
        "why_scanner_may_fail": "Scanners using regex matching for literal '0.0.0.0/0' fail when the network CIDR is calculated using Terraform's cidrsubnet function.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_24",
                "cwe": "CWE-284",
                "cis": "CIS AWS 1.4 - 5.2",
                "nist": "SC-7",
                "resource": "aws_security_group.function_cidr_sg",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "5.2", "nist_800_53": "SC-7", "pci_dss": "1.2.1", "soc2": "CC6.6"},
        "source_refs": ["https://developer.hashicorp.com/terraform/language/functions/cidrsubnet"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "function_cidr_sg" {
  name        = "calculated-cidr-sg"
  description = "Ingress with function-calculated CIDR"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [cidrsubnet("0.0.0.0/0", 0, 0)]
  }
}
"""
        }
    },
    {
        "id": "TF-SEC-004",
        "iac_type": "terraform",
        "category": "secrets",
        "label": "EVASIVE_MISCONFIG",
        "description": "Sensitive database password passed in EC2 user_data script via base64 gzip archive",
        "why_scanner_may_fail": "Scanners that do not decode user_data_base64 payloads miss embedded credentials.",
        "severity": "CRITICAL",
        "expected_findings": [
            {
                "rule": "CKV_AWS_46",
                "cwe": "CWE-798",
                "cis": "CIS AWS 1.4 - 1.14",
                "nist": "IA-2",
                "resource": "aws_instance.provisioned_instance",
                "file": "main.tf",
                "line": 5,
                "severity": "CRITICAL"
            }
        ],
        "expected_no_findings": [],
        "compliance": {"cis": "1.14", "nist_800_53": "IA-2", "pci_dss": "8.2.1", "soc2": "CC6.1"},
        "source_refs": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html"],
        "undeliverable_static": False,
        "files": {
            "main.tf": """provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "provisioned_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # Base64 encoded payload containing: export DB_PASSWORD="SyntheticSuperSecretPassword123"
  user_data_base64 = "ZXhwb3J0IERCX1BBU1NXT1JEPSJTeW50aGV0aWNTdXBlclNlY3JldFBhc3N3b3JkMTIzIgo="
}
"""
        }
    }
]

from typing import List
from .base import FixtureBuilder, TargetLine

def generate_terraform_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: TERRAFORM
    # -------------------------------------------------------------

    # 1. S3 Bucket Public Read ACL (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_s3_public_read_flag.tf")
    fb.add('resource "aws_s3_bucket" "distribution" {')
    fb.add('  bucket = "app-distribution-artifacts"')
    fb.add_target(
        '  acl    = "public-read"',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-001",
        "S3 bucket configured with world-readable public ACL"
    )
    fb.add("}")
    fixtures.append(fb)

    # 2. S3 Bucket Private ACL (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_s3_private_noflag.tf")
    fb.add('resource "aws_s3_bucket" "secure_store" {')
    fb.add('  bucket = "app-private-credentials"')
    fb.add_target(
        '  acl    = "private"',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-002",
        "S3 bucket explicitly configured with private ACL restriction"
    )
    fb.add("}")
    fixtures.append(fb)

    # 3. Security Group Open Ingress SSH IPv4 (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_open_ssh_flag.tf")
    fb.add('resource "aws_security_group_rule" "ingress_ssh" {')
    fb.add('  type              = "ingress"')
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add_target(
        '  cidr_blocks       = ["0.0.0.0/0"]',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-003",
        "Security group ingress rule exposing port 22 directly to 0.0.0.0/0"
    )
    fb.add("}")
    fixtures.append(fb)

    # 4. Security Group Open Ingress SSH IPv6 (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_open_ssh_ipv6_flag.tf")
    fb.add('resource "aws_security_group_rule" "ingress_ssh_v6" {')
    fb.add('  type              = "ingress"')
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add_target(
        '  ipv6_cidr_blocks  = ["::/0"]',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-004",
        "Security group rule exposing SSH port 22 to all IPv6 addresses"
    )
    fb.add("}")
    fixtures.append(fb)

    # 5. Security Group Private Ingress SSH (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_private_ssh_noflag.tf")
    fb.add('resource "aws_security_group_rule" "internal_ssh" {')
    fb.add('  type              = "ingress"')
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add_target(
        '  cidr_blocks       = ["10.0.0.0/8"]',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-005",
        "Ingress port 22 strictly bounded to private RFC1918 enterprise subnet"
    )
    fb.add("}")
    fixtures.append(fb)

    # 6. Security Group /29 CIDR Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_cidr_slash29_noflag.tf")
    fb.add('resource "aws_security_group_rule" "bastion_ingress" {')
    fb.add('  type              = "ingress"')
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add_target(
        '  cidr_blocks       = ["3.251.148.96/29"]',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-006",
        "Specific small /29 prefix probing unanchored 0.0.0.0/0 regexes"
    )
    fb.add("}")
    fixtures.append(fb)

    # 7. Security Group Port Range Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_port_2200_noflag.tf")
    fb.add('resource "aws_security_group_rule" "custom_app" {')
    fb.add('  type              = "ingress"')
    fb.add_target(
        '  from_port         = 2200',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-007",
        "High port number containing digit prefix 22 without being port 22"
    )
    fb.add('  to_port           = 2299')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add('  cidr_blocks       = ["0.0.0.0/0"]')
    fb.add("}")
    fixtures.append(fb)

    # 8. Security Group Egress on Port 22 (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_egress_ssh_noflag.tf")
    fb.add('resource "aws_security_group_rule" "outbound_ssh" {')
    fb.add_target(
        '  type              = "egress"',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-008",
        "Egress traffic rule direction rather than ingress exposure"
    )
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add('  cidr_blocks       = ["0.0.0.0/0"]')
    fb.add("}")
    fixtures.append(fb)

    # 9. Security Group Description Containing 0.0.0.0/0 (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_sg_desc_lookalike_noflag.tf")
    fb.add('resource "aws_security_group_rule" "vpn_ingress" {')
    fb.add('  type              = "ingress"')
    fb.add('  from_port         = 22')
    fb.add('  to_port           = 22')
    fb.add('  protocol          = "tcp"')
    fb.add('  security_group_id = "sg-0123456789abcdef0"')
    fb.add_target(
        '  description       = "Internal VPN replacing previous 0.0.0.0/0 rule"',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-009",
        "CIDR string occurring solely inside human description text"
    )
    fb.add('  cidr_blocks       = ["10.200.0.0/16"]')
    fb.add("}")
    fixtures.append(fb)

    # 10. EBS Volume Unencrypted (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_ebs_unencrypted_flag.tf")
    fb.add('resource "aws_ebs_volume" "data_drive" {')
    fb.add('  availability_zone = "us-east-1a"')
    fb.add('  size              = 100')
    fb.add_target(
        '  encrypted         = false',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-010",
        "Explicitly disabled encryption on persistent storage volume"
    )
    fb.add("}")
    fixtures.append(fb)

    # 11. EBS Volume Encrypted (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_ebs_encrypted_noflag.tf")
    fb.add('resource "aws_ebs_volume" "data_drive" {')
    fb.add('  availability_zone = "us-east-1a"')
    fb.add('  size              = 100')
    fb.add_target(
        '  encrypted         = true',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-011",
        "EBS volume with cryptographic encryption enabled"
    )
    fb.add("}")
    fixtures.append(fb)

    # 12. RDS Instance Publicly Accessible (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_rds_public_flag.tf")
    fb.add('resource "aws_db_instance" "database" {')
    fb.add('  allocated_storage   = 20')
    fb.add('  engine              = "postgres"')
    fb.add('  instance_class      = "db.t3.micro"')
    fb.add_target(
        '  publicly_accessible = true',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-012",
        "Relational database configured with direct public internet access"
    )
    fb.add("}")
    fixtures.append(fb)

    # 13. RDS Instance Private & Encrypted (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_rds_private_noflag.tf")
    fb.add('resource "aws_db_instance" "database" {')
    fb.add('  allocated_storage   = 20')
    fb.add('  engine              = "postgres"')
    fb.add('  instance_class      = "db.t3.micro"')
    fb.add_target(
        '  publicly_accessible = false',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-013",
        "Database correctly sequestered from public internet routing"
    )
    fb.add_target(
        '  storage_encrypted   = true',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-014",
        "Database storage encryption activated"
    )
    fb.add("}")
    fixtures.append(fb)

    # 14. EC2 Associate Public IP Address (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_ec2_public_ip_flag.tf")
    fb.add('resource "aws_instance" "worker" {')
    fb.add('  ami           = "ami-0c55b159cbfafe1f0"')
    fb.add('  instance_type = "t3.micro"')
    fb.add_target(
        '  associate_public_ip_address = true',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-015",
        "Direct public IP allocation enabled on compute instance"
    )
    fb.add("}")
    fixtures.append(fb)

    # 15. EC2 Associate Public IP False (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_ec2_public_ip_noflag.tf")
    fb.add('resource "aws_instance" "worker" {')
    fb.add('  ami           = "ami-0c55b159cbfafe1f0"')
    fb.add('  instance_type = "t3.micro"')
    fb.add_target(
        '  associate_public_ip_address = false',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-016",
        "Explicit prevention of public IP allocation on instance"
    )
    fb.add("}")
    fixtures.append(fb)

    # 16. S3 Public Access Block Disabled (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_s3_pab_open_flag.tf")
    fb.add('resource "aws_s3_bucket_public_access_block" "open_access" {')
    fb.add('  bucket = "app-unprotected-bucket"')
    fb.add_target(
        '  block_public_acls = false',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-017",
        "S3 public access block with public ACL enforcement disabled"
    )
    fb.add("}")
    fixtures.append(fb)

    # 17. S3 Public Access Block Enabled (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_s3_pab_strict_noflag.tf")
    fb.add('resource "aws_s3_bucket_public_access_block" "hardened_access" {')
    fb.add('  bucket = "app-hardened-bucket"')
    fb.add_target(
        '  block_public_acls       = true',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-018",
        "Strict blocking of public ACL assignments"
    )
    fb.add_target(
        '  block_public_policy     = true',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-019",
        "Strict blocking of public bucket policies"
    )
    fb.add("}")
    fixtures.append(fb)

    # 18. IAM Wildcard Policy (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_iam_wildcard_flag.tf")
    fb.add('resource "aws_iam_policy" "wildcard_policy" {')
    fb.add('  name   = "admin-policy"')
    fb.add('  policy = jsonencode({')
    fb.add('    Version = "2012-10-17"')
    fb.add('    Statement = [{')
    fb.add_target(
        '      Action   = "*"',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-020",
        "Unrestricted wildcard Action in IAM policy statement"
    )
    fb.add('      Effect   = "Allow"')
    fb.add_target(
        '      Resource = "*"',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-021",
        "Unrestricted wildcard Resource in IAM policy statement"
    )
    fb.add('    }]')
    fb.add('  })')
    fb.add("}")
    fixtures.append(fb)

    # 19. IAM Principal Condition Neutralization (NO_FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_iam_org_condition_noflag.tf")
    fb.add('resource "aws_iam_policy" "org_restricted_policy" {')
    fb.add('  name   = "org-policy"')
    fb.add('  policy = jsonencode({')
    fb.add('    Version = "2012-10-17"')
    fb.add('    Statement = [{')
    fb.add('      Action    = "s3:GetObject"')
    fb.add('      Effect    = "Allow"')
    fb.add('      Principal = "*"')
    fb.add('      Resource  = "arn:aws:s3:::corporate-assets/*"')
    fb.add('      Condition = {')
    fb.add_target(
        '        StringEquals = { "aws:PrincipalOrgID" = "o-abcdef1234" }',
        "NO_FLAG", "TERRAFORM", "L1_BASIC", "TF-022",
        "PrincipalOrgID condition neutralizing Principal wildcard"
    )
    fb.add('      }')
    fb.add('    }]')
    fb.add('  })')
    fb.add("}")
    fixtures.append(fb)

    # 20. Terraform Provider Hardcoded Keys (FLAG)
    fb = FixtureBuilder("l1_basic/terraform/tf_provider_hardcoded_flag.tf")
    fb.add('provider "aws" {')
    fb.add('  region     = "us-east-1"')
    fb.add_target(
        '  access_key = "AKIA2Y8Z4W9V3X7R1T5M"',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-023",
        "Static AWS access key credential inside provider block"
    )
    fb.add_target(
        '  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz8947KlMnP"',
        "FLAG", "TERRAFORM", "L1_BASIC", "TF-024",
        "Static AWS secret access key credential inside provider block"
    )
    fb.add("}")
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: TERRAFORM
    # -------------------------------------------------------------

    # L2-1: Security Groups Intermediate
    fb = FixtureBuilder("l2_intermediate/terraform/security_groups.tf")
    fb.add('resource "aws_security_group" "web_tier" {')
    fb.add('  name        = "web-tier-sg"')
    fb.add('  description = "Tier SG for production web"')
    fb.add('  vpc_id      = "vpc-0123456789abcdef0"')
    fb.add('  ingress {')
    fb.add('    from_port   = 443')
    fb.add('    to_port     = 443')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["0.0.0.0/0"]',
        "DEBATABLE", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-001",
        "Standard HTTPS ingress port 443 open to internet"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["0.0.0.0/0"]',
        "FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-002",
        "Insecure SSH access exposed globally on 0.0.0.0/0"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 3389')
    fb.add('    to_port     = 3389')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    ipv6_cidr_blocks = ["::/0"]',
        "FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-003",
        "Insecure RDP port exposed to all IPv6 addresses"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["10.0.0.0/8"]',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-004",
        "SSH access restricted to private internal IP range"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add('    from_port   = 22')
    fb.add('    to_port     = 22')
    fb.add('    protocol    = "tcp"')
    fb.add_target(
        '    cidr_blocks = ["3.251.148.96/29"]',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-005",
        "SSH port restricted to specific external /29 CIDR block"
    )
    fb.add('  }')
    fb.add('  ingress {')
    fb.add_target(
        '    from_port   = 2200',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-006",
        "Custom service high port range start digit lookalike"
    )
    fb.add('    to_port     = 2299')
    fb.add('    protocol    = "tcp"')
    fb.add('    cidr_blocks = ["0.0.0.0/0"]')
    fb.add('  }')
    fb.add('  egress {')
    fb.add('    from_port   = 0')
    fb.add('    to_port     = 0')
    fb.add('    protocol    = "-1"')
    fb.add_target(
        '    cidr_blocks = ["0.0.0.0/0"]',
        "DEBATABLE", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-007",
        "Standard unrestricted outbound egress rule"
    )
    fb.add('  }')
    fb.add("}")
    fixtures.append(fb)

    # L2-2: Storage Resources Intermediate
    fb = FixtureBuilder("l2_intermediate/terraform/storage_resources.tf")
    fb.add('resource "aws_s3_bucket" "audit_archive" {')
    fb.add('  bucket = "prod-audit-archive-logs"')
    fb.add_target(
        '  acl    = "private"',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-008",
        "Private ACL setting on audit archive S3 bucket"
    )
    fb.add("}")
    fb.add('resource "aws_s3_bucket_public_access_block" "audit_pab" {')
    fb.add('  bucket                  = aws_s3_bucket.audit_archive.id')
    fb.add_target(
        '  block_public_acls       = true',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-009",
        "Public access block active for public ACL prevention"
    )
    fb.add_target(
        '  block_public_policy     = true',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-010",
        "Public access block active for policy prevention"
    )
    fb.add("}")
    fb.add('resource "aws_db_instance" "prod_db" {')
    fb.add('  allocated_storage   = 100')
    fb.add('  engine              = "postgres"')
    fb.add('  instance_class      = "db.r6g.large"')
    fb.add_target(
        '  publicly_accessible = true',
        "FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-011",
        "Production database marked publicly accessible"
    )
    fb.add_target(
        '  storage_encrypted   = false',
        "FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-012",
        "Production database storage encryption disabled"
    )
    fb.add("}")
    fb.add('resource "aws_ebs_volume" "app_cache" {')
    fb.add('  availability_zone = "us-east-1a"')
    fb.add('  size              = 50')
    fb.add_target(
        '  encrypted         = true',
        "NO_FLAG", "TERRAFORM", "L2_INTERMEDIATE", "TF-L2-013",
        "Encrypted EBS volume storage"
    )
    fb.add("}")
    fixtures.append(fb)

    return fixtures

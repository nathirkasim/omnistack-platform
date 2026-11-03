# Advanced Terraform with dynamic blocks, locals, and cross-resource dependencies

variable "environment" {
  type    = string
  default = "prod"
}

variable "create_insecure_bucket" {
  type    = bool
  default = true
}

variable "enable_ssh_ingress" {
  type    = bool
  default = true
}

locals {
  bucket_acl = var.environment == "prod" ? "public-read" : "private"
  ssh_ports  = var.enable_ssh_ingress ? [22] : []
}

resource "aws_s3_bucket" "resolved_bucket" {
  bucket = "company-resolved-storage-bucket"
  # GT: id=IAC-TF-1001 type=TP rule=s3-public-read-acl-resolved technique=resolved-local-variable
  acl    = local.bucket_acl
}

resource "aws_s3_bucket" "dev_resolved_bucket" {
  bucket = "company-dev-storage-bucket"
  # GT: id=IAC-TF-1007 type=FP reason=dev-environment-resolves-private-acl technique=resolved-local-variable
  acl    = "private"
}

resource "aws_security_group" "dynamic_sg" {
  name = "dynamic-security-group"

  dynamic "ingress" {
    for_each = local.ssh_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      # GT: id=IAC-TF-1002 type=TP rule=dynamic-block-open-ssh technique=dynamic-block-resolution
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = [443]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      # GT: id=IAC-TF-1008 type=FP reason=safe-public-https-ingress technique=dynamic-block-resolution
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

# Cross-Resource Trio: Public IP + Public Subnet + Open Ingress SG = TP
resource "aws_instance" "exposed_web_instance" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  subnet_id                   = "subnet-public-123"
  vpc_security_group_ids      = [aws_security_group.dynamic_sg.id]
  # GT: id=IAC-TF-1004 type=TP rule=cross-resource-public-instance-exposed technique=cross-resource-correlation
  tags = { Name = "ExposedPublicInstance" }
}

# Cross-Resource: SG alone without public compute instance = FP
resource "aws_security_group" "isolated_sg" {
  name = "isolated-sg-no-instances"
  # GT: id=IAC-TF-1010 type=FP reason=isolated-sg-unattached-to-instance technique=cross-resource-isolation
  description = "Unattached security group"
}

# Cross-Resource: Instance in private subnet with no public IP = FP
resource "aws_instance" "isolated_private_instance" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
  subnet_id                   = "subnet-private-456"
  # GT: id=IAC-TF-1011 type=FP reason=private-subnet-no-public-ip technique=cross-resource-isolation
  tags = { Name = "IsolatedPrivateInstance" }
}

# Count block creating unencrypted storage if true
resource "aws_s3_bucket" "conditional_bucket" {
  count  = var.create_insecure_bucket ? 1 : 0
  bucket = "conditional-insecure-bucket"
  # GT: id=IAC-TF-1005 type=TP rule=conditional-count-insecure-bucket technique=count-block-conditional
  acl    = "public-read"
}

resource "aws_s3_bucket" "disabled_conditional_bucket" {
  count  = 0
  bucket = "disabled-bucket"
  # GT: id=IAC-TF-1012 type=FP reason=count-zero-resource-not-created technique=count-block-conditional
  acl    = "public-read"
}

# Dynamic statement block generating wildcard admin IAM
resource "aws_iam_policy" "dynamic_admin_policy" {
  name = "dynamic-admin-policy"
  # GT: id=IAC-TF-1006 type=TP rule=dynamic-iam-wildcard-admin technique=dynamic-block-iam
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }]
  })
}

resource "aws_iam_policy" "dynamic_scoped_policy" {
  name = "dynamic-scoped-policy"
  # GT: id=IAC-TF-1013 type=FP reason=dynamic-statement-scoped-arn technique=dynamic-block-iam
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = ["s3:GetObject"], Effect = "Allow", Resource = "arn:aws:s3:::safe-bucket/*" }]
  })
}

# Module Call with unencrypted RDS = TP
module "unencrypted_database" {
  source            = "./modules/rds"
  # GT: id=IAC-TF-1003 type=TP rule=module-call-storage-unencrypted technique=module-parameter-resolution
  storage_encrypted = false
}

# Module Call with encrypted RDS = FP
module "encrypted_database" {
  source            = "./modules/rds"
  # GT: id=IAC-TF-1009 type=FP reason=module-call-storage-encrypted technique=module-parameter-resolution
  storage_encrypted = true
}

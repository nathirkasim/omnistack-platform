# Cloud Infrastructure Provisioning with Terraform

resource "aws_s3_bucket" "insecure_data_bucket" {
  bucket = "company-internal-confidential-bucket"
  # GT: id=IAC-TF-001 type=TP rule=s3-public-read-acl
  acl    = "public-read"
}

resource "aws_s3_bucket" "static_site_bucket" {
  bucket = "company-public-docs-static-site"
  # GT: id=IAC-TF-007 type=FP reason=intentional-static-website-bucket
  acl    = "public-read"
  tags = {
    Type = "PublicWebsite"
  }
}

resource "aws_security_group" "ssh_bastion" {
  name        = "bastion-sg"
  description = "SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # GT: id=IAC-TF-002 type=TP rule=security-group-open-ssh-ingress
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "public_alb" {
  name        = "public-alb-sg"
  description = "Public Load Balancer HTTPS"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # GT: id=IAC-TF-006 type=FP reason=public-alb-https-ingress-intentional
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "insecure_db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  # GT: id=IAC-TF-003 type=TP rule=rds-storage-unencrypted
  storage_encrypted = false
}

resource "aws_db_instance" "secure_kms_db" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  # GT: id=IAC-TF-008 type=FP reason=encryption-via-kms-key
  storage_encrypted = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/custom-key"
}

resource "aws_iam_policy" "wildcard_admin" {
  name = "overly-permissive-policy"
  # GT: id=IAC-TF-004 type=TP rule=iam-star-wildcard-permission
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "scoped_wildcard" {
  name = "scoped-s3-read-policy"
  # GT: id=IAC-TF-009 type=FP reason=scoped-wildcard-action-restricted-resource
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["s3:GetObject*", "s3:ListBucket*"]
      Effect   = "Allow"
      Resource = "arn:aws:s3:::app-scoped-bucket/*"
    }]
  })
}

resource "aws_cloudtrail" "insecure_trail" {
  name           = "audit-trail"
  s3_bucket_name = "audit-bucket"
  # GT: id=IAC-TF-005 type=TP rule=cloudtrail-logging-disabled
  enable_logging = false
}


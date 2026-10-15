terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# S3 Bucket for Exported Analytical Reports
resource "aws_s3_bucket" "report_storage" {
  bucket = "omniflow-crm-reports-${var.environment}"

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Compliance  = "SOC2-Type-II"
  }
}

resource "aws_s3_bucket_versioning" "report_versioning" {
  bucket = aws_s3_bucket.report_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "report_crypto" {
  bucket = aws_s3_bucket.report_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "report_block_public" {
  bucket = aws_s3_bucket.report_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Policy for Application Workload Pods
# IAC False Positive: Scanners flag wildcard '*' in Resource.
# SAFE: The wildcard is explicitly scoped to object keys within this specific bucket ARN only!
resource "aws_iam_policy" "report_worker_policy" {
  name        = "omniflow-report-worker-s3-policy"
  description = "Allows worker pods to put and get generated analytical PDF reports"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ScopedBucketObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.report_storage.arn}/*"
      }
    ]
  })
}

# Security Group for Internal Database Cluster
resource "aws_security_group" "db_sg" {
  name        = "omniflow-db-sg-${var.environment}"
  description = "Controls PostgreSQL cluster network boundaries"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow TLS DB connections from application private subnet"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.app_subnet_cidr]
  }

  egress {
    description = "Outbound egress for NTP and OS updates"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

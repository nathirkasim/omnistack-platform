# Infrastructure as Code Fixture: AWS S3 Storage
# Covers paired True Positives and False Positives.

# ==============================================================================
# TP-IAC-001: Public S3 Bucket with Insecure ACL and No Public Access Block
# High Severity | Insecure S3 Configuration
# ==============================================================================
resource "aws_s3_bucket" "vulnerable_public_bucket" {
  bucket = "acme-vulnerable-public-assets-storage"
}

resource "aws_s3_bucket_acl" "vulnerable_public_acl" {
  bucket = aws_s3_bucket.vulnerable_public_bucket.id
  acl    = "public-read"
}

# ==============================================================================
# FP-IAC-001: Secure Private S3 Bucket with Enforced Public Access Block & KMS
# Expected: Compliant / Safe
# ==============================================================================
resource "aws_s3_bucket" "safe_private_bucket" {
  bucket = "acme-secure-private-records-storage"
}

resource "aws_s3_bucket_public_access_block" "safe_public_block" {
  bucket = aws_s3_bucket.safe_private_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "safe_encryption" {
  bucket = aws_s3_bucket.safe_private_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

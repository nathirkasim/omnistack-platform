provider "aws" {
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

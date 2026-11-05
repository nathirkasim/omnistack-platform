provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "corp-production-assets"
  acl    = var.bucket_acl
}

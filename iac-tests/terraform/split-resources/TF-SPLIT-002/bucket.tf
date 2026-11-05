provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "corp_data" {
  bucket = "company-financial-reports-2026"
}

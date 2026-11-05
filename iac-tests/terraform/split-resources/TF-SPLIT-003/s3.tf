provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "modern_bucket" {
  bucket = "company-secure-reports"
}

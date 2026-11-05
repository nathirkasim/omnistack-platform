provider "aws" {
  region = "us-east-1"
}

# checkov:skip=CKV_AWS_20:Intentional public documentation website bucket
resource "aws_s3_bucket" "public_docs" {
  bucket = "company-public-documentation-static-website"
  acl    = "public-read"
}

# VULNERABLE: Public S3 Bucket with public-read ACL and missing Public Access Block (CKV_AWS_20, AVD-AWS-0089)
resource "aws_s3_bucket" "public_customer_data" {
  bucket = "tigergate-benchmark-public-data-bucket"
  acl    = "public-read"

  tags = {
    Environment = "Production"
  }
}

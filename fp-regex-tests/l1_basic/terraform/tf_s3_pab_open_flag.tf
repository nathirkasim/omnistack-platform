resource "aws_s3_bucket_public_access_block" "open_access" {
  bucket            = "app-unprotected-bucket"
  block_public_acls = false
}

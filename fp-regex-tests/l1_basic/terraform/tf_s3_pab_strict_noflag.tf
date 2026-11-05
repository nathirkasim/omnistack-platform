resource "aws_s3_bucket_public_access_block" "hardened_access" {
  bucket              = "app-hardened-bucket"
  block_public_acls   = true
  block_public_policy = true
}

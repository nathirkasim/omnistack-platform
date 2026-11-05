resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.modern_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

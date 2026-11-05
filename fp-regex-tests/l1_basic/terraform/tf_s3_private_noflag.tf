resource "aws_s3_bucket" "secure_store" {
  bucket = "app-private-credentials"
  acl    = "private"
}

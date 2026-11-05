resource "aws_s3_bucket" "distribution" {
  bucket = "app-distribution-artifacts"
  acl    = "public-read"
}

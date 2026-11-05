provider "aws" {
  region = "us-east-1"
}

data "aws_ssm_parameter" "encryption_enabled" {
  name = "/infra/s3/encryption_toggle"
}

resource "aws_s3_bucket" "computed_bucket" {
  bucket = "computed-runtime-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "computed_sse" {
  bucket = aws_s3_bucket.computed_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = data.aws_ssm_parameter.encryption_enabled.value == "true" ? "AES256" : "None"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_object" "verified_binary" {
  bucket = "company-software-releases"
  key    = "app-v1.0.0.tar.gz"
  # High entropy sha256 checksum (not a secret)
  etag   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

resource "aws_ssm_parameter" "template_placeholder" {
  name  = "/config/db_placeholder"
  type  = "String"
  value = "CHANGEME_ON_FIRST_LOGIN_MOCK_12345"
}

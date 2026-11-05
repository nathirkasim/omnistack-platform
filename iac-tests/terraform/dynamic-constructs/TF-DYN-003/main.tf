provider "aws" {
  region = "us-east-1"
}

variable "enable_legacy_debug_bucket" {
  type    = bool
  default = false
}

resource "aws_s3_bucket" "disabled_bucket" {
  count  = var.enable_legacy_debug_bucket ? 1 : 0
  bucket = "company-disabled-debug-bucket"
  acl    = "public-read"
}

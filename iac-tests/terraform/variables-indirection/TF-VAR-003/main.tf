provider "aws" {
  region = "us-east-1"
}

variable "raw_acl" {
  type    = string
  default = "public-read"
}

variable "is_prod" {
  type    = bool
  default = true
}

locals {
  enforced_acl = var.is_prod ? "private" : var.raw_acl
}

resource "aws_s3_bucket" "guarded_bucket" {
  bucket = "corp-hardened-customer-data"
  acl    = local.enforced_acl
}

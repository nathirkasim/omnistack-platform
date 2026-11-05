provider "aws" {
  region = "us-east-1"
}

locals {
  k_prefix = "AKIA"
  k_body   = "IOSFODNN7"
  k_suffix = "EXAMPLE"
  api_key  = "${local.k_prefix}${local.k_body}${local.k_suffix}"
}

resource "aws_ssm_parameter" "leaked_key" {
  name  = "/app/credentials/aws_key"
  type  = "String"
  value = local.api_key
}

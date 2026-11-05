provider "aws" {
  region = "us-east-1"
}

locals {
  base_config   = { admin_port = 22, fallback_cidr = "10.0.0.0/8" }
  override_map  = { active_cidr = "0.0.0.0/0" }
  merged_config = merge(local.base_config, local.override_map)
  target_port   = lookup(local.merged_config, "admin_port", 80)
  target_cidr   = coalesce(local.merged_config.active_cidr, local.merged_config.fallback_cidr)
}

resource "aws_security_group" "evasive_sg" {
  name        = "obfuscated-ingress-sg"
  description = "Evasive SSH opening via dynamic functions"

  ingress {
    from_port   = local.target_port
    to_port     = local.target_port
    protocol    = "tcp"
    cidr_blocks = [for c in [local.target_cidr] : c if length(c) > 0]
  }
}

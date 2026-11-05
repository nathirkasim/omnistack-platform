provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "dynamic_ssh" {
  name        = "bastion-dynamic-sg"
  description = "Dynamic security group"

  dynamic "ingress" {
    for_each = [22]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

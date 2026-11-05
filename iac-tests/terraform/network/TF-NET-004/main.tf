provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "function_cidr_sg" {
  name        = "calculated-cidr-sg"
  description = "Ingress with function-calculated CIDR"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [cidrsubnet("0.0.0.0/0", 0, 0)]
  }
}

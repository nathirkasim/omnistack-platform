provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "alb_https" {
  name        = "public-alb-https-sg"
  description = "Permit inbound HTTPS from internet"

  ingress {
    description = "Standard HTTPS internet ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

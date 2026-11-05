provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "open_ssh" {
  name        = "public-ssh-sg"
  description = "Open SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "ipv6_open" {
  name        = "ipv6-all-open-sg"
  description = "IPv6 unrestricted ingress"

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "windows_sg" {
  name        = "windows-fleet-sg"
  description = "Windows instances security group"
}

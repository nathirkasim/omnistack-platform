# VULNERABLE: Unrestricted 0.0.0.0/0 ingress on administrative ports 22 (SSH) and 3389 (RDP) (CKV_AWS_24, CKV_AWS_25)
resource "aws_security_group" "allow_all_ssh" {
  name        = "allow_all_admin"
  description = "Insecure security group allowing global SSH and RDP ingress"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

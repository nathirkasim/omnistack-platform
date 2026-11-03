# Fully resolved and rendered Terraform output for production environment
resource "aws_s3_bucket" "resolved_bucket" {
  bucket = "company-resolved-storage-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "dynamic_sg" {
  name = "dynamic-security-group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "exposed_web_instance" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  subnet_id                   = "subnet-public-123"
  vpc_security_group_ids      = ["sg-12345"]
}

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_vpc" "production" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_security_group" "alb" {
  name   = "alb-security-group"
  vpc_id = aws_vpc.production.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["3.251.148.96/29"]
  }
  ingress {
    from_port   = 2200
    to_port     = 2299
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "analytics" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_db_instance" "core_replica" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "prod-enterprise-audit-logs"
  acl    = "private"
}

resource "aws_s3_bucket" "public_distribution" {
  bucket = "prod-enterprise-public-dist"
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_ebs_volume" "encrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_s3_bucket_public_access_block" "audit_pab" {
  bucket              = aws_s3_bucket.audit_logs.id
  block_public_acls   = true
  block_public_policy = true
}

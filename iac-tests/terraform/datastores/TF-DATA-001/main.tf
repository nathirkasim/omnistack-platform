provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "unprotected_rds" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}

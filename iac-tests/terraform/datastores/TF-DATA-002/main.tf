provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "nobackup_rds" {
  allocated_storage       = 50
  engine                  = "postgres"
  instance_class          = "db.t3.small"
  storage_encrypted       = true
  backup_retention_period = 0
  deletion_protection     = false
}

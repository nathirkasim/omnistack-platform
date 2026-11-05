provider "aws" {
  region = "us-east-1"
}

# checkov:skip=CKV_AWS_20:Misleading suppression for S3 public read applied to RDS
resource "aws_db_instance" "bogus_suppressed" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}

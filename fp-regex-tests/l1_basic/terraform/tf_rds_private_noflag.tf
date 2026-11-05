resource "aws_db_instance" "database" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
  storage_encrypted   = true
}

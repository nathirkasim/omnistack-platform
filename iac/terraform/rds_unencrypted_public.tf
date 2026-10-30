# VULNERABLE: RDS database without encryption at rest and publicly accessible (CKV_AWS_16, CKV_AWS_17)
resource "aws_db_instance" "insecure_rds" {
  allocated_storage       = 20
  engine                  = "postgres"
  engine_version          = "14.7"
  instance_class          = "db.t3.micro"
  db_name                 = "customerdb"
  username                = "dbadmin"
  password                = "benchmark_safe_pass_2026"
  storage_encrypted       = false
  publicly_accessible     = true
  skip_final_snapshot     = true
}

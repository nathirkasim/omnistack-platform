terraform {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-rds.git?ref=v6.0.0"
}

inputs = {
  identifier        = "corp-analytics-db"
  allocated_storage = 50
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = false
}

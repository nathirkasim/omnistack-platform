resource "aws_s3_bucket" "audit_archive" {
  bucket = "prod-audit-archive-logs"
  acl    = "private"
}
resource "aws_s3_bucket_public_access_block" "audit_pab" {
  bucket              = aws_s3_bucket.audit_archive.id
  block_public_acls   = true
  block_public_policy = true
}
resource "aws_db_instance" "prod_db" {
  allocated_storage   = 100
  engine              = "postgres"
  instance_class      = "db.r6g.large"
  publicly_accessible = true
  storage_encrypted   = false
}
resource "aws_ebs_volume" "app_cache" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}

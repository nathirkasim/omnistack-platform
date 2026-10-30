# VULNERABLE: EBS Volume without encryption (CKV_AWS_3)
resource "aws_ebs_volume" "unencrypted_storage" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false

  tags = {
    Name = "Unencrypted-Production-Volume"
  }
}

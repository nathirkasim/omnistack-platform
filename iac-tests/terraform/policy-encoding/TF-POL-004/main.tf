provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "confused_deputy_role" {
  name = "public-vendor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

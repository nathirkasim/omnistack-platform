# VULNERABLE: Overly permissive IAM policy with wildcard actions on all resources (CKV_AWS_1, CKV_AWS_40)
resource "aws_iam_policy" "wildcard_admin" {
  name        = "overly_permissive_admin_policy"
  description = "Excessive wildcard IAM permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

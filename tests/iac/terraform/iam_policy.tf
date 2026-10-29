# Infrastructure as Code Fixture: AWS IAM Policies
# Covers paired True Positives and False Positives.

# ==============================================================================
# TP-IAC-002: Overly Permissive IAM Policy (Wildcard Action on Wildcard Resource)
# High Severity | Privilege Escalation Risk
# ==============================================================================
resource "aws_iam_policy" "vulnerable_admin_wildcard" {
  name        = "vulnerable-wildcard-policy"
  description = "Allows unrestricted administrative access across all cloud resources"

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

# ==============================================================================
# FP-IAC-002: Least-Privilege Scoped IAM Policy
# Expected: Compliant / Safe
# ==============================================================================
resource "aws_iam_policy" "safe_scoped_read_only" {
  name        = "safe-scoped-app-policy"
  description = "Allows read-only access strictly to specific application bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::acme-secure-private-records-storage",
          "arn:aws:s3:::acme-secure-private-records-storage/*"
        ]
      }
    ]
  })
}

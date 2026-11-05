resource "aws_iam_policy" "org_restricted_policy" {
  name = "org-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "s3:GetObject"
      Effect    = "Allow"
      Principal = "*"
      Resource  = "arn:aws:s3:::corporate-assets/*"
      Condition = {
        StringEquals = { "aws:PrincipalOrgID" = "o-abcdef1234" }
      }
    }]
  })
}

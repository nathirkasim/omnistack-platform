provider "aws" {
  region = "us-east-1"
}

data "aws_iam_policy_document" "privesc" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole", "ec2:RunInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "privesc_policy" {
  name   = "ec2-deployment-worker"
  policy = data.aws_iam_policy_document.privesc.json
}

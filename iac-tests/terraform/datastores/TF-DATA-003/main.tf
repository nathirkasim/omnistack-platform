provider "aws" {
  region = "us-east-1"
}

resource "aws_dynamodb_table" "default_encrypted_table" {
  name         = "user-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }
}

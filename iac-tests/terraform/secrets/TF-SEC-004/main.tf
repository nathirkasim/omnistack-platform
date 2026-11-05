provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "provisioned_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # Base64 encoded payload containing: export DB_PASSWORD="SyntheticSuperSecretPassword123"
  user_data_base64 = "ZXhwb3J0IERCX1BBU1NXT1JEPSJTeW50aGV0aWNTdXBlclNlY3JldFBhc3N3b3JkMTIzIgo="
}

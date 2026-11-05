source "amazon-ebs" "builder" {
  region        = "us-east-1"
  instance_type = "t3.micro"
  access_key    = "AKIAIOSFODNN7EXAMPLE"
  secret_key    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ami_name      = "custom-ubuntu-image"
}

build {
  sources = ["source.amazon-ebs.builder"]
}

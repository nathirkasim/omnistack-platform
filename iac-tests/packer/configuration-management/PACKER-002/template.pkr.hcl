source "amazon-ebs" "hardened" {
  region               = "us-east-1"
  instance_type        = "t3.micro"
  ami_name             = "hardened-image-{{timestamp}}"
  iam_instance_profile = "PackerBuilderRole"
}

build {
  sources = ["source.amazon-ebs.hardened"]
}

resource "aws_instance" "worker" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}

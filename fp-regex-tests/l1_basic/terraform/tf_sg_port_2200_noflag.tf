resource "aws_security_group_rule" "custom_app" {
  type              = "ingress"
  from_port         = 2200
  to_port           = 2299
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["0.0.0.0/0"]
}

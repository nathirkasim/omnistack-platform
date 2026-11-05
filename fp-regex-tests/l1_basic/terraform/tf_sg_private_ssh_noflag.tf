resource "aws_security_group_rule" "internal_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["10.0.0.0/8"]
}

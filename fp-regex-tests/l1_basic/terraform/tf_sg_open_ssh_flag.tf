resource "aws_security_group_rule" "ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["0.0.0.0/0"]
}

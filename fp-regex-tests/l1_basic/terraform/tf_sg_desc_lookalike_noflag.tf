resource "aws_security_group_rule" "vpn_ingress" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  description       = "Internal VPN replacing previous 0.0.0.0/0 rule"
  cidr_blocks       = ["10.200.0.0/16"]
}

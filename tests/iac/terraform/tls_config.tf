# Infrastructure as Code Fixture: TLS & Load Balancer Policy
# Covers paired True Positives and False Positives.

# ==============================================================================
# TP-IAC-003: Insecure TLS Version in ALB Security Policy
# Medium Severity | Broken Cryptography / Legacy Protocols
# ==============================================================================
resource "aws_lb_listener" "vulnerable_tls_listener" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/vuln-lb/50dc6c495c0c9188"
  port              = 443
  protocol          = "HTTPS"
  # Insecure policy permitting TLS 1.0 and 1.1
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

# ==============================================================================
# FP-IAC-003: Modern Secure TLS Policy Enforcing TLS 1.3 / 1.2
# Expected: Compliant / Safe
# ==============================================================================
resource "aws_lb_listener" "safe_tls_listener" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/safe-lb/50dc6c495c0c9188"
  port              = 443
  protocol          = "HTTPS"
  # Secure policy strictly enforcing modern TLS 1.3 / 1.2 ciphers
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

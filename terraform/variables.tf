variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS deployment region"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment tier"
}

variable "vpc_id" {
  type        = string
  default     = "vpc-0a1b2c3d4e5f67890"
  description = "Target VPC ID for database cluster"
}

variable "app_subnet_cidr" {
  type        = string
  default     = "10.100.4.0/24"
  description = "Application tier private subnet CIDR"
}

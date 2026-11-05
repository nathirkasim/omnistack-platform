terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "bucket_acl" {
  type        = string
  default     = "public-read"
  description = "Access control list for S3 bucket"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "corp-data-analytics-storage"
  acl    = var.bucket_acl
}

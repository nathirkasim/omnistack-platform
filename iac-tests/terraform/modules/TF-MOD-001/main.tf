provider "aws" {
  region = "us-east-1"
}

module "database" {
  source            = "./modules/rds"
  storage_encrypted = false
}

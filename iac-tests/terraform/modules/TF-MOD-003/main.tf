provider "aws" {
  region = "us-east-1"
}

module "hardened_db" {
  source            = "./modules/rds"
  storage_encrypted = true
}

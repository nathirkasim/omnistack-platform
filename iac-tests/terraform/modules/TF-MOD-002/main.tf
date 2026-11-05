provider "aws" {
  region = "us-east-1"
}

module "tier1" {
  source = "./modules/tier1"
}


provider "aws" {
  region = "eu-west-2"
}

module "vpc" {
  source                = "../."
  name                  = "yada"
  environment           = "test"
  cidr_block            = "10.0.0.0/16"
  additional_cidr_block = ["192.3.0.0/16", "192.2.0.0/16"]
}

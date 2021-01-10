# terrafrom-aws-vpc

```sh

module "coe-vpc" {
   source                   = "./modules/vpc"
   azs                      = "${var.azs}"
   vpc_cidr                 = "${var.vpc_cidr}"
   public_subnet_cidrs      = "${var.public_subnet_cidrs}"
   private_subnet_cidrs     = "${var.private_subnet_cidrs}"
   database_subnet_cidrs    = "${var.database_subnet_cidrs}" 
   enable_dns_hostnames     = true
   vpc_name                 = "${var.project}-${var.environment}"
   //-- In case we need to change Domain servers
   //dhcp_domain_name_servers = ["${var.domain_servers}"]
   environment              = "${var.environment}"
}

```
## Variables

```sh

variable "aws_region" {
  default = "us-east-2"
}   
variable "region" {
  default = "us-east-2"
}  
variable "state_bucket" {
  description = "The s3 bucket used to store terraform state"
  default = "cloudcoe"
}
variable "project" {
  description = "Enter the Project Name:"
}

variable "environment" {
  description = "Enter the Environment Name:"
}


/***********************************************************
VPC Variables
***********************************************************/
variable "vpc_cidr" {
  description = "VPC cidr block. Example: 10.0.0.0/16"
}
variable "public_subnet_cidrs" {
  description = "List of public cidrs, for every availability zone you want you need one. Example: 10.0.0.0/24 and 10.0.1.0/24"
  type        = "list"
}
variable "private_subnet_cidrs" {
  description = "List of private cidrs, for every availability zone you want you need one. Example: 10.0.0.0/24 and 10.0.1.0/24"
  type        = "list"
}
variable "database_subnet_cidrs" {
  description = "List of database cidrs, for every availability zone you want you need one. Example: 10.0.0.0/24 and 10.0.1.0/24"
  type        = "list"
}
variable "availability_zones" {
  description = "List of availability zones you want. Example: ap-southeast-2a, ap-southeast-2b"
  type        = "list"
}
variable "azs" {
  description = "List of availability zones you want. Example: ap-southeast-2a, ap-southeast-2b"
  type        = "list"
}

```

## tfvars

```sh

vpc_cidr = "10.0.0.0/16"
public_subnet_cidrs = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
private_subnet_cidrs = ["10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24"]
database_subnet_cidrs = ["10.0.20.0/24", "10.0.21.0/24", "10.0.22.0/24"]
availability_zones = ["us-east-2a", "us-east-2b", "us-east-2c"]
azs = ["us-east-2a", "us-east-2b", "us-east-2c"]

```
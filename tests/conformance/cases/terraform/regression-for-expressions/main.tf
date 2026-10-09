terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

locals {
  tags     = { for k, v in var.tags : k => upper(v) }
  subnets  = [for s in module.vpc.private_subnets : s if s != ""]
  services = {
    for name, service in var.services :
    name => merge(service, { cpu = 1024 })
  }
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.0"

  target_groups = { for name, _ in local.services : name => { port = 80 } }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"
}

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
  }
}

# module "legacy" {
#   source = "acme/retired/aws"
# }

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.24.0"

  cluster_name = "platform"
  bootstrap_script = <<-EOT
    # Written into user data, not read by Terraform as a module:
    source = "acme/not-a-module/aws"
    echo "${var.region}"
  EOT
}

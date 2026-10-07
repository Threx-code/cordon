/*
  Every source form Terraform accepts for a module, besides the registry.
*/

module "dns" {
  # GitHub shorthand, a subdirectory of the repository, at a commit.
  source = "github.com/acme/terraform-modules//dns?ref=3f9a1c2b4d5e6f708192a3b4c5d6e7f8091a2b3c"
}

module "tags" {
  source = "https://releases.acme.example.internal/modules/tags-1.2.0.zip"
}

module "queue" {
  source = "git::ssh://git@git.acme.example.internal/platform/queue.git?ref=main"
}

// The pre-0.13 form, a version string per provider name.
terraform {
  required_providers {
    google = ">= 4.0, < 6.0"
  }
}

provider "aws" {
  alias  = "replica"
  region = "eu-west-1"
}

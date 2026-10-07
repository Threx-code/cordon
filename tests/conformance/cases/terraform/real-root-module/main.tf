provider "github" {
  owner = "acme"
}

provider "time" {
  alias = "secondary"
}

module "label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  namespace = "acme"
  name      = "service"
}

module "label_from_git" {
  source = "git::https://github.com/cloudposse/terraform-null-label.git?ref=0.25.0"

  namespace = "acme"
  name      = "worker"
}

module "naming" {
  source = "./modules/naming"
  prefix = module.label.id
}

resource "random_pet" "suffix" {
  length = 2
}

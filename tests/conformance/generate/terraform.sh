#!/bin/sh
# Regenerates the real-world Terraform conformance case: a root module requiring providers (with
# version constraints, a provider outside the hashicorp namespace, an aliased provider) and calling
# modules (from the registry at an exact version, from git at a ref, and a local one), initialised
# with `terraform init -backend=false` and locked for two platforms with `terraform providers
# lock`. Terraform's own `terraform version -json` (the provider selections) and its module manifest
# (.terraform/modules/modules.json) are the authoritative inventory. Nothing is planned or applied.
# Run inside Docker only:
#
#   docker run --rm --entrypoint sh -v "$PWD/tests/conformance:/conformance" hashicorp/terraform:1.9 /conformance/generate/terraform.sh
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/terraform_inventory.py
#
# The terraform image has no Python: the first step leaves the tools' output in
# authoritative.raw.json and the second turns it into authoritative.json.
set -eu
OUT=/conformance/cases/terraform/real-root-module
rm -rf /tmp/t && mkdir -p /tmp/t/modules/naming && cd /tmp/t
cat > versions.tf <<'EOF'
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.0, < 4.0.0"
    }
    time = {
      source                = "hashicorp/time"
      version               = "0.12.1"
      configuration_aliases = [time.secondary]
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.3"
    }
  }
}
EOF
cat > main.tf <<'EOF'
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
EOF
cat > modules/naming/main.tf <<'EOF'
variable "prefix" {
  type = string
}

terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

resource "random_id" "this" {
  byte_length = 4
  prefix      = var.prefix
}
EOF
terraform init -backend=false -input=false >/tmp/init.log 2>&1 || { tail -20 /tmp/init.log; exit 1; }
terraform providers lock -platform=linux_amd64 -platform=darwin_arm64 >/tmp/lock.log 2>&1 || { tail -20 /tmp/lock.log; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT/modules/naming"
cp versions.tf main.tf .terraform.lock.hcl "$OUT/"
cp modules/naming/main.tf "$OUT/modules/naming/"

terraform version -json >/tmp/version.json
cp .terraform/modules/modules.json /tmp/modules.json
# The two manifests to JSON lines, without a JSON tool in the image.
{
  printf '{\n "tool": "terraform version -json (provider selections) and .terraform/modules/modules.json",\n "packages": ['
  sed -n 's/.*"registry.terraform.io\/\([^"]*\)": *"\([^"]*\)".*/"\1@\2"/p' /tmp/version.json | paste -sd, -
  printf '],\n "modules_json": '
  cat /tmp/modules.json
  printf '\n}\n'
} > "$OUT/authoritative.raw.json"
cat /tmp/version.json; cat /tmp/modules.json; cat .terraform.lock.hcl | head -30
echo done

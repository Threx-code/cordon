terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

# Runs at `terraform plan`: proposing a change is enough to run it.
data "external" "build_info" {
  program = ["python3", "${path.module}/scripts/build_info.py"]
}

# A data source that runs nothing: not reported.
data "aws_caller_identity" "current" {}

resource "aws_s3_object" "release" {
  bucket = "acme-releases"
  key    = "release.json"

  # Runs at `terraform apply`, on whoever applies it.
  provisioner "local-exec" {
    command = "./scripts/notify.sh"
  }
}

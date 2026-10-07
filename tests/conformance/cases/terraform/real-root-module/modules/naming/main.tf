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

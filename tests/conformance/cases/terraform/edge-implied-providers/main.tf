provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "cloudflare_record" "www" {
  zone_id = var.zone
  name    = "www"
}

data "terraform_remote_state" "network" {
  backend = "local"
}
